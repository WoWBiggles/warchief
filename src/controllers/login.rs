use std::net::IpAddr;

use thiserror::Error;
use tower_sessions::Session;

use crate::{geolocate, recaptcha, state, db, crypto, config, consts, routes};

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("account does not exist with that username")]
    AccountDoesNotExist,
    #[error("failed recaptcha: {0}")]
    FailedRecaptcha(#[from] recaptcha::RecaptchaError),
    #[error("failed to geolocate ip: {0}")]
    FailedToGeolocate(String),
    #[error("failed geolocation checks")]
    FailedGeolocationChecks,
    #[error("database error: {0}")]
    DatabaseError(#[from] db::DatabaseError),
    #[error("unverified email")]
    UnverifiedEmail,
    #[error("crypto error: {0}")]
    CryptoError(#[from] crypto::CryptoError),
    #[error("unable to save data to user session: {0}")]
    SessionError(#[from] tower_sessions::session::Error),
}

pub async fn attempt_login(
    session: Session,
    ip: IpAddr,
    state: &state::AppState,
    form: &routes::forms::UserForm,
) -> Result<db::Account, LoginError> {
    recaptcha::verify_recaptcha(&state.config, &form.recaptcha).await?;

    let allowed = geolocate::check_ip(&state.config, &state.mmdb_data, ip)
        .map_err(|e| LoginError::FailedToGeolocate(format!("{:?}", e)))?;
    if !allowed {
        return Err(LoginError::FailedGeolocationChecks);
    }

    let account = db::get_account(&state.pool, &form.username).await.map_err(|_| LoginError::AccountDoesNotExist)?;

    crypto::verify_password(&form.username, &form.password, &account.v, &account.s)?;

    let email_verification_enabled = state
        .config
        .get_bool(config::EMAIL_VERIFICATION_ENABLED)
        .unwrap_or(false);
    if email_verification_enabled && !account.email_verified {
        return Err(LoginError::UnverifiedEmail);
    }

    session.insert(consts::SESSION_ACCOUNT_DETAILS, account.clone())?;

    Ok(account)
}
