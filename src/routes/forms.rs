use std::{net::SocketAddr, time::Duration};

use askama_axum::IntoResponse;
use axum::{
    extract::{ConnectInfo, Path, State},
    response::Redirect,
    Form,
};
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    config, consts, controllers, crypto, db, email, geolocate, recaptcha, state, templates,
};

pub async fn login_form() -> impl IntoResponse {
    templates::LoginTemplate::default()
}

#[derive(Deserialize, Debug)]
pub struct UserForm {
    pub email: Option<String>,
    pub username: String,
    pub password: String,
    #[serde(rename = "g-recaptcha-response")]
    pub recaptcha: String,
}

pub async fn login(
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<state::AppState>,
    Form(form): Form<UserForm>,
) -> impl IntoResponse {
    tracing::info!("Login attempt from {}", addr.ip());

    match controllers::login::attempt_login(session, addr.ip(), &state, &form).await {
        Ok(account) => {
            if let Err(e) =
                db::add_login_attempt(&state.pool, &account.id, addr.ip(), true, None).await
            {
                tracing::warn!(
                    "Failed to log login attempt for {}: {}",
                    &account.username,
                    e
                )
            }
            Redirect::to("/account_management").into_response()
        }
        Err(e) => {
            // If the account exists, fetch the account ID and log the failed login attempt.
            if !matches!(e, controllers::login::LoginError::AccountDoesNotExist) {
                if let Ok(account) = db::get_account(&state.pool, &form.username).await {
                    if let Err(e) = db::add_login_attempt(
                        &state.pool,
                        &account.id,
                        addr.ip(),
                        false,
                        Some(&e.to_string()),
                    )
                    .await
                    {
                        tracing::warn!(
                            "Failed to log login attempt for {}: {}",
                            &account.username,
                            e
                        )
                    }
                }
            }

            match e {
                controllers::login::LoginError::AccountDoesNotExist => {
                    templates::LoginTemplate::error("No account exists with that username.")
                        .into_response()
                }
                controllers::login::LoginError::FailedRecaptcha(_) => {
                    templates::LoginTemplate::error("You have failed your recaptcha.")
                        .into_response()
                }
                controllers::login::LoginError::FailedToGeolocate(_) => {
                    tracing::warn!("could not geolocate IP {}", addr.ip());
                    templates::LoginTemplate::error(
                        "Your IP could not be geo-located, please contact an admin.",
                    )
                    .into_response()
                }
                controllers::login::LoginError::FailedGeolocationChecks => {
                    templates::LoginTemplate::error(
                        "Your IP is from a country or continent banned from this server.",
                    )
                    .into_response()
                }
                controllers::login::LoginError::DatabaseError(e) => {
                    templates::LoginTemplate::error(format!("Unknown DB error: {}", e))
                        .into_response()
                }
                controllers::login::LoginError::UnverifiedEmail => templates::LoginTemplate::error(
                    "Please verify your email address before logging in.",
                )
                .into_response(),
                controllers::login::LoginError::CryptoError(e) => match e {
                    crypto::CryptoError::CorruptSrpValue(v) => {
                        tracing::error!("SRP values for {} are corrupted: {}", &form.username, v);
                        templates::LoginTemplate::error(format!(
                            "Contact admin, DB values are corrupted: {}",
                            v
                        ))
                        .into_response()
                    }
                    crypto::CryptoError::InvalidUsername(_) => {
                        templates::LoginTemplate::error("You have entered an invalid username.")
                            .into_response()
                    }
                    crypto::CryptoError::InvalidPassword(_) => {
                        templates::LoginTemplate::error("You have entered an invalid password.")
                            .into_response()
                    }
                    crypto::CryptoError::InvalidPublicKey(e) => {
                        tracing::error!(
                            "SRP public key for {} is corrupted: {}",
                            &form.username,
                            e
                        );
                        templates::LoginTemplate::error(format!(
                            "Contact admin, public key generation from DB values failed: {}.",
                            e
                        ))
                        .into_response()
                    }
                    crypto::CryptoError::FailedLogin(_) => {
                        templates::LoginTemplate::error("Incorrect password.").into_response()
                    }
                },
                controllers::login::LoginError::SessionError(e) => {
                    tracing::error!("Unable to save session of {}: {}", &form.username, e);
                    templates::LoginTemplate::error(format!(
                        "Contact admin, unable to save session data: {}",
                        e
                    ))
                    .into_response()
                }
            }
        }
    }
}

pub async fn register_form(State(state): State<state::AppState>) -> impl IntoResponse {
    let email_verification_enabled = state
        .config
        .get_bool(config::EMAIL_VERIFICATION_ENABLED)
        .unwrap_or(false);

    templates::RegisterTemplate {
        email_required: email_verification_enabled,
        ..Default::default()
    }
}

pub async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<state::AppState>,
    Form(form): Form<UserForm>,
) -> impl IntoResponse {
    let email_verification_enabled = state
        .config
        .get_bool(config::EMAIL_VERIFICATION_ENABLED)
        .unwrap_or(false);

    if email_verification_enabled && form.email.as_ref().unwrap_or(&"".to_string()) == "" {
        return templates::RegisterTemplate {
            email_required: email_verification_enabled,
            success: Some(false),
            error: Some("Email is required for verification.".to_string()),
        };
    }

    tracing::info!("Registration attempt from {}", addr.ip());

    if let Err(e) = recaptcha::verify_recaptcha(&state.config, &form.recaptcha).await {
        return templates::RegisterTemplate {
            email_required: email_verification_enabled,
            success: Some(false),
            error: Some(e.to_string()),
        };
    }

    tracing::info!("Recaptcha passed by {}", addr.ip());

    if db::is_ip_banned(&state.pool, addr.ip()).await {
        return templates::RegisterTemplate {
            email_required: email_verification_enabled,
            success: Some(false),
            error: Some("Your IP is banned from creating an account on this server.".to_string()),
        };
    }

    match geolocate::check_ip(&state.config, &state.mmdb_data, addr.ip()) {
        Ok(allowed) => {
            if !allowed {
                return templates::RegisterTemplate {
                    email_required: email_verification_enabled,
                    success: Some(false),
                    error: Some("Your country or continent is banned from creating an account on this server.".to_string())
                };
            }
        }
        Err(e) => {
            return templates::RegisterTemplate {
                email_required: email_verification_enabled,
                success: Some(false),
                error: Some(format!("Failed to geolocate your IP: {:?}", e)),
            }
        }
    }

    tracing::info!("GeoIp passed by {}", addr.ip());

    match crypto::generate_srp_values(&form.username, &form.password) {
        Ok((username, verifier, salt)) => {
            if let Err(e) = db::add_account(&state.pool, &username, &verifier, &salt).await {
                return templates::RegisterTemplate::error(
                    email_verification_enabled,
                    e.to_string(),
                );
            }
        }
        Err(e) => {
            return templates::RegisterTemplate::error(
                email_verification_enabled,
                format!("Generating SRP values failed: {}", e),
            )
        }
    }

    tracing::info!("Added account {} for {}", &form.username, addr.ip());

    if email_verification_enabled {
        let email_verification_timeout: u64 = state
            .config
            .get_int(config::EMAIL_VERIFICATION_TOKEN_TIMEOUT_M)
            .expect("Email verification token timeout must be defined.")
            .try_into()
            .expect("Email verification token must be a u64.");
        let token = Uuid::new_v4().to_string();
        state.verification_tokens.write().await.insert(
            token.clone(),
            form.username.clone(),
            Duration::from_secs(60 * email_verification_timeout),
        );

        if let Err(e) = email::send_verification_email(&state.config, &token, form).await {
            return templates::RegisterTemplate::error(
                email_verification_enabled,
                format!("Unable to send verification email: {}", e),
            );
        }

        tracing::info!(
            "Saved verification token {} for {}, sent email",
            &token,
            addr.ip()
        );
    }

    templates::RegisterTemplate {
        email_required: email_verification_enabled,
        success: Some(true),
        error: None,
    }
}

pub async fn verify(
    State(state): State<state::AppState>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    if let Some(username) = state.verification_tokens.read().await.get(&token) {
        match db::verify_account(&state.pool, username).await {
            Ok(()) => templates::VerifyTemplate {
                username: Some(username.to_string()),
                success: Some(true),
                error: None,
            },
            Err(e) => templates::VerifyTemplate::error(e.to_string()),
        }
    } else {
        templates::VerifyTemplate::error(
            "Invalid verify token. It may have timed out, please re-request a verification token.",
        )
    }
}

pub async fn change_password_form() -> impl IntoResponse {
    templates::ChangePassword::default()
}

#[derive(Deserialize, Debug)]
pub struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    repeat_new_password: String,
    #[serde(rename = "g-recaptcha-response")]
    recaptcha: String,
}

pub async fn change_password(
    session: Session,
    State(state): State<state::AppState>,
    Form(form): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    let account = session
        .get::<db::Account>(consts::SESSION_ACCOUNT_DETAILS)
        .ok()
        .flatten()
        .expect(
            "Getting account from session data should always work after the auth-middleware check",
        );

    if form.repeat_new_password != form.new_password {
        return templates::ChangePassword::error("New password does not match repeated password.")
            .into_response();
    }

    if let Err(e) = recaptcha::verify_recaptcha(&state.config, &form.recaptcha).await {
        return templates::ChangePassword::error(e.to_string()).into_response();
    }

    if let Err(e) = crypto::verify_password(
        &account.username,
        &form.current_password,
        &account.v,
        &account.s,
    ) {
        return templates::ChangePassword::error(e.to_string()).into_response();
    }

    let (username, v_hex, s_hex) =
        match crypto::generate_srp_values(&account.username, &form.new_password) {
            Ok(r) => r,
            Err(e) => {
                return templates::ChangePassword::error(format!(
                    "Unable to normalize new password: {}",
                    e
                ))
                .into_response();
            }
        };

    if let Err(e) = db::update_srp_values(&state.pool, &username, &v_hex, &s_hex).await {
        return templates::ChangePassword::error(format!(
            "Could not generate new SRP values: {}",
            e
        ))
        .into_response();
    }

    Redirect::to("/account_management").into_response()
}
