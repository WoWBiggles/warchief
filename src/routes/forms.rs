use std::net::SocketAddr;

use askama_axum::IntoResponse;
use axum::{
    extract::{ConnectInfo, State},
    response::Redirect,
    Form,
};
use mail_send::mail_builder::MessageBuilder;
use serde::Deserialize;
use tower_sessions::Session;

use crate::{consts, crypto, db, errors, geolocate, recaptcha, templates, state};

pub async fn login_form() -> impl IntoResponse {
    templates::LoginTemplate::default()
}

#[derive(Deserialize, Debug)]
pub struct UserForm {
    username: String,
    password: String,
    #[serde(rename = "g-recaptcha-response")]
    recaptcha: String,
}

pub async fn login(
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<state::AppState>,
    Form(form): Form<UserForm>,
) -> impl IntoResponse {
    tracing::info!("Login attempt from {}", addr.ip());

    if let Err(e) = recaptcha::verify_recaptcha(&state.config, form.recaptcha).await {
        return templates::LoginTemplate::error(e.to_string()).into_response();
    }

    match geolocate::check_ip(&state.config, &state.mmdb_data, addr.ip()) {
        Ok(allowed) => {
            if !allowed {
                return templates::LoginTemplate::error(format!(
                    "Your country or continent is banned from creating an account on this server."
                ))
                .into_response();
            }
        }
        Err(e) => {
            return templates::LoginTemplate::error(format!(
                "Failed to geolocate your IP: {:?}",
                e
            ))
            .into_response();
        }
    }

    let account = match db::get_account(&state.pool, &form.username).await {
        Ok(account) => {
            match crypto::verify_password(&form.username, &form.password, &account.v, &account.s) {
                Ok(_) => account,
                Err(e) => {
                    return match e {
                        errors::AuthenticationError::IncorrectPassword(_) => {
                            templates::LoginTemplate::error("Incorrect password").into_response()
                        }
                        errors::AuthenticationError::DatabaseError(e) => {
                            templates::LoginTemplate::error(format!("Unknown DB error: {}", e))
                                .into_response()
                        }
                        errors::AuthenticationError::MissingSrpValues(_) => {
                            templates::LoginTemplate::error("Missing DB data").into_response()
                        }
                        errors::AuthenticationError::InvalidSrpValues(_) => {
                            templates::LoginTemplate::error("Dodgy DB data").into_response()
                        }
                        e => templates::LoginTemplate::error(format!("Unexpected error {}", e))
                            .into_response(),
                    }
                }
            }
        }
        Err(e) => {
            return templates::LoginTemplate::error(format!(
                "Could not find an account for that username {:?}",
                e
            ))
            .into_response()
        }
    };

    if let Err(e) = session.insert(consts::SESSION_ACCOUNT_DETAILS, account) {
        return templates::LoginTemplate::error(format!("Failed to save session: {:?}", e))
            .into_response();
    }

    Redirect::to("/account_management").into_response()
}

pub async fn register_form() -> impl IntoResponse {
    templates::RegisterTemplate::default()
}

pub async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<state::AppState>,
    Form(form): Form<UserForm>,
) -> impl IntoResponse {
    tracing::info!("Registration attempt from {}", addr.ip());

    if let Err(e) = recaptcha::verify_recaptcha(&state.config, form.recaptcha).await {
        return templates::RegisterTemplate {
            success: Some(false),
            error: Some(e.to_string()),
        };
    }

    tracing::info!("Recaptcha passed by {}", addr.ip());

    if db::is_ip_banned(&state.pool, addr.ip()).await {
        return templates::RegisterTemplate {
            success: Some(false),
            error: Some(format!(
                "Your IP is banned from creating an account on this server."
            )),
        };
    }

    match geolocate::check_ip(&state.config, &state.mmdb_data, addr.ip()) {
        Ok(allowed) => {
            if !allowed {
                return templates::RegisterTemplate {
                    success: Some(false),
                    error: Some(format!("Your country or continent is banned from creating an account on this server."))
                };
            }
        }
        Err(e) => {
            return templates::RegisterTemplate {
                success: Some(false),
                error: Some(format!("Failed to geolocate your IP: {:?}", e)),
            }
        }
    }

    tracing::info!("GeoIp passed by {}", addr.ip());

    if let Ok((username, verifier, salt)) =
        crypto::generate_srp_values(&form.username, &form.password)
    {
        match db::add_account(&state.pool, username, verifier, salt).await {
            Ok(()) => {
                tracing::info!("Successful registation from {}", addr.ip());
                let message = MessageBuilder::new()
                    .from(("Biggles", "wowbiggles@proton.me"))
                    .to(vec![
                        ("Jane Doe", "silep39743@newnime.com"),
                    ])
                    .subject("Hi!")
                    .html_body("<h1>Hello, world!</h1>")
                    .text_body("Hello world!");
                state.smtp.lock().await.send(message).await.expect("Email should send properly.");
                templates::RegisterTemplate {
                    success: Some(true),
                    error: None,
                }
            }
            Err(e) => match e {
                errors::AuthenticationError::ExistingUser => templates::RegisterTemplate {
                    success: Some(false),
                    error: Some(String::from("Existing user found with that username")),
                },
                errors::AuthenticationError::DatabaseError(e) => templates::RegisterTemplate {
                    success: Some(false),
                    error: Some(format!("DB error: {}", e)),
                },
                _ => templates::RegisterTemplate {
                    success: Some(false),
                    error: Some(format!("Unknown DB error {}", e)),
                },
            },
        }
    } else {
        templates::RegisterTemplate {
            success: Some(false),
            error: Some(String::from("Generating SRP values failed")),
        }
    }
}

pub async fn change_password_form() -> impl IntoResponse {
    templates::ChangePasswordForm::default()
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
        return templates::ChangePasswordForm::error(
            "New password does not match repeated password.",
        )
        .into_response();
    }

    if let Err(e) = recaptcha::verify_recaptcha(&state.config, form.recaptcha).await {
        return templates::ChangePasswordForm::error(e.to_string()).into_response();
    }

    if let Err(e) = crypto::verify_password(
        &account.username,
        &form.current_password,
        &account.v,
        &account.s,
    ) {
        return match e {
            errors::AuthenticationError::IncorrectPassword(_) => {
                templates::ChangePasswordForm::error("Incorrect password").into_response()
            }
            errors::AuthenticationError::DatabaseError(e) => {
                templates::ChangePasswordForm::error(format!("Unknown DB error: {}", e))
                    .into_response()
            }
            errors::AuthenticationError::MissingSrpValues(_) => {
                templates::ChangePasswordForm::error("Missing DB data").into_response()
            }
            errors::AuthenticationError::InvalidSrpValues(_) => {
                templates::ChangePasswordForm::error("Dodgy DB data").into_response()
            }
            e => templates::ChangePasswordForm::error(format!("Unexpected error {}", e))
                .into_response(),
        };
    }

    let (username, v_hex, s_hex) =
        match crypto::generate_srp_values(&account.username, &form.new_password) {
            Ok(r) => r,
            Err(e) => {
                return templates::ChangePasswordForm::error(format!(
                    "Unable to normalize new password: {}",
                    e
                ))
                .into_response();
            }
        };

    if let Err(e) = db::update_srp_values(&state.pool, username, v_hex, s_hex).await {
        return templates::ChangePasswordForm::error(format!(
            "Could not generate new SRP values: {}",
            e
        ))
        .into_response();
    }

    Redirect::to("/account_management").into_response()
}
