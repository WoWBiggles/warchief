use ::config::Config;
use askama_axum::IntoResponse;
use axum::{
    error_handling::HandleErrorLayer,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::{self, Next},
    response::{Response, Redirect},
    routing::{get, get_service, post},
    BoxError, Form, Router,
};

use db::Account;
use http::StatusCode;
use num_bigint::{BigInt, Sign};
use recaptcha::verify_recaptcha;
use serde::Deserialize;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::{net::SocketAddr, sync::Arc};
use templates::{RegisterTemplate, LoginTemplate};
use tower::ServiceBuilder;
use tower_http::services::ServeDir;
use tower_sessions::{cookie::time::Duration, Expiry, MemoryStore, Session, SessionManagerLayer};

use crate::{
    config::init_config,
    geolocate::{check_ip, load_mmdb_data}, db::get_account, crypto::verify_password, errors::AuthenticationError,
};

mod config;
mod consts;
mod crypto;
mod db;
mod errors;
mod geolocate;
mod recaptcha;
mod structs;
mod templates;

#[derive(Clone)]
struct AppState {
    pool: Pool<MySql>,
    mmdb_data: Vec<u8>,
    config: Config,
}

async fn auth_middleware<B>(session: Session, request: Request<B>, next: Next<B>) -> Response {
    if session.get::<Account>(consts::SESSION_ACCOUNT_DETAILS).ok().flatten().is_none() {
        return Redirect::to("/login").into_response()
    }

    let response = next.run(request).await;
    response
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = init_config();

    let db_url = config
        .get_string(config::DB_URL)
        .expect("Database configuration should have a connection string.");
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("Connecting to MySql DB");

    let mmdb_data = load_mmdb_data().expect("Loading MMDB data");

    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(
            SessionManagerLayer::new(session_store)
                .with_secure(false)
                .with_expiry(Expiry::OnInactivity(Duration::minutes(1))),
        );

    tracing::info!("Loaded MMDB ({}b)", mmdb_data.len());

    let shared_state = Arc::new(AppState {
        pool,
        mmdb_data,
        config,
    });

    let app = Router::new()
        .route("/test", get(test))
        .layer(middleware::from_fn(auth_middleware))
        .route("/login", get(login_form))
        .route("/login", post(login))
        .route("/register", get(register_form))
        .route("/register", post(register))
        .fallback(get_service(ServeDir::new("assets")))
        .layer(session_service)
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn test() -> String {
    String::from("Testing")
}

async fn login_form() -> impl IntoResponse {
    LoginTemplate::default()
}

#[derive(Deserialize, Debug)]
struct UserForm {
    username: String,
    password: String,
    #[serde(rename = "g-recaptcha-response")]
    recaptcha: String,
}

async fn login(
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Form(form): Form<UserForm>,
) -> impl IntoResponse {
    tracing::info!("Login attempt from {}", addr.ip());

    if let Err(e) = verify_recaptcha(
        state
            .config
            .get_string(config::RECAPTCHA_SECRET)
            .expect("Recaptcha configuration requires a site secret."),
        form.recaptcha,
    )
    .await
    {
        return LoginTemplate {
            error: Some(e.to_string()),
        }.into_response();
    }

    match check_ip(&state.config, &state.mmdb_data, addr.ip()) {
        Ok(allowed) => {
            if !allowed {
                return LoginTemplate{
                    error: Some(format!("Your country or continent is banned from creating an account on this server."))
                }.into_response();
            }
        }
        Err(e) => {
            return LoginTemplate{
                error: Some(format!("Failed to geolocate your IP: {:?}", e)),
            }.into_response();
        }
    }

    let account = match get_account(&state.pool, &form.username).await {
        Ok(account) => {
            match verify_password(&form.username, &form.password, &account.v, &account.s) {
                Ok(_) => account,
                Err(e) => {
                    return LoginTemplate {
                        error: Some(format!("Failed to login: {:?}", e))
                    }.into_response()
                },
            }
        },
        Err(e) => return LoginTemplate {
            error: Some(format!("Could not find an account for that username {:?}", e))
        }.into_response(),
    };

    session.insert(consts::SESSION_ACCOUNT_DETAILS, account).expect("New session details saved");

    Redirect::to("/test").into_response()
}

async fn register_form() -> impl IntoResponse {
    RegisterTemplate::default()
}

async fn register(
    session: Session,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Form(form): Form<UserForm>,
) -> impl IntoResponse {
    tracing::info!("Registration attempt from {}", addr.ip());

    if let Err(e) = verify_recaptcha(
        state
            .config
            .get_string(config::RECAPTCHA_SECRET)
            .expect("Recaptcha configuration requires a site secret."),
        form.recaptcha,
    )
    .await
    {
        return RegisterTemplate {
            success: Some(false),
            error: Some(e.to_string()),
        };
    }

    tracing::info!("Recaptcha passed by {}", addr.ip());

    match check_ip(&state.config, &state.mmdb_data, addr.ip()) {
        Ok(allowed) => {
            if !allowed {
                return RegisterTemplate {
                    success: Some(false),
                    error: Some(format!("Your country or continent is banned from creating an account on this server."))
                };
            }
        }
        Err(e) => {
            return RegisterTemplate {
                success: Some(false),
                error: Some(format!("Failed to geolocate your IP: {:?}", e)),
            }
        }
    }

    tracing::info!("GeoIp passed by {}", addr.ip());

    if let Ok((username, verifier, salt)) =
        crypto::generate_srp_values(&form.username, &form.password)
    {
        match db::add_account(
            &state.pool,
            username,
            verifier,
            salt,
        )
        .await
        {
            Ok(()) => {
                tracing::info!("Successful registation from {}", addr.ip());
                RegisterTemplate {
                    success: Some(true),
                    error: None,
                }
            }
            Err(e) => match e {
                errors::AuthenticationError::ExistingUser => RegisterTemplate {
                    success: Some(false),
                    error: Some(String::from("Existing user found with that username")),
                },
                errors::AuthenticationError::DatabaseError(e) => RegisterTemplate {
                    success: Some(false),
                    error: Some(format!("DB error: {}", e)),
                },
                _ => RegisterTemplate {
                    success: Some(false),
                    error: Some(format!("Unknown DB error {}", e)),
                },
            },
        }
    } else {
        RegisterTemplate {
            success: Some(false),
            error: Some(String::from("Generating SRP values failed")),
        }
    }
}
