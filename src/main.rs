use askama_axum::IntoResponse;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::{get, get_service, post},
    Form, Json, Router,
};
use ::config::Config;
use core::panic;
use geolocate::geolocate_ip_country;
use num_bigint::{BigInt, Sign};
use recaptcha::verify_recaptcha;
use serde::{Deserialize, Serialize};
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use templates::RegisterTemplate;
use tower_http::services::ServeDir;

use crate::{geolocate::load_mmdb_data, config::init_config};

mod config;
mod crypto;
mod db;
mod errors;
mod geolocate;
mod recaptcha;
mod structs;
mod templates;

struct AppState {
    pool: Pool<MySql>,
    mmdb_data: Vec<u8>,
    config: Config,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = init_config();

    let db_url = config.get_string(config::CONFIG_DB_URL).expect("Database configuration should have a connection string.");
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("Connecting to MySql DB");

    let mmdb_data = load_mmdb_data().expect("Loading MMDB data");

    tracing::info!("Loaded MMDB {}", mmdb_data.len());

    let shared_state = Arc::new(AppState { pool, mmdb_data, config });

    let app = Router::new()
        .route("/register", get(register_form))
        .route("/register", post(register))
        .fallback(get_service(ServeDir::new("assets")))
        .with_state(shared_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn register_form() -> impl IntoResponse {
    RegisterTemplate::default()
}

#[derive(Deserialize, Debug)]
struct Register {
    username: String,
    password: String,
    #[serde(rename = "g-recaptcha-response")]
    recaptcha: String,
}

async fn register(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Form(form): Form<Register>,
) -> impl IntoResponse {
    if let Err(e) = verify_recaptcha(
        state.config.get_string(config::RECAPTCHA_SECRET).expect("Recaptcha configuration requires a site secret."),
        form.recaptcha,
    )
    .await
    {
        return RegisterTemplate {
            success: Some(false),
            error: Some(e.to_string()),
        };
    }

    let geoip_enabled = state.config.get_bool(config::CONFIG_GEOIP_ENABLED).unwrap_or(false);
    if !addr.ip().is_loopback() && geoip_enabled {
        match geolocate_ip_country(&state.mmdb_data, addr.ip()) {
            Ok(location) => tracing::info!("geolocate {:?}", location),
            Err(e) => tracing::error!("geolocate error {:?} for {}", e, addr.ip()),
        }
    }

    if let Ok((username, verifier, salt)) =
        crypto::generate_srp_values(form.username, form.password)
    {
        let (_, verifier_be) = BigInt::from_bytes_le(Sign::Plus, &verifier).to_bytes_be();
        let (_, salt_be) = BigInt::from_bytes_le(Sign::Plus, &salt).to_bytes_be();
        match db::add_account(
            &state.pool,
            username,
            hex::encode_upper(verifier_be),
            hex::encode_upper(salt_be),
        )
        .await
        {
            Ok(()) => RegisterTemplate {
                success: Some(true),
                error: None,
            },
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
