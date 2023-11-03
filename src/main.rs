use askama_axum::IntoResponse;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, get_service, post},
    Form, Json, Router,
};
use num_bigint::{BigInt, Sign};
use serde::Deserialize;
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::{fmt::Display, net::SocketAddr, sync::Arc};
use templates::RegisterTemplate;
use tower_http::services::ServeDir;

mod crypto;
mod db;
mod errors;
mod geolocate;
mod structs;
mod templates;

struct AppState {
    pool: Pool<MySql>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect("mysql://mangos:mangos@localhost:3306/realmd")
        .await
        .expect("Connecting to MySql DB");

    let shared_state = Arc::new(AppState { pool });

    let app = Router::new()
        .route("/register", get(register_form))
        .route("/register", post(register))
        .fallback(get_service(ServeDir::new("assets")))
        .with_state(shared_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn register_form() -> impl IntoResponse {
    RegisterTemplate {}
}

async fn register(State(state): State<Arc<AppState>>, Form(form): Form<Register>) -> StatusCode {
    tracing::info!("{:?}", form);
    if let Ok((username, verifier, salt)) =
        crypto::generate_srp_values(form.username, form.password)
    {
        let (_, verifier_be) = BigInt::from_bytes_le(Sign::Plus, &verifier).to_bytes_be();
        let (_, salt_be) = BigInt::from_bytes_le(Sign::Plus, &salt).to_bytes_be();
        if let Ok(()) = db::add_account(&state.pool,
            username,
            hex::encode_upper(verifier_be),
            hex::encode_upper(salt_be),
        ).await {
            StatusCode::CREATED
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

#[derive(Deserialize, Debug)]
struct Register {
    username: String,
    password: String,
    #[serde(rename = "g-recaptcha-response")]
    recaptcha: String,
}
