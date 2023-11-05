use ::config::Config;
use askama_axum::IntoResponse;
use axum::{
    error_handling::HandleErrorLayer,
    http::Request,
    middleware::{self, Next},
    response::{Redirect, Response},
    routing::{get, get_service, post},
    BoxError, Router, extract::Path,
};

use db::Account;
use http::StatusCode;


use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::{net::SocketAddr, sync::Arc};
use templates::{AccountManagementTemplate, ErrorTemplate};
use tower::ServiceBuilder;
use tower_http::services::ServeDir;
use tower_sessions::{cookie::time::Duration, Expiry, MemoryStore, Session, SessionManagerLayer};

use crate::{
    config::init_config,
    geolocate::load_mmdb_data,
};

mod config;
mod consts;
mod crypto;
mod db;
mod errors;
mod geolocate;
mod recaptcha;
mod routes;
mod templates;

#[derive(Clone)]
struct AppState {
    pool: Pool<MySql>,
    mmdb_data: Vec<u8>,
    config: Config,
}

async fn auth_middleware<B>(session: Session, request: Request<B>, next: Next<B>) -> Response {
    let account = session
        .get::<Account>(consts::SESSION_ACCOUNT_DETAILS)
        .ok()
        .flatten();
    match account {
        Some(a) => {
            if a.banned {
                return Redirect::to("/error/banned").into_response();
            }
        }
        None => {
            return Redirect::to("/login").into_response();
        }
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
        .route("/account_management", get(account_management))
        .layer(middleware::from_fn(auth_middleware))
        .route("/", get(|| async { Redirect::permanent("/login") }))
        .route("/error/:error_code", get(error))
        .route("/login", get(routes::forms::login_form))
        .route("/login", post(routes::forms::login))
        .route("/register", get(routes::forms::register_form))
        .route("/register", post(routes::forms::register))
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

async fn error(Path(error_code): Path<errors::ErrorCode>) -> impl IntoResponse {
    ErrorTemplate {
        message: error_code.to_string(),
    }
}

async fn account_management() -> impl IntoResponse {
    AccountManagementTemplate::default()
}
