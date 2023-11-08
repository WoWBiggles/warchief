use askama_axum::IntoResponse;
use axum::{
    error_handling::HandleErrorLayer,
    extract::Path,
    http::Request,
    middleware::{self, Next},
    response::{Redirect, Response},
    routing::{get, get_service, post},
    BoxError, Router,
};

use db::Account;
use http::StatusCode;



use tower::ServiceBuilder;
use std::net::SocketAddr;
use templates::ErrorTemplate;
use tower_http::services::ServeDir;
use tower_sessions::{cookie::time::Duration, Expiry, MemoryStore, Session, SessionManagerLayer};



mod config;
mod consts;
mod crypto;
mod db;
mod errors;
mod email;
mod geolocate;
mod recaptcha;
mod routes;
mod state;
mod templates;

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

    let shared_state = state::init_state().await;

    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(
            SessionManagerLayer::new(session_store)
                .with_secure(false)
                .with_expiry(Expiry::OnInactivity(Duration::minutes(15))),
        );

    let app = Router::new()
        .route(
            "/account_management",
            get(routes::account::account_management),
        )
        .route("/change_password", get(routes::forms::change_password_form))
        .route("/change_password", post(routes::forms::change_password))
        .layer(middleware::from_fn(auth_middleware))
        .route("/", get(|| async { Redirect::permanent("/login") }))
        .route("/error/:error_code", get(error))
        .route("/login", get(routes::forms::login_form))
        .route("/login", post(routes::forms::login))
        .route("/register", get(routes::forms::register_form))
        .route("/register", post(routes::forms::register))
        .route("/verify/:token", get(routes::forms::verify))
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
