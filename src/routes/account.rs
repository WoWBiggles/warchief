use std::sync::Arc;

use askama_axum::IntoResponse;
use axum::extract::State;
use tower_sessions::Session;

use crate::{db, AppState, consts, templates};

pub async fn account_management(
    session: Session,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let account = session
        .get::<db::Account>(consts::SESSION_ACCOUNT_DETAILS)
        .ok()
        .flatten()
        .expect("Getting account from session data should always work after the auth-middleware check");

    templates::AccountManagementTemplate {
        account_id: account.id,
    }
}
