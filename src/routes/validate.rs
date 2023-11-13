use askama_axum::{IntoResponse, Response};
use axum::Form;
use http::StatusCode;
use serde::Deserialize;
use wow_srp::normalized_string::NormalizedString;

use crate::templates;

#[derive(Deserialize, Debug)]
pub struct ValidationForm {
    username: String,
    password: String,
}

pub async fn username(Form(form): Form<ValidationForm>) -> Response {
    if form.username.len() == 0 {
        return templates::ValidationResponse::error("Please enter a username!").into_response()
    }
    
    if let Err(e) = NormalizedString::from(form.username) {
        return templates::ValidationResponse::error(e.to_string()).into_response()
    }

    templates::ValidationResponse::blank().into_response()
}

pub async fn password(Form(form): Form<ValidationForm>) -> Response {
    if let Err(e) = NormalizedString::from(form.password) {
        return templates::ValidationResponse::error(e.to_string()).into_response()
    }

    templates::ValidationResponse::blank().into_response()
}