use config::Config;
use serde::Deserialize;
use thiserror::Error;

use crate::config::{RECAPTCHA_ENABLED, RECAPTCHA_SECRET};

#[derive(Error, Debug)]
pub enum RecaptchaError {
    #[error("failed recaptcha with codes: {0}")]
    ExpectedFailure(String),
    #[error("failed to verify recaptcha result: {0}")]
    Network(#[from] reqwest::Error),
}

#[derive(Deserialize, Debug)]
struct RecaptchaResponse {
    success: bool,
    score: Option<f32>,
    challenge_ts: Option<String>,
    hostname: Option<String>,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

pub async fn verify_recaptcha(config: &Config, token: &str) -> Result<(), RecaptchaError> {
    let enabled = config
        .get_bool(RECAPTCHA_ENABLED)
        .expect("Recaptcha configuration required an enabled bool");
    let secret = config
        .get_string(RECAPTCHA_SECRET)
        .expect("Recaptcha configuration requires a site secret");

    if !enabled {
        return Ok(());
    }

    let client = reqwest::Client::new();
    let res = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&(("secret", &secret), ("response", &token)))
        .send()
        .await?;

    let json = res.json::<RecaptchaResponse>().await?;
    tracing::info!("Got score {}", json.score.unwrap_or(0f32));
    if !json.success {
        Err(RecaptchaError::ExpectedFailure(
            json.error_codes
                .map(|codes| codes.join(", "))
                .unwrap_or(String::from("")),
        ))
    } else {
        Ok(())
    }
}
