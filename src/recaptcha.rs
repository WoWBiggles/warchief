use std::collections::HashMap;

use config::Config;
use serde::Deserialize;

use crate::{errors::AuthenticationError, config::RECAPTCHA_SECRET};

#[derive(Deserialize, Debug)]
struct RecaptchaResponse {
    success: bool,
    score: Option<f32>,
    challenge_ts: Option<String>,
    hostname: Option<String>,
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

pub async fn verify_recaptcha(config: &Config, token: String) -> Result<(), AuthenticationError> {
    let secret = config.get_string(RECAPTCHA_SECRET)
        .expect("Recaptcha configuration requires a site secret.");

    let mut body = HashMap::new();
    body.insert("secret", secret);
    body.insert("response", token);

    let client = reqwest::Client::new();
    let res = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&body)
        .send()
        .await;

    if let Ok(res) = res {
        match res.json::<RecaptchaResponse>().await {
            Ok(json) => {
                tracing::info!("Got score {}", json.score.unwrap_or(0f32));
                if !json.success {
                    Err(AuthenticationError::FailedRecaptcha(format!(
                        "Failed with error_codes: {:?}",
                        json.error_codes
                    )))
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(AuthenticationError::FailedRecaptcha(format!(
                "Failed to parse recaptcha response: {}",
                e.to_string()
            ))),
        }
    } else {
        Err(AuthenticationError::FailedRecaptcha(String::from(
            "Recaptcha request failed",
        )))
    }
}
