use std::fmt::Display;

use serde::Deserialize;
use thiserror::Error;
use wow_srp::error::{InvalidPublicKeyError, MatchProofsError, NormalizedStringError};

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("unnormalised username or password")]
    InvalidCharacters(#[from] NormalizedStringError),
    #[error("invalid public key")]
    InvalidPublicKey(#[from] InvalidPublicKeyError),
    #[error("incorrect password")]
    IncorrectPassword(#[from] MatchProofsError),
    #[error("failed recaptcha: {0}")]
    FailedRecaptcha(String),
    #[error("existing username")]
    ExistingUser,
    #[error("database error")]
    DatabaseError(#[from] sqlx::Error),
    #[error("invalid gm level: {0}")]
    InvalidGmLevel(u8),
    #[error("missing srp value from db: {0}")]
    MissingSrpValues(String),
    #[error("invalid srp value from db: {0}")]
    InvalidSrpValues(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Banned,
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCode::Banned => f.write_str("Your account is banned from this server."),
        }
    }
}
