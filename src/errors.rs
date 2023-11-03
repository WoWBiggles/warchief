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
}
