use num_bigint::{BigInt, Sign};
use wow_srp::{
    client::SrpClientUser, error::NormalizedStringError, normalized_string::NormalizedString,
    server::SrpVerifier, PublicKey, GENERATOR, LARGE_SAFE_PRIME_LITTLE_ENDIAN,
    PASSWORD_VERIFIER_LENGTH, SALT_LENGTH,
};

use crate::errors::AuthenticationError;

pub fn generate_srp_values(
    username: &String,
    password: &String,
) -> Result<(String, String, String), NormalizedStringError> {
    let username = NormalizedString::new(username)?;
    let password = NormalizedString::new(password)?;
    let v = SrpVerifier::from_username_and_password(username, password);

    let (_, verifier_be) =
        BigInt::from_bytes_le(Sign::Plus, &v.password_verifier().to_owned()).to_bytes_be();
    let (_, salt_be) = BigInt::from_bytes_le(Sign::Plus, &v.salt().to_owned()).to_bytes_be();

    Ok((
        v.username().to_owned(),
        hex::encode_upper(verifier_be),
        hex::encode_upper(salt_be),
    ))
}

pub fn verify_password(
    username: &String,
    password: &String,
    password_verifier: &String,
    salt: &String,
) -> Result<(), AuthenticationError> {
    let username = NormalizedString::new(username)?;
    let password = NormalizedString::new(password)?;

    let verifier = hex::decode(password_verifier)
        .map_err(|_| AuthenticationError::InvalidSrpValues(String::from("v")))?;
    let salt =
        hex::decode(salt).map_err(|_| AuthenticationError::InvalidSrpValues(String::from("s")))?;

    let (_, verifier_le) = BigInt::from_bytes_be(Sign::Plus, &verifier).to_bytes_le();
    let (_, salt_le) = BigInt::from_bytes_be(Sign::Plus, &salt).to_bytes_le();

    let verifier_le: [u8; PASSWORD_VERIFIER_LENGTH as usize] = verifier_le
        .try_into()
        .map_err(|_| AuthenticationError::InvalidSrpValues(String::from("v")))?;

    let salt_le: [u8; SALT_LENGTH as usize] = salt_le
        .try_into()
        .map_err(|_| AuthenticationError::InvalidSrpValues(String::from("s")))?;

    let verifier = SrpVerifier::from_database_values(username.clone(), verifier_le, salt_le);
    let server_proof = verifier.into_proof();
    let server_public_key = PublicKey::from_le_bytes(*server_proof.server_public_key())?;

    let client = SrpClientUser::new(username, password);
    let client_challenge = client.into_challenge(
        GENERATOR,
        LARGE_SAFE_PRIME_LITTLE_ENDIAN,
        server_public_key,
        salt_le,
    );
    let client_public_key = PublicKey::from_le_bytes(*client_challenge.client_public_key())?;

    let (mut _server, _server_proof) =
        server_proof.into_server(client_public_key, *client_challenge.client_proof())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use wow_srp::error::NormalizedStringError;

    use super::*;

    #[test]
    fn correct_login_succeeds() {
        let password = String::from("password");
        let (username, password_verifier, salt) =
            generate_srp_values(&String::from("test"), &password).unwrap();

        let result = verify_password(&username, &password, &password_verifier, &salt);

        assert!(result.is_ok());
    }

    #[test]
    fn incorrect_password_fails() {
        let (username, password_verifier, salt) =
            generate_srp_values(&String::from("test"), &String::from("correct")).unwrap();

        let result = verify_password(
            &username,
            &String::from("incorrect"),
            &password_verifier,
            &salt,
        );
        if let Err(AuthenticationError::IncorrectPassword(_)) = result {
        } else {
            panic!("Expected an IncorrectPassword error {:?}", result);
        }
    }

    #[test]
    fn long_username_fails() {
        let result = generate_srp_values(
            &String::from("waytoolongforausernameomegalul"),
            &String::from("correct"),
        );
        if let Err(NormalizedStringError::StringTooLong) = result {
        } else {
            panic!("Expected a StringtooLong error {:?}", result);
        }
    }
}
