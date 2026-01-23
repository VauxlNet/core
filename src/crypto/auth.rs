use crate::crypto::token;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use ed25519_dalek::SigningKey;
use serde::Serialize;

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?
        .to_string();
    Ok(password_hash)
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(hash).map_err(|e| e.to_string())?;
    let outcome = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

    match outcome {
        Ok(_) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

pub fn sign_token<T: Serialize>(claims: &T, private_key_hex: &str) -> Result<String, String> {
    token::sign_paseto(claims, private_key_hex)
}

pub fn verify_token<T: for<'a> serde::Deserialize<'a>>(
    token: &str,
    public_key_hex: &str,
) -> Result<T, String> {
    token::verify_paseto(token, public_key_hex)
}

/// Generates an Ed25519 keypair for PASETO v4.public tokens.
/// Returns (public_key_hex, private_key_hex).
pub fn generate_keypair() -> (String, String) {
    let secret_bytes: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // PASETO v4.public expects 64-byte private key (32-byte secret + 32-byte public)
    let mut private_key_bytes = [0u8; 64];
    private_key_bytes[..32].copy_from_slice(&signing_key.to_bytes());
    private_key_bytes[32..].copy_from_slice(verifying_key.as_bytes());

    let public_key_hex = hex::encode(verifying_key.as_bytes());
    let private_key_hex = hex::encode(private_key_bytes);

    (public_key_hex, private_key_hex)
}
