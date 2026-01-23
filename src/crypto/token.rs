use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// PASETO v4.public Implementation (Simplified)
/// Format: v4.public.[message].[signature]
/// Message: base64url(json_claims)
/// Signature: base64url(Ed25519_Sign(m, version_header || m))

const HEADER: &[u8] = b"v4.public.";

pub fn sign_paseto<T: Serialize>(claims: &T, private_key_hex: &str) -> Result<String, String> {
    // 1. Decode Private Key
    let key_bytes = hex::decode(private_key_hex).map_err(|e| e.to_string())?;

    // We expect a 64-byte key (32 secret + 32 public) as per standard Ed25519 practice in some libs,
    // but ed25519-dalek `SigningKey` is initialized from 32-byte secret.
    // Let's assume the first 32 bytes are the secret.
    if key_bytes.len() < 32 {
        return Err("Invalid private key length".to_string());
    }
    let secret: [u8; 32] = key_bytes[0..32]
        .try_into()
        .map_err(|_| "Invalid key length".to_string())?;
    let signing_key = SigningKey::from_bytes(&secret);

    // 2. Prepare Message (M)
    // In canonical PASETO, the "message" is typically the payload.
    // For simplicity, we will just serialize the claims to JSON.
    let json_claims = serde_json::to_string(claims).map_err(|e| e.to_string())?;
    let m = json_claims.as_bytes();

    // 3. Prepare PASETO Pre-Authentication Encoding (PAE)
    // PAE(header, m, footer) = LE64(num_pieces) | LE64(len(header)) | header | LE64(len(m)) | m | ...
    // Here: PAE("v4.public.", m, "")
    // Actually, v4.public format is: v4.public.base64(m).base64(sig)
    // BUT efficient implementations sign: PAE(header, m, footer)
    // Let's stick to the spec: https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign

    let m2 = pae(HEADER, m, &[]); // footer is empty

    // 4. Sign
    let signature = signing_key.sign(&m2);

    // 5. Assemble Token
    // token = header || base64(m) || . || base64(sig)
    // Note: The standard actually says "v4.public." || base64(m) || base64(sig) NO.
    // Wait, let's double check the spec carefully.
    // "The content of the token is the message m, signed."
    // Format: version || . || purpose || . || base64url(m) || . || base64url(sig)
    // Standard: v4.public.payload.signature (where payload and signature are base64url)

    let b64_m = URL_SAFE_NO_PAD.encode(m);
    let b64_sig = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!(
        "{}{}.{}",
        std::str::from_utf8(HEADER).unwrap(),
        b64_m,
        b64_sig
    ))
}

pub fn verify_paseto<T: for<'a> Deserialize<'a>>(
    token: &str,
    public_key_hex: &str,
) -> Result<T, String> {
    // 1. Check Header
    let header_str = std::str::from_utf8(HEADER).unwrap();
    if !token.starts_with(header_str) {
        return Err("Invalid token header".to_string());
    }

    // 2. Split remainder
    let remainder = &token[header_str.len()..];
    let parts: Vec<&str> = remainder.split('.').collect();
    if parts.len() != 2 {
        return Err("Invalid token format".to_string());
    }

    let b64_m = parts[0];
    let b64_sig = parts[1];

    // 3. Decode
    let m = URL_SAFE_NO_PAD
        .decode(b64_m)
        .map_err(|_| "Invalid base64 payload".to_string())?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(b64_sig)
        .map_err(|_| "Invalid base64 signature".to_string())?;

    let signature = Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "Invalid signature length".to_string())?,
    );

    // 4. Decode Public Key
    let pk_bytes = hex::decode(public_key_hex).map_err(|e| e.to_string())?;
    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "Invalid public key length".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pk_array).map_err(|e| e.to_string())?;

    // 5. Verify Signature
    // Must reconstruct PAE(header, m, footer)
    let m2 = pae(HEADER, &m, &[]);
    verifying_key
        .verify(&m2, &signature)
        .map_err(|e| e.to_string())?;

    // 6. Deserialize Payload
    let claims: T = serde_json::from_slice(&m).map_err(|e| e.to_string())?;

    Ok(claims)
}

/// Pre-Authentication Encoding (PAE)
fn pae(header: &[u8], m: &[u8], footer: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    output.extend_from_slice(&le64(3)); // Number of pieces (header, m, footer)

    output.extend_from_slice(&le64(header.len() as u64));
    output.extend_from_slice(header);

    output.extend_from_slice(&le64(m.len() as u64));
    output.extend_from_slice(m);

    output.extend_from_slice(&le64(footer.len() as u64));
    output.extend_from_slice(footer);

    output
}

fn le64(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}
