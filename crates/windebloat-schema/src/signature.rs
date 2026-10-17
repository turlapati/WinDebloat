use crate::Bundle;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Manifest is unsigned")]
    Unsigned,
    #[error("Invalid hex encoding in key or signature: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("Invalid Ed25519 signature or key bytes: {0}")]
    Crypto(#[from] ed25519_dalek::SignatureError),
    #[error("Canonical JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Manifest signature did not match any trusted public key")]
    UntrustedSigner,
}

/// Produces deterministic canonical JSON bytes for the manifest's `bundles` list
/// so Ed25519 signatures are invariant to outer formatting.
pub fn canonicalize_bundles(bundles: &[Bundle]) -> Result<Vec<u8>, SignatureError> {
    let val = serde_json::to_value(bundles)?;
    let canonical = canonicalize_json_value(&val);
    Ok(serde_json::to_vec(&canonical)?)
}

fn canonicalize_json_value(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                if let Some(v) = map.get(k) {
                    sorted.insert(k.clone(), canonicalize_json_value(v));
                }
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_json_value).collect())
        }
        other => other.clone(),
    }
}

/// Sign a slice of bundles with an Ed25519 `SigningKey` and return the hex-encoded signature.
pub fn sign_manifest_bundles(
    bundles: &[Bundle],
    signing_key: &SigningKey,
) -> Result<String, SignatureError> {
    let payload = canonicalize_bundles(bundles)?;
    let sig: Signature = signing_key.sign(&payload);
    Ok(hex::encode(sig.to_bytes()))
}

/// Verify a manifest's hex-encoded signature against a list of hex-encoded Ed25519 public keys.
pub fn verify_manifest_signature(
    bundles: &[Bundle],
    signature_hex: Option<&str>,
    trusted_pubkeys_hex: &[String],
) -> Result<(), SignatureError> {
    let sig_hex = signature_hex.ok_or(SignatureError::Unsigned)?;
    if sig_hex.trim().is_empty() {
        return Err(SignatureError::Unsigned);
    }
    let sig_bytes = hex::decode(sig_hex.trim())?;
    let signature = Signature::from_slice(&sig_bytes)?;
    let payload = canonicalize_bundles(bundles)?;

    for pubkey_hex in trusted_pubkeys_hex {
        let key_bytes = match hex::decode(pubkey_hex.trim()) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        if let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) {
            if verifying_key.verify(&payload, &signature).is_ok() {
                return Ok(());
            }
        }
    }

    Err(SignatureError::UntrustedSigner)
}

/// Reads trusted Ed25519 public keys (hex strings) from `HKLM\SOFTWARE\Policies\WinDebloat\TrustedKeys` (§3.4).
#[cfg(windows)]
pub fn load_system_trusted_keys() -> Vec<String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Policies\WinDebloat\TrustedKeys",
        KEY_READ,
    ) else {
        return Vec::new();
    };

    let mut keys = Vec::new();
    for item in key.enum_values().flatten() {
        let (_name, reg_val) = item;
        if let Ok(s) = String::from_utf8(reg_val.bytes) {
            let trimmed = s.trim_matches('\0').trim().to_string();
            if !trimmed.is_empty() {
                keys.push(trimmed);
            }
        }
    }
    keys
}

#[cfg(not(windows))]
pub fn load_system_trusted_keys() -> Vec<String> {
    Vec::new()
}
