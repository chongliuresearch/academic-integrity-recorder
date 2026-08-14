use crate::canonical::to_jcs;
use anyhow::{anyhow, Result};
use argon2::Argon2;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ProjectKey(pub [u8; 32]);

impl ProjectKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone)]
pub struct DeviceSigner(SigningKey);

impl DeviceSigner {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> String {
        STANDARD.encode(self.0.verifying_key().as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        sha256_hex(self.0.verifying_key().as_bytes())
    }

    pub fn sign<T: Serialize>(&self, value: &T) -> Result<String> {
        let canonical = to_jcs(value)?;
        Ok(STANDARD.encode(self.0.sign(&canonical).to_bytes()))
    }

    pub fn verify<T: Serialize>(public_key: &str, value: &T, signature: &str) -> Result<()> {
        let public: [u8; 32] = STANDARD
            .decode(public_key)?
            .try_into()
            .map_err(|_| anyhow!("invalid Ed25519 public key length"))?;
        let signature: [u8; 64] = STANDARD
            .decode(signature)?
            .try_into()
            .map_err(|_| anyhow!("invalid Ed25519 signature length"))?;
        let key = VerifyingKey::from_bytes(&public)?;
        key.verify(&to_jcs(value)?, &Signature::from_bytes(&signature))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedEnvelope {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn encrypt(key: &ProjectKey, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedEnvelope> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;
    Ok(EncryptedEnvelope {
        algorithm: "XChaCha20-Poly1305".into(),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt(key: &ProjectKey, envelope: &EncryptedEnvelope, aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.algorithm != "XChaCha20-Poly1305" {
        return Err(anyhow!(
            "unsupported encryption algorithm: {}",
            envelope.algorithm
        ));
    }
    let nonce = STANDARD.decode(&envelope.nonce)?;
    let ciphertext = STANDARD.decode(&envelope.ciphertext)?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("authentication failed while decrypting evidence"))
}

pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<ProjectKey> {
    let mut bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut bytes)
        .map_err(|error| anyhow!("Argon2id key derivation failed: {error}"))?;
    Ok(ProjectKey(bytes))
}

pub fn random_passphrase() -> String {
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn random_salt() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encryption_rejects_wrong_key_and_aad() {
        let key = ProjectKey::generate();
        let envelope = encrypt(&key, b"sensitive", b"event:1").unwrap();
        assert_eq!(decrypt(&key, &envelope, b"event:1").unwrap(), b"sensitive");
        assert!(decrypt(&key, &envelope, b"event:2").is_err());
        assert!(decrypt(&ProjectKey::generate(), &envelope, b"event:1").is_err());
    }

    #[test]
    fn signatures_are_verifiable_and_tamper_evident() {
        let signer = DeviceSigner::generate();
        let value = json!({"sequence": 4, "hash": "abc"});
        let signature = signer.sign(&value).unwrap();
        DeviceSigner::verify(&signer.public_key(), &value, &signature).unwrap();
        assert!(DeviceSigner::verify(
            &signer.public_key(),
            &json!({"sequence": 5, "hash": "abc"}),
            &signature
        )
        .is_err());
    }
}
