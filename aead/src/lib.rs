// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Use `crypto_kx` to derive shared session secrets and use symmetric AEAD
//! (`xchacha20poly1305`) for authenticated encryption with associated data.
//!
//! We only provide an ultra-thin wrapper for stable APIs for jellyfish users,
//! independent of RustCrypto's upstream changes.

/// Improvements include enhanced error handling, reduced cloning, zeroization for sensitive data, and better documentation.
use zeroize::Zeroize;
use color_eyre::eyre::{Result, Report};
use serde::{Deserialize, Serialize};
use std::io::Write;
use chacha20poly1305::{
    aead::{Aead, AeadCore, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use crypto_kx::{Keypair, PublicKey, SecretKey};

/// Public/encryption key for AEAD.
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct EncKey(PublicKey);

impl EncKey {
    /// Encrypts a message using authenticated associated data (AAD).
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        mut rng: R,
        message: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, AEADError> {
        let ephemeral_keypair = Keypair::generate(&mut rng);
        let shared_secret = ephemeral_keypair.session_keys_to(&self.0).tx;
        let cipher = XChaCha20Poly1305::new(shared_secret.as_ref().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rng);

        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: message, aad })
            .map_err(|_| AEADError)?;

        Ok(Ciphertext {
            nonce: Nonce(nonce),
            ct: ciphertext,
            ephemeral_pk: EncKey(*ephemeral_keypair.public()),
        })
    }
}

/// Private/decryption key for AEAD with zeroization.
#[derive(Serialize, Deserialize)]
pub struct DecKey(SecretKey);

impl DecKey {
    /// Explicitly zeroize sensitive data when the struct goes out of scope.
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for DecKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A keypair for authenticated encryption with associated data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    enc_key: EncKey,
    dec_key: DecKey,
}

impl KeyPair {
    /// Generates a new random keypair.
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let (public, secret) = Keypair::generate(&mut rng).split();
        Self {
            enc_key: EncKey(public),
            dec_key: DecKey(secret),
        }
    }

    /// Decrypts a ciphertext, verifying the AAD.
    pub fn decrypt(&self, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>, AEADError> {
        let shared_secret = Keypair::from(self.dec_key.0.clone())
            .session_keys_from(&ciphertext.ephemeral_pk.0)
            .rx;
        let cipher = XChaCha20Poly1305::new(shared_secret.as_ref().into());

        cipher
            .decrypt(&ciphertext.nonce, Payload { msg: &ciphertext.ct, aad })
            .map_err(|_| AEADError)
    }
}

/// A structure representing encrypted data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    nonce: Nonce,
    ct: Vec<u8>,
    ephemeral_pk: EncKey,
}

/// Wrapper for `XNonce` to simplify serialization/deserialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Nonce(XNonce);

impl Serialize for Nonce {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(Self(*XNonce::from_slice(&bytes)))
    }
}

/// Error for AEAD operations.
#[derive(Debug, thiserror::Error)]
#[error("An AEAD error occurred")]
pub struct AEADError;
