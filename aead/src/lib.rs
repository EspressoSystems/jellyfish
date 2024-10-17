// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Use `crypto_kx` to derive shared session secrets and use symmetric AEAD
//! (`xchacha20poly1305`) for authenticated encryption with associated data.
//!
//! We only provide an ultra-thin wrapper for stable APIs for jellyfish users,
//! independent of RustCrypto's upstream changes.

#![cfg_attr(not(feature = "std"), no_std)]
// Temporarily allow warning for nightly compilation with [`displaydoc`].
#![allow(warnings)]
#![deny(missing_docs)]
#[cfg(test)]
extern crate std;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
#[doc(hidden)]
extern crate alloc;

use ark_serialize::*;
use ark_std::{
    fmt, format,
    ops::{Deref, DerefMut},
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use chacha20poly1305::{
    aead::{Aead, AeadCore, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use derivative::Derivative;
use displaydoc::Display;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Eq, Derivative, Serialize, Deserialize)]
#[derivative(PartialEq, Hash)]
/// Public/encryption key for AEAD
pub struct EncKey(crypto_kx::PublicKey);

impl From<[u8; 32]> for EncKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(crypto_kx::PublicKey::from(bytes))
    }
}
impl From<EncKey> for [u8; 32] {
    fn from(enc_key: EncKey) -> Self {
        *enc_key.0.as_ref()
    }
}
impl From<DecKey> for EncKey {
    fn from(dec_key: DecKey) -> Self {
        let enc_key = *crypto_kx::Keypair::from(dec_key.0).public();
        Self(enc_key)
    }
}
impl Default for EncKey {
    fn default() -> Self {
        Self(crypto_kx::PublicKey::from(
            [0u8; crypto_kx::PublicKey::BYTES],
        ))
    }
}
impl fmt::Debug for EncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("aead::EncKey")
            .field(self.0.as_ref())
            .finish()
    }
}

/// AEAD Error.
// This type is deliberately opaque as in `crypto_kx`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Display)]
pub struct AEADError;

impl ark_std::error::Error for AEADError {}

impl EncKey {
    /// Encrypt a message with authenticated associated data which is an
    /// optional bytestring which is not encrypted, but is authenticated
    /// along with the message. Failure to pass the same AAD that was used
    /// during encryption will cause decryption to fail, which is useful if you
    /// would like to "bind" the ciphertext to some identifier, like a
    /// digital signature key.
    pub fn encrypt(
        &self,
        mut rng: impl RngCore + CryptoRng,
        message: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, AEADError> {
        // generate an ephemeral key pair as the virtual sender to derive the crypto box
        let ephemeral_keypair = crypto_kx::Keypair::generate(&mut rng);
        // `crypto_kx` generates a pair of shared secrets, see <https://libsodium.gitbook.io/doc/key_exchange>
        // we use the transmission key of the ephemeral sender (equals to the receiving
        // key of the server) as the shared secret.
        let shared_secret = ephemeral_keypair.session_keys_to(&self.0).tx;
        let cipher = XChaCha20Poly1305::new(shared_secret.as_ref().into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rng);

        // encrypt the message and associated data using crypto box
        let ct = cipher
            .encrypt(&nonce, Payload { msg: message, aad })
            .map_err(|_| AEADError)?;

        Ok(Ciphertext {
            nonce: Nonce(nonce),
            ct,
            ephemeral_pk: EncKey(*ephemeral_keypair.public()),
        })
    }
}

/// Private/decryption key for AEAD
// look into zeroization logic from aead lib
#[derive(Clone, Serialize, Deserialize)]
struct DecKey(crypto_kx::SecretKey);

impl From<[u8; 32]> for DecKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(crypto_kx::SecretKey::from(bytes))
    }
}
impl From<DecKey> for [u8; 32] {
    fn from(dec_key: DecKey) -> Self {
        dec_key.0.to_bytes()
    }
}

impl Default for DecKey {
    fn default() -> Self {
        Self(crypto_kx::SecretKey::from([0; crypto_kx::SecretKey::BYTES]))
    }
}
impl fmt::Debug for DecKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("aead::DecKey")
            .field(&self.0.to_bytes())
            .finish()
    }
}

/// Keypair for Authenticated Encryption with Associated Data
#[derive(
    Clone, Debug, Default, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct KeyPair {
    enc_key: EncKey,
    dec_key: DecKey,
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &KeyPair) -> bool {
        self.enc_key == other.enc_key
    }
}

impl KeyPair {
    /// Randomly sample a key pair.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (enc_key, dec_key) = crypto_kx::Keypair::generate(rng).split();
        Self {
            enc_key: EncKey(enc_key),
            dec_key: DecKey(dec_key),
        }
    }

    /// Getter for the public/encryption key
    pub fn enc_key(&self) -> EncKey {
        self.enc_key.clone()
    }

    /// Getter for reference to the public/encryption key
    pub fn enc_key_ref(&self) -> &EncKey {
        &self.enc_key
    }

    /// Decrypt a ciphertext with authenticated associated data provided.
    /// If the associated data is different from that used during encryption,
    /// then decryption will fail.
    pub fn decrypt(&self, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>, AEADError> {
        let shared_secret = crypto_kx::Keypair::from(self.dec_key.0.clone())
            .session_keys_from(&ciphertext.ephemeral_pk.0)
            .rx;
        let cipher = XChaCha20Poly1305::new(shared_secret.as_ref().into());
        let plaintext = cipher
            .decrypt(
                &ciphertext.nonce,
                Payload {
                    msg: &ciphertext.ct,
                    aad,
                },
            )
            .map_err(|_| AEADError)?;
        Ok(plaintext)
    }
}
// newtype for `chacha20poly1305::XNonce` for easier serde support for
// `Ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Nonce(XNonce);

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NonceVisitor;

        impl<'de> serde::de::Visitor<'de> for NonceVisitor {
            type Value = Nonce;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("byte array")
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Nonce(*XNonce::from_slice(&v)))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(Nonce(*XNonce::from_slice(&bytes)))
            }
        }

        deserializer.deserialize_byte_buf(NonceVisitor)
    }
}

// Deref for newtype which acts like a smart pointer
impl Deref for Nonce {
    type Target = XNonce;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for Nonce {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The ciphertext produced by AEAD encryption
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct Ciphertext {
    nonce: Nonce,
    ct: Vec<u8>,
    ephemeral_pk: EncKey,
}

// TODO: (alex) Temporarily add CanonicalSerde back to these structs due to the
// limitations of `tagged` proc macro and requests from downstream usage.
// Tracking issue: <https://github.com/EspressoSystems/jellyfish/issues/288>
mod canonical_serde {
    use super::*;

    impl CanonicalSerialize for EncKey {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            _compress: Compress,
        ) -> Result<(), SerializationError> {
            let bytes: [u8; crypto_kx::PublicKey::BYTES] = self.clone().into();
            writer.write_all(&bytes)?;
            Ok(())
        }
        fn serialized_size(&self, _compress: Compress) -> usize {
            crypto_kx::PublicKey::BYTES
        }
    }

    impl CanonicalDeserialize for EncKey {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            _compress: Compress,
            _validate: Validate,
        ) -> Result<Self, SerializationError> {
            let mut result = [0u8; crypto_kx::PublicKey::BYTES];
            reader.read_exact(&mut result)?;
            Ok(EncKey(crypto_kx::PublicKey::from(result)))
        }
    }

    impl Valid for EncKey {
        fn check(&self) -> Result<(), SerializationError> {
            Ok(())
        }
    }

    impl CanonicalSerialize for DecKey {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            _compress: Compress,
        ) -> Result<(), SerializationError> {
            let bytes: [u8; crypto_kx::SecretKey::BYTES] = self.clone().into();
            writer.write_all(&bytes)?;
            Ok(())
        }
        fn serialized_size(&self, _compress: Compress) -> usize {
            crypto_kx::SecretKey::BYTES
        }
    }

    impl CanonicalDeserialize for DecKey {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            _compress: Compress,
            _validate: Validate,
        ) -> Result<Self, SerializationError> {
            let mut result = [0u8; crypto_kx::SecretKey::BYTES];
            reader.read_exact(&mut result)?;
            Ok(DecKey(crypto_kx::SecretKey::from(result)))
        }
    }
    impl Valid for DecKey {
        fn check(&self) -> Result<(), SerializationError> {
            Ok(())
        }
    }

    impl CanonicalSerialize for Nonce {
        fn serialize_with_mode<W: Write>(
            &self,
            mut writer: W,
            _compress: Compress,
        ) -> Result<(), SerializationError> {
            writer.write_all(self.0.as_slice())?;
            Ok(())
        }
        fn serialized_size(&self, _compress: Compress) -> usize {
            // see <https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/type.XNonce.html>
            24
        }
    }

    impl CanonicalDeserialize for Nonce {
        fn deserialize_with_mode<R: Read>(
            mut reader: R,
            _compress: Compress,
            _validate: Validate,
        ) -> Result<Self, SerializationError> {
            let mut result = [0u8; 24];
            reader.read_exact(&mut result)?;
            Ok(Nonce(XNonce::from(result)))
        }
    }
    impl Valid for Nonce {
        fn check(&self) -> Result<(), SerializationError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_aead_encryption() -> Result<(), AEADError> {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let keypair1 = KeyPair::generate(&mut rng);
        let keypair2 = KeyPair::generate(&mut rng);
        let msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        let aad = b"my associated data".to_vec();

        // check correctness
        let ct1 = keypair1.enc_key.encrypt(&mut rng, &msg, &aad)?;
        assert!(keypair1.decrypt(&ct1, &aad).is_ok());
        let plaintext1 = keypair1.decrypt(&ct1, &aad)?;
        assert!(msg == plaintext1);

        // check soundness
        assert!(keypair2.decrypt(&ct1, &aad).is_err());
        assert!(keypair1.decrypt(&ct1, b"wrong associated data").is_err());
        let ct2 = keypair1.enc_key.encrypt(&mut rng, b"wrong message", &aad)?;
        let plaintext2 = keypair1.decrypt(&ct2, &aad)?;
        assert!(msg != plaintext2);

        // rng or nounce shouldn't affect decryption
        let rng = ChaCha20Rng::from_seed([1u8; 32]);
        let ct3 = keypair1.enc_key.encrypt(rng, &msg, &aad)?;
        assert!(keypair1.decrypt(&ct3, &aad).is_ok());
        let plaintext3 = keypair1.decrypt(&ct3, &aad)?;
        assert!(msg == plaintext3);

        Ok(())
    }

    #[test]
    fn test_serde() {
        let mut rng = jf_utils::test_rng();
        let keypair = KeyPair::generate(&mut rng);
        let msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        let aad = b"my associated data".to_vec();
        let ciphertext = keypair.enc_key.encrypt(&mut rng, &msg, &aad).unwrap();

        // serde for Keypair
        let bytes = bincode::serialize(&keypair).unwrap();
        assert_eq!(keypair, bincode::deserialize(&bytes).unwrap());
        // wrong byte length
        assert!(bincode::deserialize::<KeyPair>(&bytes[1..]).is_err());

        // serde for EncKey
        let bytes = bincode::serialize(keypair.enc_key_ref()).unwrap();
        assert_eq!(
            keypair.enc_key_ref(),
            &bincode::deserialize(&bytes).unwrap()
        );
        // wrong byte length
        assert!(bincode::deserialize::<EncKey>(&bytes[1..]).is_err());

        // serde for DecKey
        let bytes = bincode::serialize(&keypair.dec_key).unwrap();
        assert_eq!(
            keypair.dec_key.0.to_bytes(),
            bincode::deserialize::<DecKey>(&bytes).unwrap().0.to_bytes()
        );
        // wrong byte length
        assert!(bincode::deserialize::<DecKey>(&bytes[1..]).is_err());

        // serde for Ciphertext
        let bytes = bincode::serialize(&ciphertext).unwrap();
        assert_eq!(&ciphertext, &bincode::deserialize(&bytes).unwrap());
        // wrong byte length
        assert!(bincode::deserialize::<Ciphertext>(&bytes[1..]).is_err());
    }

    #[test]
    fn test_canonical_serde() {
        let mut rng = jf_utils::test_rng();
        let keypair = KeyPair::generate(&mut rng);
        let msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        let aad = b"my associated data".to_vec();
        let ciphertext = keypair.enc_key.encrypt(&mut rng, &msg, &aad).unwrap();

        // when testing keypair, already tests serde on pk and sk
        let mut bytes = Vec::new();
        CanonicalSerialize::serialize_compressed(&keypair, &mut bytes).unwrap();
        assert_eq!(
            keypair,
            KeyPair::deserialize_compressed(&bytes[..]).unwrap()
        );
        assert!(KeyPair::deserialize_compressed(&bytes[1..]).is_err());

        let mut bytes = Vec::new();
        CanonicalSerialize::serialize_compressed(&ciphertext, &mut bytes).unwrap();
        assert_eq!(
            ciphertext,
            Ciphertext::deserialize_compressed(&bytes[..]).unwrap()
        );
        assert!(Ciphertext::deserialize_compressed(&bytes[1..]).is_err());
    }
}
