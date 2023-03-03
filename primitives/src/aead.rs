// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Wraps crypto_box's AEAD encryption scheme.

use crate::errors::PrimitivesError;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::{
    format,
    rand::{CryptoRng, RngCore},
    vec,
    vec::Vec,
};
use crypto_box::{
    aead::{Aead, AeadCore, Nonce, Payload},
    ChaChaBox,
};
use generic_array::{typenum::U24, GenericArray};

#[derive(Clone, Debug, Eq, Derivative)]
#[derivative(PartialEq, Hash)]
/// Public/encryption key for AEAD
pub struct EncKey(crypto_box::PublicKey);

impl From<[u8; 32]> for EncKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(crypto_box::PublicKey::from(bytes))
    }
}
impl From<EncKey> for [u8; 32] {
    fn from(enc_key: EncKey) -> Self {
        *enc_key.0.as_bytes()
    }
}
impl From<&DecKey> for EncKey {
    fn from(dec_key: &DecKey) -> Self {
        let enc_key = crypto_box::PublicKey::from(&dec_key.0);
        Self(enc_key)
    }
}
impl Default for EncKey {
    fn default() -> Self {
        Self(crypto_box::PublicKey::from([0u8; crypto_box::KEY_SIZE]))
    }
}

impl CanonicalSerialize for EncKey {
    /// Serializes the public key. Only compressed form is supported.
    /// TODO (tessico): should we fail if user asks for uncompressed form?
    fn serialize_with_mode<W>(&self, w: W, _compress: Compress) -> Result<(), SerializationError>
    where
        W: Write,
    {
        CanonicalSerialize::serialize_compressed(self.0.as_ref(), w)
    }
    fn serialized_size(&self, _compress: Compress) -> usize {
        crypto_box::KEY_SIZE
    }
}

impl CanonicalDeserialize for EncKey {
    /// Currently no checking is done on the public key. This is unimplemented
    /// upstream, see <https://github.com/RustCrypto/nacl-compat/blob/b57fb37eb558132546131d1ca2b59615d8aa3c72/crypto_box/src/lib.rs#L338>
    fn deserialize_with_mode<R>(
        mut reader: R,
        _compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let len = u64::deserialize_compressed_unchecked(&mut reader)?;
        if len != crypto_box::KEY_SIZE as u64 {
            return Err(SerializationError::InvalidData);
        }

        let mut key = [0u8; crypto_box::KEY_SIZE];
        reader.read_exact(&mut key)?;
        let enc_key = Self(crypto_box::PublicKey::from(key));
        if validate == Validate::Yes {
            // TODO (tessico): Currently this is a no-op. Should we fail if user asks to
            // validate?
            enc_key.check()?;
        }

        Ok(enc_key)
    }
}

impl Valid for EncKey {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

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
    ) -> Result<Ciphertext, PrimitivesError> {
        let nonce = ChaChaBox::generate_nonce(&mut rng);

        // generate an ephemeral key pair as the virtual sender to derive the crypto box
        let ephemeral_sk = crypto_box::SecretKey::generate(&mut rng);
        let ephemeral_pk = EncKey(crypto_box::PublicKey::from(&ephemeral_sk));
        let my_box = ChaChaBox::new(&self.0, &ephemeral_sk);

        // encrypt the message and associated data using crypto box
        let ct = my_box
            .encrypt(&nonce, Payload { msg: message, aad })
            .map_err(|e| PrimitivesError::InternalError(format!("{e:?}")))?;

        Ok(Ciphertext {
            nonce,
            ct,
            ephemeral_pk,
        })
    }
}

/// Private/decryption key for AEAD
// look into zeroization logic from aead lib
#[derive(Clone, Debug)]
struct DecKey(crypto_box::SecretKey);

impl From<[u8; 32]> for DecKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(crypto_box::SecretKey::from(bytes))
    }
}
impl From<DecKey> for [u8; 32] {
    fn from(dec_key: DecKey) -> Self {
        *dec_key.0.as_bytes()
    }
}

impl Default for DecKey {
    fn default() -> Self {
        Self(crypto_box::SecretKey::from([0; crypto_box::KEY_SIZE]))
    }
}

impl CanonicalSerialize for DecKey {
    fn serialize_with_mode<W>(&self, w: W, _compress: Compress) -> Result<(), SerializationError>
    where
        W: Write,
    {
        CanonicalSerialize::serialize_compressed(self.0.as_bytes().as_ref(), w)
    }
    fn serialized_size(&self, _compress: Compress) -> usize {
        crypto_box::KEY_SIZE
    }
}

impl CanonicalDeserialize for DecKey {
    fn deserialize_with_mode<R>(
        mut reader: R,
        _compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let len = u64::deserialize_compressed_unchecked(&mut reader)?;
        if len != crypto_box::KEY_SIZE as u64 {
            return Err(SerializationError::InvalidData);
        }
        let mut k = [0u8; crypto_box::KEY_SIZE];
        reader.read_exact(&mut k)?;
        let dec_key = Self(crypto_box::SecretKey::from(k));

        if validate == Validate::Yes {
            // TODO (tessico): Currently this is a no-op. Should we fail if user asks to
            // validate?
            dec_key.check()?;
        }

        Ok(dec_key)
    }
}

impl Valid for DecKey {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

/// Keypair for Authenticated Encryption with Associated Data
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
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
        let dec_key = crypto_box::SecretKey::generate(rng);
        let enc_key = crypto_box::PublicKey::from(&dec_key);
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
    /// If the associated data is different that that used during encryption,
    /// then decryption will fail.
    pub fn decrypt(&self, ciphertext: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>, PrimitivesError> {
        let my_box = ChaChaBox::new(&ciphertext.ephemeral_pk.0, &self.dec_key.0);
        let plaintext = my_box
            .decrypt(
                &ciphertext.nonce,
                Payload {
                    msg: &ciphertext.ct,
                    aad,
                },
            )
            .map_err(|e| PrimitivesError::FailedDecryption(format!("{e:?}")))?;
        Ok(plaintext)
    }
}

/// The ciphertext produced by AEAD encryption
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ciphertext {
    nonce: Nonce<ChaChaBox>,
    ct: Vec<u8>,
    ephemeral_pk: EncKey,
}

impl CanonicalSerialize for Ciphertext {
    /// Serialize the ciphertext. `Compress` mode is ignored.
    fn serialize_with_mode<W>(
        &self,
        mut writer: W,
        _compress: Compress,
    ) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        let len = self.nonce.len() as u64;
        len.serialize_compressed(&mut writer)?;
        writer.write_all(self.nonce.as_slice())?;

        let len = self.ct.len() as u64;
        len.serialize_compressed(&mut writer)?;
        writer.write_all(&self.ct[..])?;

        self.ephemeral_pk.serialize_compressed(&mut writer)
    }
    fn serialized_size(&self, compress: Compress) -> usize {
        core::mem::size_of::<u64>() * 2
            + self.nonce.len()
            + self.ct.len()
            + self.ephemeral_pk.serialized_size(compress)
    }
}

impl CanonicalDeserialize for Ciphertext {
    fn deserialize_with_mode<R>(
        mut reader: R,
        _compress: Compress,
        validate: Validate,
    ) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let len = u64::deserialize_uncompressed_unchecked(&mut reader)?;
        if len != 24 {
            return Err(SerializationError::InvalidData);
        }
        let mut nonce = [0u8; 24];
        reader.read_exact(&mut nonce)?;
        let nonce: Nonce<ChaChaBox> = GenericArray::<u8, U24>::clone_from_slice(&nonce);

        let len = u64::deserialize_uncompressed_unchecked(&mut reader)?;
        let mut ct = vec![0u8; len as usize];
        reader.read_exact(&mut ct)?;

        // Note: since EncKey validation check is a no-op, it will propagate here and
        // validation will also be a no-op. Keeping the validation flag for
        // potential future use when some EncKey validation is implemented.
        let ephemeral_pk = EncKey::deserialize_with_mode(&mut reader, Compress::Yes, validate)?;
        Ok(Self {
            nonce,
            ct,
            ephemeral_pk,
        })
    }
}

impl Valid for Ciphertext {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_aead_encryption() -> Result<(), PrimitivesError> {
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
    fn test_conversion() {
        let mut rng = jf_utils::test_rng();
        let mut rand_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_bytes[..]);
        let enc_key = EncKey::from(rand_bytes);
        let bytes: [u8; 32] = enc_key.into();
        assert_eq!(bytes, rand_bytes);

        rng.fill_bytes(&mut rand_bytes[..]);
        let dec_key = DecKey::from(rand_bytes);
        let bytes: [u8; 32] = dec_key.into();
        assert_eq!(bytes, rand_bytes);

        let keypair = KeyPair::generate(&mut rng);
        let enc_key = EncKey::from(&keypair.dec_key);
        assert_eq!(enc_key, keypair.enc_key());
    }

    #[test]
    fn test_serde() {
        let mut rng = jf_utils::test_rng();
        let keypair = KeyPair::generate(&mut rng);
        let msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        let aad = b"my associated data".to_vec();
        let ciphertext = keypair.enc_key.encrypt(&mut rng, &msg, &aad).unwrap();

        // serde for Keypair
        let mut keypair_bytes = Vec::new();
        keypair.serialize_compressed(&mut keypair_bytes).unwrap();
        let keypair_de = KeyPair::deserialize_compressed(&keypair_bytes[..]).unwrap();
        assert_eq!(keypair, keypair_de);
        // wrong byte length
        assert!(KeyPair::deserialize_compressed(&keypair_bytes[1..]).is_err());

        // serde for EncKey
        let mut enc_key_bytes = Vec::new();
        keypair
            .enc_key
            .serialize_compressed(&mut enc_key_bytes)
            .unwrap();
        let enc_key_de = EncKey::deserialize_compressed(&enc_key_bytes[..]).unwrap();
        assert_eq!(enc_key_de, keypair.enc_key);
        // wrong byte length
        assert!(EncKey::deserialize_compressed(&enc_key_bytes[1..]).is_err());

        // serde for DecKey
        let mut dec_key_bytes = Vec::new();
        keypair
            .dec_key
            .serialize_compressed(&mut dec_key_bytes)
            .unwrap();
        let dec_key_de = DecKey::deserialize_compressed(&dec_key_bytes[..]).unwrap();
        assert_eq!(dec_key_de.0.as_bytes(), keypair.dec_key.0.as_bytes());
        // wrong byte length
        assert!(DecKey::deserialize_compressed(&dec_key_bytes[1..]).is_err());

        // serde for Ciphertext
        let mut ciphertext_bytes = Vec::new();
        ciphertext
            .serialize_compressed(&mut ciphertext_bytes)
            .unwrap();
        let ciphertext_de = Ciphertext::deserialize_compressed(&ciphertext_bytes[..]).unwrap();
        assert_eq!(ciphertext_de, ciphertext);
        // wrong byte length
        assert!(Ciphertext::deserialize_compressed(&ciphertext_bytes[1..]).is_err());
    }
}
