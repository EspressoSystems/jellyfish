//! BLS Signature Scheme

use super::SignatureScheme;
use crate::{
    constants::{
        BLS_SIG_KEY_SIZE, BLS_SIG_SIGNATURE_SIZE, BLS_SIG_VERKEY_SIZE, CS_ID_BLS_SIG_NAIVE,
    },
    errors::PrimitivesError,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{
    convert::TryInto,
    format,
    rand::{CryptoRng, RngCore},
};

use blst::BLST_ERROR;
use espresso_systems_common::jellyfish::tag;
use tagged_base64::tagged;

pub use blst::min_sig::{PublicKey, SecretKey, Signature};
use zeroize::Zeroize;

/// Newtype wrapper for a BLS Signing Key.
#[tagged(tag::BLS_SIGNING_KEY)]
#[derive(Clone, Debug, Zeroize)]
pub struct BLSSignKey(SecretKey);

impl core::ops::Deref for BLSSignKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CanonicalSerialize for BLSSignKey {
    fn serialized_size(&self) -> usize {
        BLS_SIG_KEY_SIZE
    }

    fn serialize<W: ark_serialize::Write>(&self, writer: W) -> Result<(), SerializationError> {
        let bytes = &self.0.serialize();
        CanonicalSerialize::serialize(bytes.as_ref(), writer)
    }
}

impl CanonicalDeserialize for BLSSignKey {
    fn deserialize<R: ark_serialize::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len = <usize as ark_serialize::CanonicalDeserialize>::deserialize(&mut reader)?;
        if len != BLS_SIG_KEY_SIZE {
            return Err(SerializationError::InvalidData);
        }

        let mut key = [0u8; BLS_SIG_KEY_SIZE];
        reader.read_exact(&mut key)?;
        SecretKey::deserialize(&key)
            .map(Self)
            .map_err(|_| SerializationError::InvalidData)
    }
}

impl PartialEq for BLSSignKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.serialize() == other.0.serialize()
    }
}

impl Eq for BLSSignKey {}

/// Newtype wrapper for a BLS Signature.
#[tagged(tag::BLS_SIG)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BLSSignature(Signature);

impl core::ops::Deref for BLSSignature {
    type Target = Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CanonicalSerialize for BLSSignature {
    fn serialized_size(&self) -> usize {
        BLS_SIG_SIGNATURE_SIZE
    }

    fn serialize<W: ark_serialize::Write>(&self, writer: W) -> Result<(), SerializationError> {
        let bytes = &self.0.serialize();
        CanonicalSerialize::serialize(bytes.as_ref(), writer)
    }
}

impl CanonicalDeserialize for BLSSignature {
    fn deserialize<R: ark_serialize::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len = <usize as ark_serialize::CanonicalDeserialize>::deserialize(&mut reader)?;
        if len != BLS_SIG_SIGNATURE_SIZE {
            return Err(SerializationError::InvalidData);
        }

        let mut sig = [0u8; BLS_SIG_SIGNATURE_SIZE];
        reader.read_exact(&mut sig)?;
        Signature::deserialize(&sig)
            .map(Self)
            .map_err(|_| SerializationError::InvalidData)
    }
}

/// Newtype wrapper for a BLS Verification Key.
#[tagged(tag::BLS_VER_KEY)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BLSVerKey(PublicKey);

impl core::ops::Deref for BLSVerKey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CanonicalSerialize for BLSVerKey {
    fn serialized_size(&self) -> usize {
        BLS_SIG_VERKEY_SIZE
    }

    fn serialize<W: ark_serialize::Write>(&self, writer: W) -> Result<(), SerializationError> {
        let bytes = &self.0.serialize();
        CanonicalSerialize::serialize(bytes.as_ref(), writer)
    }
}

impl CanonicalDeserialize for BLSVerKey {
    fn deserialize<R: ark_serialize::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let len = <usize as ark_serialize::CanonicalDeserialize>::deserialize(&mut reader)?;
        if len != BLS_SIG_VERKEY_SIZE {
            return Err(SerializationError::InvalidData);
        }

        let mut key = [0u8; BLS_SIG_VERKEY_SIZE];
        reader.read_exact(&mut key)?;
        PublicKey::deserialize(&key)
            .map(Self)
            .map_err(|_| SerializationError::InvalidData)
    }
}

/// BLS signature scheme. Imports blst library.
pub struct BLSSignatureScheme;

impl SignatureScheme for BLSSignatureScheme {
    const CS_ID: &'static str = CS_ID_BLS_SIG_NAIVE;

    /// Public parameter
    type PublicParameter = ();

    /// Signing key
    type SigningKey = BLSSignKey;

    /// Verification key
    type VerificationKey = BLSVerKey;

    /// Signature
    type Signature = BLSSignature;

    /// A message is &\[MessageUnit\]
    type MessageUnit = u8;

    /// generate public parameters from RNG.
    /// If the RNG is not presented, use the default group generator.
    fn param_gen<R: CryptoRng + RngCore>(
        _prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError> {
        Ok(())
    }

    /// Sample a pair of keys.
    fn key_gen<R: CryptoRng + RngCore>(
        _pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), PrimitivesError> {
        let mut ikm = [0u8; 32];
        prng.fill_bytes(&mut ikm);
        let sk = match SecretKey::key_gen(&ikm, &[]) {
            Ok(sk) => sk,
            Err(e) => return Err(PrimitivesError::InternalError(format!("{:?}", e))),
        };
        let vk = sk.sk_to_pk();
        Ok((BLSSignKey(sk), BLSVerKey(vk)))
    }

    /// Sign a message
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError> {
        Ok(BLSSignature(sk.sign(
            msg.as_ref(),
            Self::CS_ID.as_bytes(),
            &[],
        )))
    }

    /// Verify a signature.
    fn verify<M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        vk: &Self::VerificationKey,
        msg: M,
        sig: &Self::Signature,
    ) -> Result<(), PrimitivesError> {
        match sig.verify(false, msg.as_ref(), Self::CS_ID.as_bytes(), &[], vk, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(PrimitivesError::VerificationError(format!("{:?}", e))),
        }
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, vec::Vec};

    use super::*;
    use crate::signatures::tests::{failed_verification, sign_and_verify};

    #[test]
    fn test_bls_sig() {
        let message = "this is a test message";
        let message_bad = "this is a wrong message";
        sign_and_verify::<BLSSignatureScheme>(message.as_ref());
        failed_verification::<BLSSignatureScheme>(message.as_ref(), message_bad.as_ref());
    }

    #[test]
    fn test_bls_sig_serde() {
        let rng = &mut test_rng();
        let parameters = BLSSignatureScheme::param_gen(Some(rng)).unwrap();
        let (sk, vk) = BLSSignatureScheme::key_gen(&parameters, rng).unwrap();

        // serde for Verification Key
        let mut keypair_bytes = Vec::new();
        vk.serialize(&mut keypair_bytes).unwrap();
        let keypair_de = BLSVerKey::deserialize(&keypair_bytes[..]).unwrap();
        assert_eq!(vk, keypair_de);
        // wrong byte length
        assert!(BLSVerKey::deserialize(&keypair_bytes[1..]).is_err());

        // serde for Signature
        let message = "this is a test message";
        let sig = BLSSignatureScheme::sign(&parameters, &sk, message.as_bytes(), rng).unwrap();
        let mut sig_bytes = Vec::new();
        sig.serialize(&mut sig_bytes).unwrap();
        let sig_de = BLSSignature::deserialize(&sig_bytes[..]).unwrap();
        assert_eq!(sig, sig_de);
        // wrong byte length
        assert!(BLSSignature::deserialize(&sig_bytes[1..]).is_err());
    }
}
