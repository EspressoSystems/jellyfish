//! BLS Signature Scheme

use super::SignatureScheme;
use crate::{constants::CS_ID_BLS_SIG_NAIVE, errors::PrimitivesError};

use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use ark_std::fmt::Write;
use ark_std::{
    format,
    rand::{CryptoRng, RngCore},
};

use blst::{min_sig::*, BLST_ERROR};

pub use blst::min_sig::{PublicKey as BLSVerKey, SecretKey, Signature as BLSSignature};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, CanonicalSerialize)]
pub struct BLSSignKey(pub SecretKey);

impl core::ops::Deref for BLSSignKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for BLSSignKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let out = &self.0.serialize();
        serializer.serialize_newtype_struct("SecretKey", out)
    }
}

impl<'de> Deserialize<'de> for BLSSignKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Deserialize::deserialize(deserializer)
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
        Ok((BLSSignKey(sk), vk))
    }

    /// Sign a message
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError> {
        Ok(sk.sign(msg.as_ref(), Self::CS_ID.as_bytes(), &[]))
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
    use ark_std::test_rng;

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
    fn test_serialize() {
        let rng = &mut test_rng();
        let parameters = BLSSignatureScheme::param_gen(Some(rng)).unwrap();
        let (sk, pk) = BLSSignatureScheme::key_gen(&parameters, rng).unwrap();
    }
}
