// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! BLS Signature Scheme
//!
//! Conforming to [IRTF draft][irtf], wrapping [`blst` crate][blst] under the
//! hood.
//!
//! [irtf]: https://datatracker.ietf.org/doc/pdf/draft-irtf-cfrg-bls-signature-05
//! [blst]: https://github.com/supranational/blst
//!
//! # Examples
//!
//! ```
//! use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
//! use jf_signature::{SignatureScheme, bls_over_bls12381::BLSSignatureScheme};
//!
//! let pp = BLSSignatureScheme::param_gen::<ChaCha20Rng>(None)?;
//!
//! // make sure the PRNG passed has good and trusted entropy.
//! // you could use `OsRng` from `rand_core` or `getrandom` crate,
//! // or a `SeedableRng` like `ChaChaRng` with seed generated from good randomness source.
//! let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
//! let (sk, pk) = BLSSignatureScheme::key_gen(&pp, &mut rng)?;
//!
//! let msg = "The quick brown fox jumps over the lazy dog";
//! let sig = BLSSignatureScheme::sign(&pp, &sk, &msg, &mut rng)?;
//! assert!(BLSSignatureScheme::verify(&pp, &pk, &msg, &sig).is_ok());
//!
//! # Ok::<(), Box<dyn ark_std::error::Error>>(())
//! ```
//!
//! ## Generating independent keys from the same IKM
//!
//! In case you want to keep the IKM for multiple key pairs, and potentially
//! reconstruct them later on from IKM.
//!
//! ```
//! use rand_chacha::{ChaCha20Rng, rand_core::{SeedableRng, RngCore}};
//! use sha2::{Sha256, Digest};
//! use jf_signature::{SignatureScheme, bls_over_bls12381::BLSSignatureScheme};
//!
//! let mut rng = ChaCha20Rng::from_seed([0u8; 32]); // seed from proper entropy source in practice!
//! let pp = BLSSignatureScheme::param_gen::<ChaCha20Rng>(None)?;
//!
//! // NOTE: in practice, please use [`zeroize`][zeroize] to wipe sensitive
//! // key materials out of memory.
//! let mut ikm = [0u8; 32]; // should be at least 32 bytes
//! rng.fill_bytes(&mut ikm);
//!
//! let mut hasher = Sha256::new();
//! hasher.update(b"MY-BLS-SIG-KEYGEN-SALT-DOM-SEP");
//! let salt = hasher.finalize();
//!
//! let (sk1, pk1) = BLSSignatureScheme::key_gen_v5(&ikm, &salt, b"banking".as_ref())?;
//! let (sk2, pk2) = BLSSignatureScheme::key_gen_v5(&ikm, &salt, b"legal".as_ref())?;
//!
//! let msg = "I authorize transferring 10 dollars to Alice";
//! let sig = BLSSignatureScheme::sign(&pp, &sk1, &msg, &mut rng)?;
//! assert!(BLSSignatureScheme::verify(&pp, &pk1, &msg, &sig).is_ok());
//!
//! let msg = "I agree to the Terms and Conditions.";
//! let sig = BLSSignatureScheme::sign(&pp, &sk2, &msg, &mut rng)?;
//! assert!(BLSSignatureScheme::verify(&pp, &pk2, &msg, &sig).is_ok());
//!
//! # Ok::<(), Box<dyn ark_std::error::Error>>(())
//! ```
//!
//! [zeroize]: https://github.com/RustCrypto/utils/tree/master/zeroize

use super::SignatureScheme;
use crate::{
    constants::{
        tag, BLS_SIG_COMPRESSED_PK_SIZE, BLS_SIG_COMPRESSED_SIGNATURE_SIZE, BLS_SIG_PK_SIZE,
        BLS_SIG_SIGNATURE_SIZE, BLS_SIG_SK_SIZE,
    },
    SignatureError,
};

use crate::constants::CS_ID_BLS_MIN_SIG;
use ark_serialize::*;
use ark_std::{
    format,
    ops::{Deref, DerefMut},
    rand::{CryptoRng, RngCore},
};
use blst::{min_sig::*, BLST_ERROR};
use derivative::Derivative;
use tagged_base64::{tagged, TaggedBase64, Tb64Error};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Derivative, Zeroize)]
#[zeroize(drop)]
/// A BLS Secret Key (Signing Key). We intentionally omit the implementation of
/// `serde::Serializable` so that it won't be unnoticably serialized or printed
/// out through outer structs. However, users could manually serialize it into
/// bytes by calling `to_bytes()` or `to_tagged_base64()` and exercise with
/// self-cautions.
pub struct BLSSignKey(SecretKey);

// This content-hiding `Debug` implementation makes sure that the auto-derived
// `Debug` for user's outer struct won't undesirably print out this secret key.
impl core::fmt::Debug for BLSSignKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("<BLSSignKey>").finish()
    }
}

impl BLSSignKey {
    /// Explicit calls to serialize a `SignKey` into bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserialize `SignKey` from bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<BLSSignKey, BLST_ERROR> {
        SecretKey::from_bytes(bytes).map(|sk| BLSSignKey(sk))
    }

    /// Explicit calls to serialize a `SignKey` into `TaggedBase64`.
    pub fn to_tagged_base64(&self) -> Result<TaggedBase64, Tb64Error> {
        TaggedBase64::new(tag::BLS_SIGNING_KEY, &self.to_bytes())
    }
}

impl<'a> TryFrom<&'a TaggedBase64> for BLSSignKey {
    type Error = Tb64Error;

    fn try_from(tb: &'a TaggedBase64) -> Result<Self, Self::Error> {
        if tb.tag() != tag::BLS_SIGNING_KEY {
            return Err(Tb64Error::InvalidTag);
        }
        SecretKey::from_bytes(tb.as_ref())
            .map(|sk| BLSSignKey(sk))
            .map_err(|err| Tb64Error::InvalidData)
    }
}

impl TryFrom<TaggedBase64> for BLSSignKey {
    type Error = Tb64Error;

    fn try_from(tb: TaggedBase64) -> Result<Self, Self::Error> {
        if tb.tag() != tag::BLS_SIGNING_KEY {
            return Err(Tb64Error::InvalidTag);
        }
        SecretKey::from_bytes(tb.as_ref())
            .map(|sk| BLSSignKey(sk))
            .map_err(|err| Tb64Error::InvalidData)
    }
}

impl PartialEq for BLSSignKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.serialize() == other.0.serialize()
    }
}

impl Eq for BLSSignKey {}

#[tagged(tag::BLS_VER_KEY)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Copy)]
/// A BLS Public Key (Verification Key).
pub struct BLSVerKey(PublicKey);

impl Deref for BLSVerKey {
    type Target = PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CanonicalSerialize for BLSVerKey {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        if compress == Compress::No {
            CanonicalSerialize::serialize_compressed(&self.serialize()[..], writer)
        } else {
            CanonicalSerialize::serialize_compressed(&self.compress()[..], writer)
        }
    }

    fn serialized_size(&self, _compress: Compress) -> usize {
        BLS_SIG_COMPRESSED_PK_SIZE
    }

    fn uncompressed_size(&self) -> usize {
        BLS_SIG_PK_SIZE
    }
}

impl CanonicalDeserialize for BLSVerKey {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let len = <usize as ark_serialize::CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            Compress::Yes,
            validate,
        )?;
        // length validation is always performed
        if !(len == BLS_SIG_COMPRESSED_PK_SIZE && compress == Compress::Yes
            || len == BLS_SIG_PK_SIZE && compress == Compress::No)
        {
            return Err(SerializationError::InvalidData);
        }

        let pk = if compress == Compress::Yes {
            let mut pk_bytes = [0u8; BLS_SIG_COMPRESSED_PK_SIZE];
            reader.read_exact(&mut pk_bytes)?;

            PublicKey::uncompress(&pk_bytes).map_err(|_| SerializationError::InvalidData)?
        } else {
            let mut pk_bytes = [0u8; BLS_SIG_PK_SIZE];
            reader.read_exact(&mut pk_bytes)?;

            PublicKey::deserialize(&pk_bytes).map_err(|_| SerializationError::InvalidData)?
        };

        let ver_key = Self(pk);
        if validate == Validate::Yes && ver_key.check().is_err() {
            return Err(SerializationError::InvalidData);
        }

        Ok(ver_key)
    }
}

impl Valid for BLSVerKey {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.0
            .validate()
            .map_err(|_| SerializationError::InvalidData)
    }
}

/// A BLS Signature.
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[tagged(tag::BLS_SIG)]
pub struct BLSSignature(Signature);

impl Deref for BLSSignature {
    type Target = Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CanonicalSerialize for BLSSignature {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        if compress == Compress::No {
            CanonicalSerialize::serialize_compressed(&self.serialize()[..], writer)
        } else {
            CanonicalSerialize::serialize_compressed(&self.compress()[..], writer)
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        if compress == Compress::Yes {
            BLS_SIG_COMPRESSED_SIGNATURE_SIZE
        } else {
            BLS_SIG_SIGNATURE_SIZE
        }
    }
}

impl CanonicalDeserialize for BLSSignature {
    // compressed
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let len = <usize as ark_serialize::CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            Compress::Yes,
            Validate::Yes,
        )?;
        if !(len == BLS_SIG_COMPRESSED_SIGNATURE_SIZE && compress == Compress::Yes
            || len == BLS_SIG_SIGNATURE_SIZE && compress == Compress::No)
        {
            return Err(SerializationError::InvalidData);
        }

        let sig = if compress == Compress::Yes {
            let mut sig_bytes = [0u8; BLS_SIG_COMPRESSED_SIGNATURE_SIZE];
            reader.read_exact(&mut sig_bytes)?;
            Signature::uncompress(&sig_bytes).map_err(|_| SerializationError::InvalidData)?
        } else {
            let mut sig_bytes = [0u8; BLS_SIG_SIGNATURE_SIZE];
            reader.read_exact(&mut sig_bytes)?;

            Signature::deserialize(&sig_bytes).map_err(|_| SerializationError::InvalidData)?
        };

        let bls_sig = Self(sig);

        if validate == Validate::Yes && bls_sig.check().is_err() {
            return Err(SerializationError::InvalidData);
        }

        Ok(bls_sig)
    }
}

impl Valid for BLSSignature {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.0
            .validate(true)
            .map_err(|_| SerializationError::InvalidData)
    }
}

/// BLS signature scheme. Wrapping around structs from the `blst` crate.
/// See [module-level documentation](self) for example usage.
#[derive(Clone, Debug)]
pub struct BLSSignatureScheme;

impl SignatureScheme for BLSSignatureScheme {
    const CS_ID: &'static str = CS_ID_BLS_MIN_SIG;

    /// Signing key
    type SigningKey = BLSSignKey;

    /// Verification key
    type VerificationKey = BLSVerKey;

    /// Public parameter
    type PublicParameter = ();

    /// Signature
    type Signature = BLSSignature;

    /// A message is &\[MessageUnit\]
    type MessageUnit = u8;

    /// generate public parameters from RNG.
    /// If the RNG is not presented, use the default group generator.
    fn param_gen<R: CryptoRng + RngCore>(
        _prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, SignatureError> {
        Ok(())
    }

    /// Generate a BLS key pair.
    /// Make sure the `prng` passed in are properly seeded with trusted entropy.
    fn key_gen<R: CryptoRng + RngCore>(
        _pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), SignatureError> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        prng.fill_bytes(ikm.deref_mut());

        let sk = SecretKey::key_gen(ikm.deref(), &[])?;
        let vk = sk.sk_to_pk();
        Ok((BLSSignKey(sk), BLSVerKey(vk)))
    }

    /// Sign a message
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, SignatureError> {
        Ok(BLSSignature(sk.0.sign(
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
    ) -> Result<(), SignatureError> {
        vk.check()
            .map_err(|_| SignatureError::FailedValidityCheck)?;
        sig.check()
            .map_err(|_| SignatureError::FailedValidityCheck)?;
        match sig.verify(false, msg.as_ref(), Self::CS_ID.as_bytes(), &[], vk, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(SignatureError::VerificationError(format!("{e:?}"))),
        }
    }
}

impl BLSSignatureScheme {
    /// Alternative deterministic key_gen compatible with [IRTF draft v5][v5].
    ///
    /// - Secret byte string `ikm` MUST be infeasible to guess, ideally
    ///   generated by a trusted source of randomness. `ikm` MUST be at least 32
    ///   bytes long, but it MAY be longer.
    /// - `salt` should either be empty or an unstructured byte string. It is
    ///   RECOMMENDED to fix a uniformly random byte string of length 32. See
    ///   details [here][salt].
    /// - `key_info` is optional, it MAY be used to derived multiple independent
    ///   keys from the same `ikm`. By default, `key_info` is the empty string.
    ///
    /// [v5]: https://datatracker.ietf.org/doc/pdf/draft-irtf-cfrg-bls-signature-05
    /// [salt]: https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-choosing-a-salt-value-for-k
    pub fn key_gen_v5(
        ikm: &[u8],
        salt: &[u8],
        key_info: &[u8],
    ) -> Result<
        (
            <Self as SignatureScheme>::SigningKey,
            <Self as SignatureScheme>::VerificationKey,
        ),
        SignatureError,
    > {
        let sk = SecretKey::key_gen_v5(ikm, salt, key_info)?;
        let vk = sk.sk_to_pk();

        Ok((BLSSignKey(sk), BLSVerKey(vk)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::{failed_verification, sign_and_verify};
    use ark_std::{fmt::Debug, rand::Rng, vec};

    #[test]
    fn test_bls_sig() {
        let message = "this is a test message";
        let message_bad = "this is a wrong message";
        sign_and_verify::<BLSSignatureScheme>(message.as_ref());
        failed_verification::<BLSSignatureScheme>(message.as_ref(), message_bad.as_ref());
    }

    #[test]
    fn test_canonical_serde() {
        let mut rng = jf_utils::test_rng();
        let (sk, pk) = BLSSignatureScheme::key_gen(&(), &mut rng).unwrap();
        let msg = "The quick brown fox jumps over the lazy dog";
        let sig = BLSSignatureScheme::sign(&(), &sk, msg, &mut rng).unwrap();

        let bytes = sk.to_bytes();
        let de = BLSSignKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk, de);

        let tagged_blob = sk.to_tagged_base64().unwrap();
        let de: BLSSignKey = tagged_blob.try_into().unwrap();
        assert_eq!(sk, de);

        test_canonical_serde_helper(pk);
        test_canonical_serde_helper(sig);
    }

    fn test_canonical_serde_helper<T>(data: T)
    where
        T: CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq,
    {
        let mut bytes = vec![];
        CanonicalSerialize::serialize_compressed(&data, &mut bytes).unwrap();
        let de: T = CanonicalDeserialize::deserialize_compressed(&bytes[..]).unwrap();
        assert_eq!(data, de);

        bytes = vec![];
        CanonicalSerialize::serialize_uncompressed(&data, &mut bytes).unwrap();
        let de: T = CanonicalDeserialize::deserialize_uncompressed(&bytes[..]).unwrap();
        assert_eq!(data, de);

        bytes = vec![];
        CanonicalSerialize::serialize_compressed(&data, &mut bytes).unwrap();
        let de: T = CanonicalDeserialize::deserialize_compressed_unchecked(&bytes[..]).unwrap();
        assert_eq!(data, de);
    }
}
