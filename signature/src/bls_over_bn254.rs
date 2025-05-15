// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements the BLS signature over the BN254 curve.
//! The [BLS signature scheme][bls] relies on a bilinear map `e:G1 x G2 -> GT`
//! and a hash function `H` from a message input space (e.g. bytes) to a group
//! element `G1`. `H` must be such that for all `m`, the discrete logarithm
//! `H(m)` w.r.t to the generator of `G1` is unknown.
//!
//! The scheme works as follows:
//! Let `g1` and `g2` be generators of `G1` and `G2`.
//!
//! **KeyGen()**
//!    * sample a random `s` in the scalar field `Fr` and return the key pair
//!      `(sk,pk):=(s,g2^s)`
//!
//! **Sign(sk,m)**
//!    * return `sigma=H(m)^{sk}`
//!
//! **Verify(pk,m,sigma)**
//!    * Check that `e(sigma,g_2)=e(H(m),pk)`
//!
//! In this module:
//! * `e` is the pairing over the curve [BN254][bn254] supported by the EVM
//!   [EIP-196][eip196], [EIP197][eip197]
//! * `H` is implemented using the "hash-and-pray" approach. See function
//!   [`hash_to_curve`]
//!
//! [bls]: https://hovav.net/ucsd/dist/sigs.pdf
//! [bn254]: https://eprint.iacr.org/2005/133.pdf
//! [eip196]: https://eips.ethereum.org/EIPS/eip-196
//! [eip197]: https://eips.ethereum.org/EIPS/eip-197

use core::fmt::Debug;

use super::{AggregateableSignatureSchemes, SignatureScheme};
use crate::{
    constants::{tag, CS_ID_BLS_BN254},
    SignatureError,
};
use ark_bn254::{
    Bn254, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    bn::{Bn, G1Prepared, G2Prepared},
    pairing::Pairing,
    AffineRepr, CurveGroup, Group,
};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    BigInteger, Field, PrimeField,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, *};
use ark_std::{
    format,
    hash::{Hash, Hasher},
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
    One, UniformRand,
};
use derivative::Derivative;
use digest::DynDigest;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;

use crate::SignatureError::{ParameterError, VerificationError};

use tagged_base64::{tagged, TaggedBase64, Tb64Error};
use zeroize::Zeroize;

/// BLS signature scheme.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BLSOverBN254CurveSignatureScheme;

impl SignatureScheme for BLSOverBN254CurveSignatureScheme {
    const CS_ID: &'static str = CS_ID_BLS_BN254;

    /// Signing key.
    type SigningKey = SignKey;

    /// Verification key
    type VerificationKey = VerKey;

    /// Public Parameter
    type PublicParameter = ();

    /// Signature
    type Signature = Signature;

    /// A message is &\[MessageUnit\]
    type MessageUnit = u8;

    /// Generate public parameters from RNG.
    fn param_gen<R: CryptoRng + RngCore>(
        _prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, SignatureError> {
        Ok(())
    }

    /// Sample a pair of keys.
    fn key_gen<R: CryptoRng + RngCore>(
        _pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), SignatureError> {
        let kp = KeyPair::generate(prng);
        Ok((kp.sk.clone(), kp.vk))
    }

    /// Sign a message with the signing key
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, SignatureError> {
        let kp = KeyPair::generate_with_sign_key(sk.0);
        Ok(kp.sign(msg.as_ref(), Self::CS_ID))
    }

    /// Verify a signature.
    fn verify<M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        vk: &Self::VerificationKey,
        msg: M,
        sig: &Self::Signature,
    ) -> Result<(), SignatureError> {
        vk.verify(msg.as_ref(), sig, Self::CS_ID)
    }
}

impl AggregateableSignatureSchemes for BLSOverBN254CurveSignatureScheme {
    /// Aggregate multiple signatures into a single signature
    /// Follow the instantiation from <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-aggregate>
    fn aggregate(
        _pp: &Self::PublicParameter,
        _vks: &[Self::VerificationKey],
        sigs: &[Self::Signature],
    ) -> Result<Self::Signature, SignatureError> {
        if sigs.is_empty() {
            return Err(ParameterError("no signatures to aggregate".to_string()));
        }
        let mut agg_point = sigs[0].sigma;
        for sig in sigs.iter().skip(1) {
            agg_point += sig.sigma;
        }
        Ok(Self::Signature { sigma: agg_point })
    }

    /// Verify an aggregate signature w.r.t. a list of messages and public keys.
    /// It is user's responsibility to ensure that the public keys are
    /// validated.
    /// Follow the instantiation from <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-coreaggregateverify>
    fn aggregate_verify<M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        msgs: &[M],
        sig: &Self::Signature,
    ) -> Result<(), SignatureError> {
        if vks.is_empty() {
            return Err(ParameterError(
                "no verification key for signature verification".to_string(),
            ));
        }
        if vks.len() != msgs.len() {
            return Err(ParameterError(format!(
                "vks.len = {}; msgs.len = {}",
                vks.len(),
                msgs.len(),
            )));
        }
        // both oncurve check and subgroup check for verification keys
        vks.iter()
            .try_for_each(|vk| vk.check().map_err(|_| SignatureError::FailedValidityCheck))?;
        // NOTE: for BN curve, we don't need subgroup check, since co-factor is 1,
        // thus only conducting on_curve check
        if !sig.sigma.into_affine().is_on_curve() {
            return Err(SignatureError::FailedOnCurveCheck);
        }

        // verify
        let mut m_points: Vec<G1Prepared<_>> = msgs
            .iter()
            .map(|msg| {
                let msg_input: Vec<u8> = [msg.as_ref(), Self::CS_ID.as_bytes()].concat();
                let hash_value: G1Projective = hash_to_curve::<Keccak256>(msg_input.as_ref());
                G1Prepared::from(hash_value)
            })
            .collect();
        let mut vk_points: Vec<G2Prepared<_>> =
            vks.iter().map(|vk| G2Prepared::from(vk.0)).collect();
        m_points.push(G1Prepared::from(-sig.sigma));
        let g2 = G2Projective::generator();
        vk_points.push(G2Prepared::from(g2));
        let is_sig_valid = Bn254::multi_pairing(m_points, vk_points)
            == ark_ec::pairing::PairingOutput(
                <Bn<ark_bn254::Config> as ark_ec::pairing::Pairing>::TargetField::one(),
            );
        match is_sig_valid {
            true => Ok(()),
            false => Err(VerificationError("Batch pairing check failed".to_string())),
        }
    }

    /// Verify a multisignature w.r.t. a single message and a list of public
    /// keys. It is user's responsibility to ensure that the public keys are
    /// validated.
    /// Follow the instantiation from <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-fastaggregateverify>
    fn multi_sig_verify(
        pp: &Self::PublicParameter,
        vks: &[Self::VerificationKey],
        msg: &[Self::MessageUnit],
        sig: &Self::Signature,
    ) -> Result<(), SignatureError> {
        if vks.is_empty() {
            return Err(ParameterError(
                "no verification key for signature verification".to_string(),
            ));
        }
        // both oncurve check and subgroup check for verification keys
        vks.iter()
            .try_for_each(|vk| vk.check().map_err(|_| SignatureError::FailedValidityCheck))?;
        // NOTE: for BN curve, we don't need subgroup check, since co-factor is 1,
        // thus only conducting on_curve check
        if !sig.sigma.into_affine().is_on_curve() {
            return Err(SignatureError::FailedOnCurveCheck);
        }

        let mut agg_vk = vks[0].0;
        for vk in vks.iter().skip(1) {
            agg_vk += vk.0;
        }
        Self::verify(pp, &VerKey(agg_vk), msg, sig)
    }
}
// =====================================================
// Signing key
// =====================================================
#[derive(Clone, Hash, Default, Zeroize, Eq, PartialEq)]
#[zeroize(drop)]
/// Signing key for BLS signature. We intentionally omit the implementation of
/// `serde::Serializable` so that it won't be unnoticably serialized or printed
/// out through outer structs. However, users could manually serialize it into
/// bytes by calling `to_bytes()` or `to_tagged_base64()` and exercise with
/// self-cautions.
pub struct SignKey(pub(crate) ScalarField);

// This content-hiding `Debug` implementation makes sure that the auto-derived
// `Debug` for user's outer struct won't undesirably print out this secret key.
impl core::fmt::Debug for SignKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("<BLSSignKey>").finish()
    }
}

impl SignKey {
    /// Signature Key generation function
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> SignKey {
        SignKey(ScalarField::rand(prng))
    }

    /// Explicit calls to serialize a `SignKey` into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.into_bigint().to_bytes_le()
    }

    /// Deserialize `SignKey` from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ScalarField::from_le_bytes_mod_order(bytes))
    }

    /// Explicit calls to serialize a `SignKey` into `TaggedBase64`.
    pub fn to_tagged_base64(&self) -> Result<TaggedBase64, Tb64Error> {
        TaggedBase64::new(tag::BLS_SIGNING_KEY, &self.to_bytes())
    }
}

impl<'a> TryFrom<&'a TaggedBase64> for SignKey {
    type Error = Tb64Error;

    fn try_from(tb: &'a TaggedBase64) -> Result<Self, Self::Error> {
        if tb.tag() != tag::BLS_SIGNING_KEY {
            return Err(Tb64Error::InvalidTag);
        }
        Ok(SignKey::from_bytes(tb.as_ref()))
    }
}

impl TryFrom<TaggedBase64> for SignKey {
    type Error = Tb64Error;

    fn try_from(tb: TaggedBase64) -> Result<Self, Self::Error> {
        if tb.tag() != tag::BLS_SIGNING_KEY {
            return Err(Tb64Error::InvalidTag);
        }
        Ok(SignKey::from_bytes(tb.as_ref()))
    }
}

// =====================================================
// Verification key
// =====================================================

/// Signature public verification key
#[tagged(tag::BLS_VER_KEY)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Zeroize, Eq, PartialEq, Clone, Copy, Hash)]
pub struct VerKey(pub(crate) G2Projective);

// An arbitrary comparison for VerKey.
// The ordering here has no actual meaning.
impl PartialOrd for VerKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for VerKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.into_affine().xy().cmp(&other.0.into_affine().xy())
    }
}

// Override the Debug implementation to print the [`VerKey`] in TaggedBase64
// format
impl Debug for VerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl VerKey {
    /// Convert the verification key into the affine form.
    pub fn to_affine(&self) -> G2Affine {
        self.0.into_affine()
    }
}

// =====================================================
// Key pair
// =====================================================

/// Signature secret key pair used to sign messages
#[derive(Clone, Debug, Zeroize, Eq, PartialEq)]
#[zeroize(drop)]
pub struct KeyPair {
    sk: SignKey,
    vk: VerKey,
}

// =====================================================
// Signature
// =====================================================

/// The signature of BLS signature scheme
#[tagged(tag::BLS_SIG)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Eq, Clone, Debug)]
#[allow(non_snake_case)]
pub struct Signature {
    /// The signature is a G1 group element.
    pub sigma: G1Projective,
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.sigma, state);
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sigma == other.sigma
    }
}

// =====================================================
// end of definitions
// =====================================================

/// Non constant time hash to curve algorithm (a.k.a "hash-and-pray")
/// The hashing algorithm consists of the following steps:
///   1. Hash the bytes to a field element `x`.
///   2. Compute `Y = x^3 + 3`. (Note: the equation of the BN curve is
/// y^2=x^3+3)   3. Check if `Y` is a quadratic residue (QR), in which case
/// return `y=sqrt(Y)` otherwise try with `x+1, x+2` etc... until `Y` is a QR.
///   4. Return `P=(x,y)`
///
///  In the future we may switch to a constant time algorithm such as Fouque-Tibouchi <https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf>
/// * `H` - parameterizable hash function (e.g. SHA256, Keccak)
/// * `msg` - input message
/// * `returns` - A group element in G1
#[allow(non_snake_case)]
pub fn hash_to_curve<H: Default + DynDigest + Clone>(msg: &[u8]) -> G1Projective {
    let hasher_init = &[1u8];
    let hasher = <DefaultFieldHasher<H> as HashToField<BaseField>>::new(hasher_init);

    // General equation of the curve: y^2 = x^3 + ax + b
    // For BN254 we have a=0 and b=3 so we only use b
    let coeff_b: BaseField = BaseField::from(3);

    let mut x: BaseField = hasher.hash_to_field(msg, 1)[0];
    let mut Y: BaseField = x * x * x + coeff_b;

    // Loop until we find a quadratic residue
    while Y.legendre().is_qnr() {
        // println!("point with x={} is off the curve!!", x_affine);
        x += BaseField::from(1);
        Y = x * x * x + coeff_b;
    }

    // Safe unwrap as `y` is a quadratic residue
    let mut y = Y.sqrt().unwrap();

    // Ensure that y < p/2 where p is the modulus of Fq
    let mut y_mul_2 = y.into_bigint();
    y_mul_2.mul2();
    if y_mul_2 > BaseField::MODULUS {
        y.neg_in_place();
    }

    let g1_affine = G1Affine::new(x, y);
    G1Projective::from(g1_affine)
}

impl KeyPair {
    /// Key-pair generation algorithm
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> KeyPair {
        let sk = SignKey::generate(prng);
        let vk = VerKey::from(&sk);
        KeyPair { sk, vk }
    }

    /// Key pair generation using a particular sign key secret `sk`
    pub fn generate_with_sign_key(sk: ScalarField) -> Self {
        let sk = SignKey(sk);
        let vk = VerKey::from(&sk);
        KeyPair { sk, vk }
    }

    /// Get reference to verification key
    pub fn ver_key_ref(&self) -> &VerKey {
        &self.vk
    }

    /// Get the verification key
    pub fn ver_key(&self) -> VerKey {
        self.vk
    }

    /// Get the internal of the signing key, namely a P::ScalarField element
    pub fn sign_key_internal(&self) -> &ScalarField {
        &self.sk.0
    }

    /// Get the signing key reference
    pub fn sign_key_ref(&self) -> &SignKey {
        &self.sk
    }

    /// Signature function
    pub fn sign<B: AsRef<[u8]>>(&self, msg: &[u8], csid: B) -> Signature {
        let msg_input = [msg, csid.as_ref()].concat();
        let hash_value: G1Projective = hash_to_curve::<Keccak256>(&msg_input);
        let sigma = hash_value * self.sk.0;
        Signature { sigma }
    }

    /// Explicit calls to serialize a `KeyPair` into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sk.to_bytes()
    }

    /// Deserialize `KeyPair` from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::generate_with_sign_key(ScalarField::from_le_bytes_mod_order(bytes))
    }

    /// Explicit calls to serialize a `KeyPair` into `TaggedBase64`.
    pub fn to_tagged_base64(&self) -> Result<TaggedBase64, Tb64Error> {
        TaggedBase64::new(tag::BLS_KEY_PAIR, &self.to_bytes())
    }
}

impl<'a> TryFrom<&'a TaggedBase64> for KeyPair {
    type Error = Tb64Error;

    fn try_from(tb: &'a TaggedBase64) -> Result<Self, Self::Error> {
        if tb.tag() != tag::BLS_KEY_PAIR {
            return Err(Tb64Error::InvalidTag);
        }
        Ok(KeyPair::from_bytes(tb.as_ref()))
    }
}

impl TryFrom<TaggedBase64> for KeyPair {
    type Error = Tb64Error;

    fn try_from(tb: TaggedBase64) -> Result<Self, Self::Error> {
        if tb.tag() != tag::BLS_KEY_PAIR {
            return Err(Tb64Error::InvalidTag);
        }
        Ok(KeyPair::from_bytes(tb.as_ref()))
    }
}

impl From<SignKey> for KeyPair {
    fn from(sk: SignKey) -> Self {
        let vk = VerKey::from(&sk);
        Self { sk, vk }
    }
}

impl From<&SignKey> for VerKey {
    fn from(sk: &SignKey) -> Self {
        VerKey(G2Projective::generator() * sk.0)
    }
}

impl VerKey {
    /// Get the internal of verifying key, namely a curve Point
    pub fn internal(&self) -> G2Projective {
        self.0
    }

    /// Signature verification function
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        msg: &[u8],
        sig: &Signature,
        csid: B,
    ) -> Result<(), SignatureError> {
        // NOTE: for BN curve, we don't need subgroup check, since co-factor is 1,
        // thus only conducting on_curve check
        if !sig.sigma.into_affine().is_on_curve() {
            return Err(SignatureError::FailedOnCurveCheck);
        }
        let msg_input = [msg, csid.as_ref()].concat();
        let group_elem = hash_to_curve::<Keccak256>(&msg_input);
        let g2 = G2Projective::generator();

        let is_sig_valid = Bn254::pairing(sig.sigma, g2) == Bn254::pairing(group_elem, self.0);
        match is_sig_valid {
            true => Ok(()),
            false => Err(VerificationError("Pairing check failed".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {

    // These tests are adapted from schnorr.rs
    use crate::{
        bls_over_bn254::{BLSOverBN254CurveSignatureScheme, KeyPair, SignKey, Signature, VerKey},
        constants::CS_ID_BLS_BN254,
        tests::{agg_sign_and_verify, failed_verification, sign_and_verify},
        AggregateableSignatureSchemes, SignatureError,
    };
    use ark_bn254::{Fq, G1Affine};
    use ark_ec::AffineRepr;
    use ark_ff::vec;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{rand::Rng, vec::Vec, UniformRand};

    #[test]
    fn test_bls_signature_internals() {
        let mut rng = jf_utils::test_rng();
        let key_pair1 = KeyPair::generate(&mut rng);
        let key_pair2 = KeyPair::generate(&mut rng);
        let key_pair3 = KeyPair::generate(&mut rng);
        let pk_bad: VerKey = KeyPair::generate(&mut rng).ver_key();
        let key_pairs = [key_pair1, key_pair2, key_pair3];

        let mut msg = vec![];
        for i in 0..10 {
            for key_pair in &key_pairs {
                assert_eq!(key_pair.vk, VerKey::from(&key_pair.sk));
                let sig = key_pair.sign(&msg, CS_ID_BLS_BN254);
                let pk = key_pair.ver_key_ref();
                assert!(pk.verify(&msg, &sig, CS_ID_BLS_BN254).is_ok());
                // wrong public key
                assert!(pk_bad.verify(&msg, &sig, CS_ID_BLS_BN254).is_err());
                // wrong message
                msg.push(i as u8);
                assert!(pk.verify(&msg, &sig, CS_ID_BLS_BN254).is_err());
            }
        }

        // Test for long messages
        const SIZE: usize = 35; // Bigger than 32 which is the number of bytes needed to encode a field element
        let key_pair = KeyPair::generate(&mut rng);
        let msg = [33u8; SIZE];
        let sig = key_pair.sign(&msg, CS_ID_BLS_BN254);
        let pk = key_pair.ver_key_ref();
        assert!(pk.verify(&msg, &sig, CS_ID_BLS_BN254).is_ok());

        let wrong_msg = [33u8; SIZE + 1];
        assert!(pk.verify(&wrong_msg, &sig, CS_ID_BLS_BN254).is_err());
    }

    #[test]
    fn test_sig_trait() {
        let message = vec![87u8, 32u8];
        let wrong_message = vec![255u8];
        sign_and_verify::<BLSOverBN254CurveSignatureScheme>(message.as_slice());
        failed_verification::<BLSOverBN254CurveSignatureScheme>(
            message.as_slice(),
            wrong_message.as_slice(),
        );
    }

    #[test]
    fn test_agg_sig_trait() {
        let m1 = [87u8, 32u8];
        let m2 = [12u8, 2u8, 7u8];
        let m3 = [3u8, 6u8];
        let m4 = [72u8];
        let messages = vec![&m1[..], &m2[..], &m3[..], &m4[..]];
        let wrong_message = vec![255u8];
        agg_sign_and_verify::<BLSOverBN254CurveSignatureScheme>(
            messages.as_slice(),
            wrong_message.as_slice(),
        );
    }

    #[test]
    fn test_serde() {
        let mut rng = jf_utils::test_rng();
        let keypair = KeyPair::generate(&mut rng);
        let sk = SignKey::generate(&mut rng);
        let vk = keypair.ver_key();
        let msg = vec![87u8];
        let sig = keypair.sign(&msg, CS_ID_BLS_BN254);

        let mut ser_bytes: Vec<u8> = keypair.to_bytes();
        let de = KeyPair::from_bytes(&ser_bytes);
        assert_eq!(de, keypair);

        let tagged_blob = keypair.to_tagged_base64().unwrap();
        let de: KeyPair = tagged_blob.try_into().unwrap();
        assert_eq!(de, keypair);

        let mut ser_bytes: Vec<u8> = sk.to_bytes();
        let de = SignKey::from_bytes(&ser_bytes);
        assert_eq!(VerKey::from(&de), VerKey::from(&sk));

        let tagged_blob = sk.to_tagged_base64().unwrap();
        let de: SignKey = tagged_blob.try_into().unwrap();
        assert_eq!(de, sk);

        let mut ser_bytes: Vec<u8> = Vec::new();
        vk.serialize_compressed(&mut ser_bytes).unwrap();
        let de: VerKey = VerKey::deserialize_compressed(&ser_bytes[..]).unwrap();
        assert_eq!(de, vk);

        let mut ser_bytes: Vec<u8> = Vec::new();
        sig.serialize_compressed(&mut ser_bytes).unwrap();
        let de: Signature = Signature::deserialize_compressed(&ser_bytes[..]).unwrap();
        assert_eq!(de, sig);
    }

    #[test]
    fn test_cmp_keys() {
        let mut rng = jf_utils::test_rng();
        for _ in 0..100 {
            let sk1 = SignKey::generate(&mut rng);
            let sk2 = SignKey::generate(&mut rng);
            let vk1 = VerKey::from(&sk1);
            let vk2 = VerKey::from(&sk2);
            if sk1 == sk2 {
                assert_eq!(vk1.cmp(&vk2), ark_std::cmp::Ordering::Equal);
                assert_eq!(vk1, vk2);
            } else {
                assert_ne!(vk1.cmp(&vk2), ark_std::cmp::Ordering::Equal);
                assert_ne!(vk1, vk2);
            }
            // Generate two group elements that are equal but have different projective
            // representation.
            let mut vk = VerKey::from(&SignKey::generate(&mut rng));
            let vk_copy = vk;
            let scalar = ark_bn254::Fq::rand(&mut rng);
            let scalar_sq = scalar * scalar;
            let scalar_cube = scalar_sq * scalar;
            vk.0.x.mul_assign_by_fp(&scalar_sq);
            vk.0.y.mul_assign_by_fp(&scalar_cube);
            vk.0.z.mul_assign_by_fp(&scalar);
            assert_eq!(vk.cmp(&vk_copy), ark_std::cmp::Ordering::Equal);
            assert_eq!(vk, vk_copy);
        }
    }

    #[test]
    fn test_malformed_signature() {
        let mut rng = jf_utils::test_rng();
        let keypair = KeyPair::generate(&mut rng);
        let vk = keypair.ver_key();
        let msg = b"hello";

        let bad_sig = Signature {
            sigma: G1Affine::new_unchecked(Fq::rand(&mut rng), Fq::rand(&mut rng)).into_group(),
        };
        assert_eq!(
            vk.verify(msg.as_slice(), &bad_sig, CS_ID_BLS_BN254),
            Result::Err(SignatureError::FailedOnCurveCheck)
        );
        assert_eq!(
            BLSOverBN254CurveSignatureScheme::multi_sig_verify(
                &(),
                &[vk],
                msg.as_slice(),
                &bad_sig
            ),
            Result::Err(SignatureError::FailedOnCurveCheck)
        );
        assert_eq!(
            BLSOverBN254CurveSignatureScheme::aggregate_verify(
                &(),
                &[vk],
                &[msg.as_slice()],
                &bad_sig
            ),
            Result::Err(SignatureError::FailedOnCurveCheck)
        );
    }

    #[test]
    fn test_malformed_vk() {
        let mut rng = jf_utils::test_rng();
        let keypair = KeyPair::generate(&mut rng);
        let msg = b"hello";
        let sig = keypair.sign(msg.as_slice(), CS_ID_BLS_BN254);

        let mut bad_vk = keypair.ver_key();
        bad_vk.0.x.c0 += Fq::rand(&mut rng);

        assert_eq!(
            BLSOverBN254CurveSignatureScheme::multi_sig_verify(
                &(),
                &[bad_vk],
                msg.as_slice(),
                &sig
            ),
            Result::Err(SignatureError::FailedValidityCheck),
        );
        assert_eq!(
            BLSOverBN254CurveSignatureScheme::aggregate_verify(
                &(),
                &[bad_vk],
                &[msg.as_slice()],
                &sig
            ),
            Result::Err(SignatureError::FailedValidityCheck),
        );
    }
}
