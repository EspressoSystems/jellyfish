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

use super::{AggregateableSignatureSchemes, SignatureScheme};
use crate::{constants::CS_ID_BLS_BN254, errors::PrimitivesError};
use ark_bn254::{
    Bn254, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    bn::{Bn, G1Prepared, G2Prepared},
    pairing::Pairing,
    CurveGroup, Group,
};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    BigInteger, Field, PrimeField,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, *};
use ark_std::{
    format,
    hash::{Hash, Hasher},
    rand::{CryptoRng, Rng, RngCore},
    string::ToString,
    vec::Vec,
    One, UniformRand,
};
use digest::DynDigest;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;

use crate::errors::PrimitivesError::{ParameterError, VerificationError};
use espresso_systems_common::jellyfish::tag;

use tagged_base64::tagged;
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
    ) -> Result<Self::PublicParameter, PrimitivesError> {
        Ok(())
    }

    /// Sample a pair of keys.
    fn key_gen<R: CryptoRng + RngCore>(
        _pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), PrimitivesError> {
        let kp = KeyPair::generate(prng);
        Ok((kp.sk.clone(), kp.vk))
    }

    /// Sign a message with the signing key
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError> {
        let kp = KeyPair::generate_with_sign_key(sk.0);
        Ok(kp.sign(msg.as_ref(), Self::CS_ID))
    }

    /// Verify a signature.
    fn verify<M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        vk: &Self::VerificationKey,
        msg: M,
        sig: &Self::Signature,
    ) -> Result<(), PrimitivesError> {
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
    ) -> Result<Self::Signature, PrimitivesError> {
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
    ) -> Result<(), PrimitivesError> {
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
        // subgroup check
        // TODO: for BN we don't need a subgroup check
        sig.sigma.check().map_err(|_e| {
            PrimitivesError::ParameterError("signature subgroup check failed".to_string())
        })?;
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
    ) -> Result<(), PrimitivesError> {
        if vks.is_empty() {
            return Err(ParameterError(
                "no verification key for signature verification".to_string(),
            ));
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
#[tagged(tag::BLS_SIGNING_KEY)]
#[derive(
    Clone, Hash, Default, Zeroize, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Debug,
)]
#[zeroize(drop)]
/// Signing key for BLS signature.
pub struct SignKey(pub(crate) ScalarField);

// =====================================================
// Verification key
// =====================================================

/// Signature public verification key
#[tagged(tag::BLS_VER_KEY)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Zeroize, Eq, Clone, Debug, Copy)]
pub struct VerKey(pub(crate) G2Projective);

impl Hash for VerKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.0.into_affine(), state)
    }
}

impl PartialEq for VerKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.into_affine().eq(&other.0.into_affine())
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
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Zeroize)]
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
    pub fn generate<R: Rng>(prng: &mut R) -> KeyPair {
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
}

impl SignKey {
    fn generate<R: Rng>(prng: &mut R) -> SignKey {
        SignKey(ScalarField::rand(prng))
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
    ) -> Result<(), PrimitivesError> {
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
        constants::CS_ID_BLS_BN254,
        signatures::{
            bls_over_bn254::{
                BLSOverBN254CurveSignatureScheme, KeyPair, SignKey, Signature, VerKey,
            },
            tests::{agg_sign_and_verify, failed_verification, sign_and_verify},
        },
    };
    use ark_ff::vec;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::vec::Vec;

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

        let mut ser_bytes: Vec<u8> = Vec::new();
        keypair.serialize_compressed(&mut ser_bytes).unwrap();
        let de: KeyPair = KeyPair::deserialize_compressed(&ser_bytes[..]).unwrap();
        assert_eq!(de.ver_key_ref(), keypair.ver_key_ref());
        assert_eq!(de.ver_key_ref(), &VerKey::from(&de.sk));

        let mut ser_bytes: Vec<u8> = Vec::new();
        sk.serialize_compressed(&mut ser_bytes).unwrap();
        let de: SignKey = SignKey::deserialize_compressed(&ser_bytes[..]).unwrap();
        assert_eq!(VerKey::from(&de), VerKey::from(&sk));

        let mut ser_bytes: Vec<u8> = Vec::new();
        vk.serialize_compressed(&mut ser_bytes).unwrap();
        let de: VerKey = VerKey::deserialize_compressed(&ser_bytes[..]).unwrap();
        assert_eq!(de, vk);

        let mut ser_bytes: Vec<u8> = Vec::new();
        sig.serialize_compressed(&mut ser_bytes).unwrap();
        let de: Signature = Signature::deserialize_compressed(&ser_bytes[..]).unwrap();
        assert_eq!(de, sig);
    }
}
