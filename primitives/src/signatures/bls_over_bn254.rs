// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements the BLS signature over the BN254 curve.ç
// TODO more comments
use super::SignatureScheme;
use crate::{constants::CS_ID_BLS_BN254, errors::PrimitivesError};
use ark_bn254::{
    Bn254, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    Field,
};
use ark_serialize::*;
use ark_std::{
    hash::{Hash, Hasher},
    rand::{CryptoRng, Rng, RngCore},
    string::ToString,
    vec::Vec,
    UniformRand,
};
use digest::DynDigest;
use sha3::Keccak256;

use crate::errors::PrimitivesError::VerificationError;
use espresso_systems_common::jellyfish::tag;

use tagged_base64::tagged;
use zeroize::Zeroize;

/// BLS signature scheme.
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

    /// generate public parameters from RNG.
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
        Ok((kp.sk, kp.vk))
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

// =====================================================
// Signing key
// =====================================================
#[tagged(tag::BLS_SIGNING_KEY)] // TODO what iis this tagging thing?
#[derive(
    Clone, Hash, Default, Zeroize, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Debug,
)]
/// Signing key for BLS signature.
pub struct SignKey(pub(crate) ScalarField);

impl Drop for SignKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// =====================================================
// Verification key
// =====================================================

/// Signature public verification key
// Derive zeroize here so that keypair can be zeroized
#[tagged(tag::BLS_VER_KEY)] // TODO how does this work???
#[derive(CanonicalSerialize, CanonicalDeserialize, Eq, Clone, Debug)]
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
// Make sure sk can be zeroized // TODO
#[tagged(tag::BLS_VER_KEY)] // TODO what is this tag for?
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct KeyPair {
    sk: SignKey,
    vk: VerKey,
}

// =====================================================
// Signature
// =====================================================

/// The signature of BLS signature scheme
#[tagged(tag::BLS_SIG)] // TODO what is this tag for?
#[derive(CanonicalSerialize, CanonicalDeserialize, Eq, Clone, Debug)]
#[allow(non_snake_case)]
pub struct Signature {
    pub(crate) sigma: G1Projective,
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

/// Hash and pray algorithm
// TODO comment
// TODO make public?
fn hash_to_curve<H: Default + DynDigest + Clone>(msg: &[u8]) -> G1Projective {
    let hasher_init = &[1u8];
    let hasher = <DefaultFieldHasher<H> as HashToField<BaseField>>::new(hasher_init);
    let field_elems: Vec<BaseField> = hasher.hash_to_field(msg, 1);

    // Coefficients of the curve: y^2 = x^3 + ax + b
    // For BN254 we have a=0 and b=3

    let coeff_a = BaseField::from(0); // TODO cleaner, fetch from config?
    let coeff_b = BaseField::from(3); // TODO cleaner, fetch from config? TODO is this correct?

    let mut x_affine = field_elems[0];
    let mut y_square_affine: BaseField =
        x_affine * x_affine * x_affine + coeff_a * x_affine + coeff_b;

    // Loop until we find a quadratic residue
    while y_square_affine.legendre().is_qnr() {
        // println!("point with x={} is off the curve!!", x_affine);
        x_affine += BaseField::from(1);
        y_square_affine = x_affine * x_affine * x_affine + coeff_a * x_affine + coeff_b;
    }

    // Safe unwrap as y_square_affine is a quadratic residue
    let y_affine = y_square_affine.sqrt().unwrap();

    let g1_affine = G1Affine::new(x_affine, y_affine);
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
        self.vk.clone()
    }

    /// Get the internal of the signing key, namely a P::ScalarField element
    pub fn sign_key_internal(&self) -> &ScalarField {
        &self.sk.0
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
        // TODO Check public key

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
            tests::{failed_verification, sign_and_verify},
        },
    };
    use ark_ff::vec;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use jf_utils::Vec;

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