// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements the BLS signature over BN curves.

use super::SignatureScheme;
use ark_bn254::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    Bn254, Fq as BaseField, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};

use crate::{
    constants::CS_ID_BLS_MIN_SIG, // TODO update this as we are using the BN128 curve
    errors::PrimitivesError,
};

use ark_ec::{
    hashing::{
        curve_maps::swu::{SWUConfig, SWUMap},
        map_to_curve_hasher::MapToCurve,
        HashToCurveError,
    },
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig, CurveGroup, Group,
};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    Field, MontFp,
};
use ark_serialize::*;
use ark_std::{
    hash::{Hash, Hasher},
    rand::{CryptoRng, Rng, RngCore},
    string::ToString,
    vec::Vec,
    UniformRand,
};

use espresso_systems_common::jellyfish::tag;
use num_traits::Zero;
use sha2::Sha256;
// use jf_utils::{fq_to_fr, fq_to_fr_with_mask, fr_to_fq};
use crate::errors::PrimitivesError::VerificationError;
use tagged_base64::tagged;
use zeroize::Zeroize;

/// BLS signature scheme.
pub struct BLSOverBNCurveSignatureScheme {
    // curve_param: PhantomData<P>, // TODO what is this?
}

impl SignatureScheme for BLSOverBNCurveSignatureScheme {
    const CS_ID: &'static str = CS_ID_BLS_MIN_SIG; // TODO change this

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
        _sk: &Self::SigningKey,
        _msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError> {
        // TODO
        Ok(Signature {
            sigma: G1Projective::generator(),
        })
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
#[tagged(tag::BLS_SIGNING_KEY)]
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

impl SignKey {
    // returns the randomized key
    // fn randomize_with(&self, randomizer: &F) -> Self {
    //     Self(self.0 + randomizer)
    // }
}

// =====================================================
// Verification key
// =====================================================

/// Signature public verification key
// derive zeroize here so that keypair can be zeroized
#[tagged(tag::BLS_VER_KEY)] // TODO how does this work???
#[derive(CanonicalSerialize, CanonicalDeserialize, Eq, Clone, Debug)]
pub struct VerKey(pub(crate) G2Projective);

impl VerKey {
    // TODO is this needed?
    // Return a randomized verification key.
    // pub fn randomize_with<F>(&self, randomizer: &F) -> Self
    // where
    //     F: PrimeField,
    //     P: Config<Fp = F>,
    // {
    //
    //     Self(G1Projective::<P>::generator() * randomizer + self.0)
    // }
}

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

// impl<P> Default for VerKey<P>
// where
//     P: Pairing,
// {
//     fn default() -> Self {
//         P::G2::generator()
//     }
// }

// impl<P> From<P::G2> for VerKey<P>
// where
//     P: Pairing,
// {
//     fn from(point: P::G2) -> Self {
//         VerKey(point)
//     }
// }

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
// make sure sk can be zeroized
#[tagged(tag::SCHNORR_KEY_PAIR)] // TODO what is this tag for?
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct KeyPair {
    // phantom: PhantomData,
    sk: SignKey,
    vk: VerKey,
}

// impl<P> Default for KeyPair<P>
// where
//     P: Pairing,
// {
//     fn default() -> Self {
//         KeyPair {
//             sk: SignKey::<P>::default(),
//             vk: VerKey::<P>::default(),
//         }
//     }
// }

// =====================================================
// Signature
// =====================================================

/// The signature of BLS signature scheme
#[tagged(tag::SCHNORR_SIG)] // TODO what is this tag for?
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

// TODO insecure!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//
fn hash_to_curve(msg: &[u8]) -> G1Projective {
    let hasher_init = &[1u8];
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<ScalarField>>::new(hasher_init);
    let field_elems: Vec<ScalarField> = hasher.hash_to_field(msg, 1);
    G1Projective::generator() * field_elems[0]
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
    #[allow(non_snake_case)]
    pub fn sign<B: AsRef<[u8]>>(&self, msg: &[u8], _csid: B) -> Signature {
        // TODO take into account csid

        let hash_value: G1Projective = hash_to_curve(msg);
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
    #[allow(non_snake_case)]
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        msg: &[u8],
        sig: &Signature,
        _csid: B,
    ) -> Result<(), PrimitivesError> {
        // TODO Check public key
        // TODO take into account csid

        let group_elem = hash_to_curve(msg);
        let g2 = G2Projective::generator();
        let is_sig_valid = Bn254::pairing(sig.sigma, g2) == Bn254::pairing(group_elem, self.0);
        if is_sig_valid {
            Ok(())
        } else {
            Err(VerificationError("Pairing check failed".to_string()))
        }
    }
}
#[allow(warnings)]
fn hash_to_curve_bn254(_msg: &[u8]) -> Result<G1Affine, HashToCurveError> {
    // TODO how to avoid copy pasting this info from ark-bn254-0.4.0/src/g1.rs ?
    // Only implement the missing trait SWUConfig?
    struct Bn254CurveConfig;

    impl CurveConfig for Bn254CurveConfig {
        type BaseField = BaseField;
        type ScalarField = ScalarField;

        /// COFACTOR = 1
        const COFACTOR: &'static [u64] = &[0x1];

        /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
        const COFACTOR_INV: ScalarField = ScalarField::ONE;
    }

    impl SWCurveConfig for Bn254CurveConfig {
        /// COEFF_A = 0
        const COEFF_A: BaseField = BaseField::ZERO;

        /// COEFF_B = 3
        const COEFF_B: BaseField = MontFp!("3");

        /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
        const GENERATOR: Affine<Self> = Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);

        #[inline(always)]
        fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
            Self::BaseField::zero()
        }
    }

    impl SWUConfig for Bn254CurveConfig {
        // TODO not clear about this... Copy pasting the documentation of the SWUConfig
        // trait here
        /// An element of the base field that is not a square root see \[WB2019,
        /// Section 4\]. It is also convenient to have $g(b/ZETA * a)$
        /// to be square. In general we use a `ZETA` with low absolute
        /// value coefficients when they are represented as integers.

        const ZETA: BaseField = MontFp!("-1");
    }

    // TODO hash msg to field element
    let test_map_to_curve = SWUMap::<Bn254CurveConfig>::new().unwrap();
    let p = test_map_to_curve.map_to_curve(BaseField::from(1)).unwrap();
    Ok(G1Affine::new(p.x, p.y))
}

#[cfg(test)]
mod tests {
    use crate::{constants::CS_ID_BLS_MIN_SIG, signatures::bls_arkwors::KeyPair};
    use ark_ff::vec; // TODO new constant

    #[test]
    fn test_bls_signature() {
        // TODO use SignatureScheme instead

        let mut rng = jf_utils::test_rng();
        let key_pair = KeyPair::generate(&mut rng);
        let msg = vec![15u8, 44u8];
        let sig = key_pair.sign(&msg, CS_ID_BLS_MIN_SIG);

        let ver_key = key_pair.vk;

        assert!(ver_key.verify(&msg, &sig, CS_ID_BLS_MIN_SIG).is_ok());

        let wrong_message = vec![0u8, 0u8];
        assert!(ver_key
            .verify(&wrong_message, &sig, CS_ID_BLS_MIN_SIG)
            .is_err());
    }

    // TODO check tests of Schnorr signature
}
