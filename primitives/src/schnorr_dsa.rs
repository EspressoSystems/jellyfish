// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements the Schnorr signature over the various Edwards
//! curves.

use crate::{constants::*, errors::PrimitivesError};
use ark_ec::{
    group::Group,
    twisted_edwards_extended::{GroupAffine, GroupProjective},
    AffineCurve, ModelParameters, ProjectiveCurve, TEModelParameters as Parameters,
};
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::{
    hash::{Hash, Hasher},
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
};
use jf_rescue::{Permutation, RescueParameter};
use jf_utils::{fq_to_fr, fq_to_fr_with_mask, fr_to_fq, tagged_blob};
use zeroize::Zeroize;

pub(crate) const DOMAIN_SEPARATION: &[u8; 24] = b"DSA_WITH_RESCUE_HASH_v01";

// =====================================================
// Signing key
// =====================================================
#[derive(
    Clone, Hash, Default, Zeroize, PartialEq, CanonicalSerialize, CanonicalDeserialize, Debug,
)]
struct SignKey<F: PrimeField>(pub(crate) F);

impl<F: PrimeField> Drop for SignKey<F> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<F: PrimeField> SignKey<F> {
    // returns the randomized key
    fn randomize_with(&self, randomizer: &F) -> Self {
        Self(self.0 + randomizer)
    }
}

// =====================================================
// Verification key
// =====================================================

/// Signature public verification key
// derive zeroize here so that keypair can be zeroized
#[tagged_blob("VERKEY")]
#[derive(Clone, Default, CanonicalSerialize, CanonicalDeserialize, Eq, Derivative)]
#[derivative(Debug(bound = "P: Parameters"))]
pub struct VerKey<P>(pub(crate) GroupProjective<P>)
where
    P: Parameters + Clone;

impl<P: Parameters + Clone> VerKey<P> {
    /// Return a randomized verification key.
    pub fn randomize_with<F>(&self, randomizer: &F) -> Self
    where
        F: PrimeField,
        P: Parameters<ScalarField = F>,
    {
        // VK = g^k, VK' = g^(k+r) = g^k * g^r
        Self(
            Group::mul(
                &GroupProjective::<P>::prime_subgroup_generator(),
                randomizer,
            ) + self.0,
        )
    }
}

impl<P> Hash for VerKey<P>
where
    P: Parameters + Clone,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.0.into_affine(), state)
    }
}

impl<P> PartialEq for VerKey<P>
where
    P: Parameters + Clone,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.into_affine().eq(&other.0.into_affine())
    }
}

impl<P> From<GroupAffine<P>> for VerKey<P>
where
    P: Parameters + Clone,
{
    fn from(point: GroupAffine<P>) -> Self {
        VerKey(point.into_projective())
    }
}

impl<P: Parameters + Clone> VerKey<P> {
    /// Convert the verification key into the affine form.
    pub fn to_affine(&self) -> GroupAffine<P> {
        self.0.into_affine()
    }
}

// =====================================================
// Key pair
// =====================================================

/// Signature secret key pair used to sign messages
// make sure sk can be zeroized
#[tagged_blob("SIGNKEYPAIR")]
#[derive(Clone, Default, CanonicalSerialize, CanonicalDeserialize, PartialEq, Derivative)]
#[derivative(Debug(bound = "P: Parameters"))]
pub struct KeyPair<P>
where
    P: Parameters + Clone,
{
    sk: SignKey<P::ScalarField>,
    vk: VerKey<P>,
}

// =====================================================
// Signature
// =====================================================

/// The signature of Schnorr signature scheme
#[tagged_blob("SIG")]
#[derive(Clone, Eq, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(Debug(bound = "P: Parameters"))]
#[allow(non_snake_case)]
pub struct Signature<P>
where
    P: Parameters + Clone,
{
    pub(crate) s: P::ScalarField,
    pub(crate) R: GroupProjective<P>,
}

impl<P> Hash for Signature<P>
where
    P: Parameters + Clone,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.s, state);
        Hash::hash(&self.R.into_affine(), state);
    }
}

impl<P> PartialEq for Signature<P>
where
    P: Parameters + Clone,
{
    fn eq(&self, other: &Self) -> bool {
        self.s == other.s && self.R.into_affine() == other.R.into_affine()
    }
}
// =====================================================
// end of definitions
// =====================================================

impl<F, P> KeyPair<P>
where
    F: RescueParameter,
    P: Parameters<BaseField = F> + Clone,
{
    /// Key-pair generation algorithm
    pub fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> KeyPair<P> {
        let sk = SignKey::generate(prng);
        let vk = VerKey::from(&sk);
        KeyPair { sk, vk }
    }

    /// Key pair generation using a particular sign key secret `sk`
    pub fn generate_with_sign_key(sk: P::ScalarField) -> Self {
        let sk = SignKey(sk);
        let vk = VerKey::from(&sk);
        KeyPair { sk, vk }
    }

    /// Get reference to verification key
    pub fn ver_key_ref(&self) -> &VerKey<P> {
        &self.vk
    }

    /// Get the verification key
    pub fn ver_key(&self) -> VerKey<P> {
        self.vk.clone()
    }

    /// Get the internal of the signing key, namely a P::ScalarField element
    pub fn sign_key_internal(&self) -> &P::ScalarField {
        &self.sk.0
    }

    /// Signature function
    #[allow(non_snake_case)]
    pub fn sign(&self, msg: &[F]) -> Signature<P> {
        let hash = Permutation::default();
        let instance_description = F::from_be_bytes_mod_order(DOMAIN_SEPARATION);
        let mut msg_input = vec![instance_description, fr_to_fq::<F, P>(&self.sk.0)];
        msg_input.extend(msg.iter());

        let r = fq_to_fr::<F, P>(&hash.sponge_with_padding(&msg_input, 1)[0]);
        let R = Group::mul(&GroupProjective::<P>::prime_subgroup_generator(), &r);
        let c = self.challenge(&hash, &R, msg);

        let s = c * self.sk.0 + r;

        Signature { s, R }
    }

    /// Randomize the key pair with the `randomizer`, return the randomized key
    /// pair.
    pub fn randomize_with(&self, randomizer: &<P as ModelParameters>::ScalarField) -> Self {
        let randomized_sk = self.sk.randomize_with(randomizer);
        let randomized_vk = self.vk.randomize_with(randomizer);
        Self {
            sk: randomized_sk,
            vk: randomized_vk,
        }
    }
}

impl<F, P> KeyPair<P>
where
    F: RescueParameter,
    P: Parameters<BaseField = F> + Clone,
{
    #[allow(non_snake_case)]
    fn challenge(
        &self,
        hash: &Permutation<F>,
        R: &GroupProjective<P>,
        msg: &[F],
    ) -> P::ScalarField {
        self.vk.challenge(hash, R, msg)
    }
}

impl<F: PrimeField> SignKey<F> {
    fn generate<R: CryptoRng + RngCore>(prng: &mut R) -> SignKey<F> {
        SignKey(F::rand(prng))
    }
}

impl<P, F> From<&SignKey<F>> for VerKey<P>
where
    P: Parameters<ScalarField = F> + Clone,
    F: PrimeField,
{
    fn from(sk: &SignKey<F>) -> Self {
        VerKey(Group::mul(
            &GroupProjective::<P>::prime_subgroup_generator(),
            &sk.0,
        ))
    }
}

impl<F, P> VerKey<P>
where
    F: RescueParameter,
    P: Parameters<BaseField = F> + Clone,
{
    /// Get the internal of verifying key, namely a curve Point
    pub fn internal(&self) -> &GroupProjective<P> {
        &self.0
    }

    /// Signature verification function
    #[allow(non_snake_case)]
    pub fn verify(&self, msg: &[P::BaseField], sig: &Signature<P>) -> Result<(), PrimitivesError> {
        // Reject if public key is of small order
        if Group::mul(&self.0, &P::ScalarField::from(curve_cofactor::<P>()))
            == GroupProjective::<P>::default()
        {
            return Err(PrimitivesError::VerificationError(
                "public key is not valid: not in the correct subgroup".to_string(),
            ));
        }

        // restrictive cofactorless verification
        let hash = Permutation::<F>::default();
        let c = self.challenge(&hash, &sig.R, msg);

        let base = GroupProjective::<P>::prime_subgroup_generator();
        let x = Group::mul(&base, &sig.s);
        let y = sig.R + Group::mul(&self.0, &c);

        if y == x {
            Ok(())
        } else {
            Err(PrimitivesError::VerificationError(
                "Signature verification error".to_string(),
            ))
        }
    }
}

impl<F, P> VerKey<P>
where
    F: RescueParameter,
    P: Parameters<BaseField = F> + Clone,
{
    #[allow(non_snake_case)]
    fn challenge(
        &self,
        hash: &Permutation<F>,
        R: &GroupProjective<P>,
        msg: &[F],
    ) -> P::ScalarField {
        // is the domain separator always an Fr? If so how about using Fr as domain
        // separator rather than bytes?
        let instance_description = F::from_be_bytes_mod_order(DOMAIN_SEPARATION);
        let mut challenge_input = {
            let vk_affine = self.0.into_affine();
            let R_affine = R.into_affine();
            vec![
                instance_description,
                vk_affine.x,
                vk_affine.y,
                R_affine.x,
                R_affine.y,
            ]
        };
        challenge_input.extend(msg);
        let challenge_fq = hash.sponge_with_padding(&challenge_input, 1)[0];

        // this masking will drop the last byte, and the resulting
        // challenge will be 248 bits
        fq_to_fr_with_mask(&challenge_fq)
    }
}

#[cfg(test)]
mod tests {
    use ark_ed_on_bls12_377::{EdwardsParameters as Param377, Fq as FqEd377};
    use ark_ed_on_bls12_381::{EdwardsParameters as Param381, Fq as FqEd381};
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsParameters as Param381b, Fq as FqEd381b};
    use ark_ed_on_bn254::{EdwardsParameters as Param254, Fq as FqEd254};
    use ark_std::UniformRand;

    use super::*;

    macro_rules! test_signature {
        ($curve_param:tt, $base_field:tt) => {
            let mut rng = ark_std::test_rng();

            let keypair1 = KeyPair::generate(&mut rng);
            // test randomized key pair
            let randomizer2 = <$curve_param as ModelParameters>::ScalarField::rand(&mut rng);
            let keypair2 = keypair1.randomize_with(&randomizer2);
            let randomizer3 = <$curve_param as ModelParameters>::ScalarField::rand(&mut rng);
            let keypair3 = keypair2.randomize_with(&randomizer3);
            let keypairs = vec![keypair1, keypair2, keypair3];

            let pk_bad: VerKey<$curve_param> = KeyPair::generate(&mut rng).ver_key_ref().clone();

            let mut msg = vec![];
            for i in 0..20 {
                for keypair in &keypairs {
                    assert_eq!(keypair.vk, VerKey::from(&keypair.sk));

                    let sig = keypair.sign(&msg);
                    let pk = keypair.ver_key_ref();
                    assert!(pk.verify(&msg, &sig).is_ok());
                    // wrong public key
                    assert!(pk_bad.verify(&msg, &sig).is_err());
                    // wrong message
                    msg.push($base_field::from(i as u64));
                    assert!(pk.verify(&msg, &sig).is_err());
                }
            }
        };
    }

    #[test]
    fn test_signature() {
        test_signature!(Param254, FqEd254);
        test_signature!(Param377, FqEd377);
        test_signature!(Param381, FqEd381);
        test_signature!(Param381b, FqEd381b);
    }

    mod serde {
        use super::super::{KeyPair, SignKey, Signature, VerKey};
        use ark_ec::twisted_edwards_extended::GroupProjective;
        use ark_ed_on_bls12_377::{EdwardsParameters as Param377, Fq as FqEd377, Fr as FrEd377};
        use ark_ed_on_bls12_381::{EdwardsParameters as Param381, Fq as FqEd381, Fr as FrEd381};
        use ark_ed_on_bls12_381_bandersnatch::{
            EdwardsParameters as Param381b, Fq as FqEd381b, Fr as FrEd381b,
        };
        use ark_ed_on_bn254::{EdwardsParameters as Param254, Fq as FqEd254, Fr as FrEd254};
        use ark_ff::Zero;
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
        use ark_std::{vec, vec::Vec, UniformRand};

        macro_rules! test_ver_key {
            ($curve_param:tt, $scalar_field:tt) => {
                let mut rng = ark_std::test_rng();

                // happy path
                let keypair: KeyPair<$curve_param> = KeyPair::generate(&mut rng);
                let vk = keypair.ver_key_ref();
                let sig = keypair.sign(&[]);
                assert!(&vk.verify(&[], &sig).is_ok());

                // Bad path
                let bad_ver_key = VerKey(GroupProjective::<$curve_param>::zero());
                let bad_keypair = KeyPair {
                    sk: SignKey($scalar_field::zero()),
                    vk: bad_ver_key.clone(),
                };

                let sig_on_bad_key = bad_keypair.sign(&[]);
                assert!(&bad_ver_key.verify(&[], &sig_on_bad_key).is_err());

                // test serialization
                let mut vk_bytes = vec![];
                vk.serialize(&mut vk_bytes).unwrap();
                let vk_de: VerKey<$curve_param> = VerKey::deserialize(vk_bytes.as_slice()).unwrap();
                assert_eq!(*vk, vk_de, "normal ser/de should pass");
            };
        }
        #[test]
        fn test_ver_key() {
            test_ver_key!(Param254, FrEd254);
            test_ver_key!(Param377, FrEd377);
            test_ver_key!(Param381, FrEd381);
            test_ver_key!(Param381b, FrEd381b);
        }

        macro_rules! test_signature {
            ($curve_param:tt, $base_field:tt) => {
                let mut rng = ark_std::test_rng();
                let keypair: KeyPair<$curve_param> = KeyPair::generate(&mut rng);

                // Happy path
                let msg = vec![$base_field::from(8u8), $base_field::from(10u8)];
                let sig = keypair.sign(&msg);
                assert!(keypair.vk.verify(&msg, &sig).is_ok());
                assert!(keypair.vk.verify(&[], &sig).is_err());
                let mut bytes_sig = vec![];
                sig.serialize(&mut bytes_sig).unwrap();
                let sig_de: Signature<$curve_param> =
                    Signature::deserialize(bytes_sig.as_slice()).unwrap();
                assert_eq!(sig, sig_de);

                // Bad path 1: when s bytes overflow
                let mut bad_bytes_sig = bytes_sig.clone();
                let mut q_minus_one_bytes = vec![];
                (-$base_field::from(1u32))
                    .serialize(&mut q_minus_one_bytes)
                    .unwrap();
                bad_bytes_sig.splice(.., q_minus_one_bytes.iter().cloned());
                assert!(Signature::<$curve_param>::deserialize(bad_bytes_sig.as_slice()).is_err());
            };
        }

        #[test]
        fn test_signature() {
            test_signature!(Param254, FqEd254);
            test_signature!(Param377, FqEd377);
            test_signature!(Param381, FqEd381);
            test_signature!(Param381b, FqEd381b);
        }

        macro_rules! test_serde {
            ($curve_param:tt, $scalar_field:tt, $base_field:tt) => {
                let mut rng = ark_std::test_rng();
                let keypair = KeyPair::generate(&mut rng);
                let sk = SignKey::<$scalar_field>::generate(&mut rng);
                let vk = keypair.ver_key();
                let msg = vec![$base_field::rand(&mut rng)];
                let sig = keypair.sign(&msg);

                let mut ser_bytes: Vec<u8> = Vec::new();
                keypair.serialize(&mut ser_bytes).unwrap();
                let de: KeyPair<$curve_param> = KeyPair::deserialize(&ser_bytes[..]).unwrap();
                assert_eq!(de.ver_key_ref(), keypair.ver_key_ref());
                assert_eq!(de.ver_key_ref(), &VerKey::from(&de.sk));

                let mut ser_bytes: Vec<u8> = Vec::new();
                sk.serialize(&mut ser_bytes).unwrap();
                let de: SignKey<$scalar_field> = SignKey::deserialize(&ser_bytes[..]).unwrap();
                assert_eq!(VerKey::<$curve_param>::from(&de), VerKey::from(&sk));

                let mut ser_bytes: Vec<u8> = Vec::new();
                vk.serialize(&mut ser_bytes).unwrap();
                let de: VerKey<$curve_param> = VerKey::deserialize(&ser_bytes[..]).unwrap();
                assert_eq!(de, vk);

                let mut ser_bytes: Vec<u8> = Vec::new();
                sig.serialize(&mut ser_bytes).unwrap();
                let de: Signature<$curve_param> = Signature::deserialize(&ser_bytes[..]).unwrap();
                assert_eq!(de, sig);
            };
        }

        #[test]
        fn test_serde() {
            test_serde!(Param254, FrEd254, FqEd254);
            test_serde!(Param377, FrEd377, FqEd377);
            test_serde!(Param381, FrEd381, FqEd381);
            test_serde!(Param381b, FrEd381b, FqEd381b);
        }
    }
}
