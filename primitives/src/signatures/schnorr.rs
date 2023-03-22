// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements the Schnorr signature over the various Edwards
//! curves.

use super::SignatureScheme;
use crate::{
    constants::CS_ID_SCHNORR,
    crhf::{VariableLengthRescueCRHF, CRHF},
    errors::PrimitivesError,
    rescue::RescueParameter,
    utils::curve_cofactor,
};
use ark_ec::{
    twisted_edwards::{Affine, Projective, TECurveConfig as Config},
    AffineRepr, CurveConfig, CurveGroup, Group,
};
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::{
    hash::{Hash, Hasher},
    marker::PhantomData,
    rand::{CryptoRng, Rng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use espresso_systems_common::jellyfish::tag;
use jf_utils::{fq_to_fr, fq_to_fr_with_mask, fr_to_fq};
use tagged_base64::tagged;
use zeroize::Zeroize;

/// Schnorr signature scheme.
pub struct SchnorrSignatureScheme<P> {
    curve_param: PhantomData<P>,
}

impl<F, P> SignatureScheme for SchnorrSignatureScheme<P>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    const CS_ID: &'static str = CS_ID_SCHNORR;

    /// Signing key.
    type SigningKey = SignKey<P::ScalarField>;

    /// Verification key
    type VerificationKey = VerKey<P>;

    /// Public Parameter
    type PublicParameter = ();

    /// Signature
    type Signature = Signature<P>;

    /// A message is &\[MessageUnit\]
    type MessageUnit = F;

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
        let kp = KeyPair::<P>::generate(prng);
        Ok((kp.sk, kp.vk))
    }

    /// Sign a message with the signing key
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError> {
        let kp = KeyPair::<P>::generate_with_sign_key(sk.0);
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
#[tagged(tag::SCHNORR_SIGNING_KEY)]
#[derive(
    Clone, Hash, Default, Zeroize, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Debug,
)]
/// Signing key for Schnorr signature.
pub struct SignKey<F: PrimeField>(pub(crate) F);

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
#[tagged(tag::SCHNORR_VER_KEY)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Default(bound = "P: Config"),
    Eq(bound = "P: Config"),
    Clone(bound = "P: Config")
)]
pub struct VerKey<P>(pub(crate) Projective<P>)
where
    P: Config;

impl<P: Config> VerKey<P> {
    /// Return a randomized verification key.
    pub fn randomize_with<F>(&self, randomizer: &F) -> Self
    where
        F: PrimeField,
        P: Config<ScalarField = F>,
    {
        // VK = g^k, VK' = g^(k+r) = g^k * g^r
        Self(Projective::<P>::generator() * randomizer + self.0)
    }
}

impl<P> Hash for VerKey<P>
where
    P: Config,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.0.into_affine(), state)
    }
}

impl<P> PartialEq for VerKey<P>
where
    P: Config,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.into_affine().eq(&other.0.into_affine())
    }
}

impl<P> From<Affine<P>> for VerKey<P>
where
    P: Config,
{
    fn from(point: Affine<P>) -> Self {
        VerKey(point.into_group())
    }
}

impl<P: Config> VerKey<P> {
    /// Convert the verification key into the affine form.
    pub fn to_affine(&self) -> Affine<P> {
        self.0.into_affine()
    }
}

// =====================================================
// Key pair
// =====================================================

/// Signature secret key pair used to sign messages
// make sure sk can be zeroized
#[tagged(tag::SCHNORR_KEY_PAIR)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Default(bound = "P: Config"),
    Clone(bound = "P: Config"),
    PartialEq(bound = "P: Config")
)]
pub struct KeyPair<P>
where
    P: Config,
{
    sk: SignKey<P::ScalarField>,
    vk: VerKey<P>,
}

// =====================================================
// Signature
// =====================================================

/// The signature of Schnorr signature scheme
#[tagged(tag::SCHNORR_SIG)]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(
    Debug(bound = "P: Config"),
    Default(bound = "P: Config"),
    Eq(bound = "P: Config"),
    Clone(bound = "P: Config")
)]
#[allow(non_snake_case)]
pub struct Signature<P>
where
    P: Config,
{
    pub(crate) s: P::ScalarField,
    pub(crate) R: Projective<P>,
}

impl<P> Hash for Signature<P>
where
    P: Config,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash(&self.s, state);
        Hash::hash(&self.R.into_affine(), state);
    }
}

impl<P> PartialEq for Signature<P>
where
    P: Config,
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
    P: Config<BaseField = F>,
{
    /// Key-pair generation algorithm
    pub fn generate<R: Rng>(prng: &mut R) -> KeyPair<P> {
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
    pub fn sign<B: AsRef<[u8]>>(&self, msg: &[F], csid: B) -> Signature<P> {
        // Do we want to remove the instance description?
        let instance_description = F::from_be_bytes_mod_order(csid.as_ref());
        let mut msg_input = vec![instance_description, fr_to_fq::<F, P>(&self.sk.0)];
        msg_input.extend(msg.iter());

        let r =
            fq_to_fr::<F, P>(&VariableLengthRescueCRHF::<F, 1>::evaluate(&msg_input).unwrap()[0]); // safe unwrap
        let R = Projective::<P>::generator() * r;
        let c = self.vk.challenge(&R, msg, csid);
        let s = c * self.sk.0 + r;

        Signature { s, R }
    }

    /// Randomize the key pair with the `randomizer`, return the randomized key
    /// pair.
    pub fn randomize_with(&self, randomizer: &<P as CurveConfig>::ScalarField) -> Self {
        let randomized_sk = self.sk.randomize_with(randomizer);
        let randomized_vk = self.vk.randomize_with(randomizer);
        Self {
            sk: randomized_sk,
            vk: randomized_vk,
        }
    }
}

impl<F: PrimeField> SignKey<F> {
    fn generate<R: Rng>(prng: &mut R) -> SignKey<F> {
        SignKey(F::rand(prng))
    }
}

impl<P, F> From<&SignKey<F>> for VerKey<P>
where
    P: Config<ScalarField = F>,
    F: PrimeField,
{
    fn from(sk: &SignKey<F>) -> Self {
        VerKey(Projective::<P>::generator() * sk.0)
    }
}

impl<F, P> VerKey<P>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    /// Get the internal of verifying key, namely a curve Point
    pub fn internal(&self) -> &Projective<P> {
        &self.0
    }

    /// Signature verification function
    #[allow(non_snake_case)]
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        msg: &[P::BaseField],
        sig: &Signature<P>,
        csid: B,
    ) -> Result<(), PrimitivesError> {
        // Reject if public key is of small order
        if (self.0 * P::ScalarField::from(curve_cofactor::<P>())) == Projective::<P>::default() {
            return Err(PrimitivesError::VerificationError(
                "public key is not valid: not in the correct subgroup".to_string(),
            ));
        }

        // restrictive cofactorless verification
        let c = self.challenge(&sig.R, msg, csid);

        let base = Projective::<P>::generator();
        let x = base * sig.s;
        let y = sig.R + self.0 * c;

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
    P: Config<BaseField = F>,
{
    // TODO: this function should be generic w.r.t. hash functions
    // Fixme after the hash-api PR is merged.
    #[allow(non_snake_case)]
    fn challenge<B: AsRef<[u8]>>(&self, R: &Projective<P>, msg: &[F], csid: B) -> P::ScalarField {
        // is the domain separator always an Fr? If so how about using Fr as domain
        // separator rather than bytes?
        let instance_description = F::from_be_bytes_mod_order(csid.as_ref());
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
        let challenge_fq = VariableLengthRescueCRHF::<F, 1>::evaluate(challenge_input).unwrap()[0]; // safe unwrap

        // this masking will drop the last byte, and the resulting
        // challenge will be 248 bits
        fq_to_fr_with_mask(&challenge_fq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::CS_ID_SCHNORR,
        signatures::tests::{failed_verification, sign_and_verify},
    };
    use ark_ed_on_bls12_377::EdwardsConfig as Param377;
    use ark_ed_on_bls12_381::EdwardsConfig as Param381;
    use ark_ed_on_bls12_381_bandersnatch::EdwardsConfig as Param381b;
    use ark_ed_on_bn254::EdwardsConfig as Param254;
    use ark_std::UniformRand;

    macro_rules! test_signature {
        ($curve_param:tt) => {
            let mut rng = jf_utils::test_rng();

            let keypair1 = KeyPair::generate(&mut rng);
            // test randomized key pair
            let randomizer2 = <$curve_param as CurveConfig>::ScalarField::rand(&mut rng);
            let keypair2 = keypair1.randomize_with(&randomizer2);
            let randomizer3 = <$curve_param as CurveConfig>::ScalarField::rand(&mut rng);
            let keypair3 = keypair2.randomize_with(&randomizer3);
            let keypairs = vec![keypair1, keypair2, keypair3];

            let pk_bad: VerKey<$curve_param> = KeyPair::generate(&mut rng).ver_key_ref().clone();

            let mut msg = vec![];
            for i in 0..20 {
                for keypair in &keypairs {
                    assert_eq!(keypair.vk, VerKey::from(&keypair.sk));

                    let sig = keypair.sign(&msg, CS_ID_SCHNORR);
                    let pk = keypair.ver_key_ref();
                    assert!(pk.verify(&msg, &sig, CS_ID_SCHNORR).is_ok());
                    // wrong public key
                    assert!(pk_bad.verify(&msg, &sig, CS_ID_SCHNORR).is_err());
                    // wrong message
                    msg.push(<$curve_param as CurveConfig>::BaseField::from(i as u64));
                    assert!(pk.verify(&msg, &sig, CS_ID_SCHNORR).is_err());
                }
            }

            let message = <$curve_param as CurveConfig>::BaseField::rand(&mut rng);
            sign_and_verify::<SchnorrSignatureScheme<$curve_param>>(&[message]);
            failed_verification::<SchnorrSignatureScheme<$curve_param>>(
                &[message],
                &[<$curve_param as CurveConfig>::BaseField::rand(&mut rng)],
            );
        };
    }

    #[test]
    fn test_signature() {
        test_signature!(Param254);
        test_signature!(Param377);
        test_signature!(Param381);
        test_signature!(Param381b);
    }

    mod serde {
        use super::super::{KeyPair, SignKey, Signature, VerKey};
        use crate::constants::CS_ID_SCHNORR;
        use ark_ec::twisted_edwards::Projective;
        use ark_ed_on_bls12_377::{EdwardsConfig as Param377, Fq as FqEd377, Fr as FrEd377};
        use ark_ed_on_bls12_381::{EdwardsConfig as Param381, Fq as FqEd381, Fr as FrEd381};
        use ark_ed_on_bls12_381_bandersnatch::{
            EdwardsConfig as Param381b, Fq as FqEd381b, Fr as FrEd381b,
        };
        use ark_ed_on_bn254::{EdwardsConfig as Param254, Fq as FqEd254, Fr as FrEd254};
        use ark_ff::Zero;
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
        use ark_std::{vec, vec::Vec, UniformRand};

        macro_rules! test_ver_key {
            ($curve_param:tt, $scalar_field:tt) => {
                let mut rng = jf_utils::test_rng();

                // happy path
                let keypair: KeyPair<$curve_param> = KeyPair::generate(&mut rng);
                let vk = keypair.ver_key_ref();
                let sig = keypair.sign(&[], CS_ID_SCHNORR);
                assert!(&vk.verify(&[], &sig, CS_ID_SCHNORR).is_ok());

                // Bad path
                let bad_ver_key = VerKey(Projective::<$curve_param>::zero());
                let bad_keypair = KeyPair {
                    sk: SignKey($scalar_field::zero()),
                    vk: bad_ver_key.clone(),
                };

                let sig_on_bad_key = bad_keypair.sign(&[], CS_ID_SCHNORR);
                assert!(&bad_ver_key
                    .verify(&[], &sig_on_bad_key, CS_ID_SCHNORR)
                    .is_err());

                // test serialization
                let mut vk_bytes = vec![];
                vk.serialize_compressed(&mut vk_bytes).unwrap();
                let vk_de: VerKey<$curve_param> =
                    VerKey::deserialize_compressed(vk_bytes.as_slice()).unwrap();
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
                let mut rng = jf_utils::test_rng();
                let keypair: KeyPair<$curve_param> = KeyPair::generate(&mut rng);

                // Happy path
                let msg = vec![$base_field::from(8u8), $base_field::from(10u8)];
                let sig = keypair.sign(&msg, CS_ID_SCHNORR);
                assert!(keypair.vk.verify(&msg, &sig, CS_ID_SCHNORR).is_ok());
                assert!(keypair.vk.verify(&[], &sig, CS_ID_SCHNORR).is_err());
                let mut bytes_sig = vec![];
                sig.serialize_compressed(&mut bytes_sig).unwrap();
                let sig_de: Signature<$curve_param> =
                    Signature::deserialize_compressed(bytes_sig.as_slice()).unwrap();
                assert_eq!(sig, sig_de);

                // Bad path 1: when s bytes overflow
                let mut bad_bytes_sig = bytes_sig.clone();
                let mut q_minus_one_bytes = vec![];
                (-$base_field::from(1u32))
                    .serialize_compressed(&mut q_minus_one_bytes)
                    .unwrap();
                bad_bytes_sig.splice(.., q_minus_one_bytes.iter().cloned());
                assert!(Signature::<$curve_param>::deserialize_compressed(
                    bad_bytes_sig.as_slice()
                )
                .is_err());
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
                let mut rng = jf_utils::test_rng();
                let keypair = KeyPair::generate(&mut rng);
                let sk = SignKey::<$scalar_field>::generate(&mut rng);
                let vk = keypair.ver_key();
                let msg = vec![$base_field::rand(&mut rng)];
                let sig = keypair.sign(&msg, CS_ID_SCHNORR);

                let mut ser_bytes: Vec<u8> = Vec::new();
                keypair.serialize_compressed(&mut ser_bytes).unwrap();
                let de: KeyPair<$curve_param> =
                    KeyPair::deserialize_compressed(&ser_bytes[..]).unwrap();
                assert_eq!(de.ver_key_ref(), keypair.ver_key_ref());
                assert_eq!(de.ver_key_ref(), &VerKey::from(&de.sk));

                let mut ser_bytes: Vec<u8> = Vec::new();
                sk.serialize_compressed(&mut ser_bytes).unwrap();
                let de: SignKey<$scalar_field> =
                    SignKey::deserialize_compressed(&ser_bytes[..]).unwrap();
                assert_eq!(VerKey::<$curve_param>::from(&de), VerKey::from(&sk));

                let mut ser_bytes: Vec<u8> = Vec::new();
                vk.serialize_compressed(&mut ser_bytes).unwrap();
                let de: VerKey<$curve_param> =
                    VerKey::deserialize_compressed(&ser_bytes[..]).unwrap();
                assert_eq!(de, vk);

                let mut ser_bytes: Vec<u8> = Vec::new();
                sig.serialize_compressed(&mut ser_bytes).unwrap();
                let de: Signature<$curve_param> =
                    Signature::deserialize_compressed(&ser_bytes[..]).unwrap();
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
