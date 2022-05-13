//! Placeholder for BLS signature.

use super::SignatureScheme;
use crate::{
    constants::CS_ID_BLS_SIG_NAIVE, errors::PrimitivesError, hash_to_group::SWHashToGroup,
};
use ark_ec::{
    bls12::{Bls12, Bls12Parameters},
    short_weierstrass_jacobian::GroupAffine,
    AffineCurve, ModelParameters, ProjectiveCurve,
};
use ark_ff::{Fp12, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Write};
use ark_std::{
    io::Read,
    ops::Neg,
    rand::{CryptoRng, RngCore},
    string::ToString,
    One, UniformRand,
};
use core::marker::PhantomData;
use jf_utils::{multi_pairing, tagged_blob};

/// BLS signature scheme.
/// Optimized for signature size, i.e.: PK in G2 and sig in G1
pub struct BLSSignatureScheme<P: Bls12Parameters> {
    pairing_friend_curve: PhantomData<P>,
}

/// BLS public verification key
#[tagged_blob("BLSVERKEY")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(Clone(bound = "P: Bls12Parameters"))]
#[derivative(Default(bound = "P: Bls12Parameters"))]
pub struct BLSVerKey<P: Bls12Parameters>(pub(crate) GroupAffine<P::G2Parameters>);

/// Signing key for BLS signature.
#[tagged_blob("BLSSIGNINGKEY")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(Clone(bound = "P: Bls12Parameters"))]
#[derivative(Default(bound = "P: Bls12Parameters"))]
pub struct BLSSignKey<P: Bls12Parameters>(
    pub(crate) <P::G1Parameters as ModelParameters>::ScalarField,
);

/// Signing key for BLS signature.
#[tagged_blob("BLSSIG")]
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(Clone(bound = "P: Bls12Parameters"))]
#[derivative(Default(bound = "P: Bls12Parameters"))]
pub struct BLSSignature<P: Bls12Parameters>(pub(crate) GroupAffine<P::G1Parameters>);

impl<P> SignatureScheme for BLSSignatureScheme<P>
where
    P: Bls12Parameters,
    P::G1Parameters: SWHashToGroup,
{
    const CS_ID: &'static str = CS_ID_BLS_SIG_NAIVE;

    /// Signing key.
    type SigningKey = BLSSignKey<P>;

    /// Verification key
    type VerificationKey = BLSVerKey<P>;

    /// Public Parameter
    /// For BLS signatures, we want to use default
    /// prime subgroup generators. So here we don't need
    /// to specify which PP it is.
    type PublicParameter = ();

    /// Signature
    type Signature = BLSSignature<P>;

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
        // TODO: absorb ciphersuite_id in prng
        let sk = BLSSignKey(<P::G1Parameters as ModelParameters>::ScalarField::rand(
            prng,
        ));
        let vk = BLSVerKey(
            GroupAffine::<P::G2Parameters>::prime_subgroup_generator()
                .mul(sk.0)
                .into_affine(),
        );
        Ok((sk, vk))
    }

    /// Sign a message
    fn sign<R: CryptoRng + RngCore, M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        sk: &Self::SigningKey,
        msg: M,
        _prng: &mut R,
    ) -> Result<Self::Signature, PrimitivesError> {
        let hm = <P::G1Parameters as SWHashToGroup>::hash_to_group(
            msg.as_ref(),
            CS_ID_BLS_SIG_NAIVE.as_ref(),
        )?;
        Ok(BLSSignature(hm.mul(&sk.0.into_repr()).into_affine()))
    }

    /// Verify a signature.
    fn verify<M: AsRef<[Self::MessageUnit]>>(
        _pp: &Self::PublicParameter,
        vk: &Self::VerificationKey,
        msg: M,
        sig: &Self::Signature,
    ) -> Result<(), PrimitivesError> {
        let hm = <P::G1Parameters as SWHashToGroup>::hash_to_group(
            msg.as_ref(),
            CS_ID_BLS_SIG_NAIVE.as_ref(),
        )?;

        if multi_pairing::<Bls12<P>>(
            [hm.into_affine(), sig.0].as_ref(),
            [
                vk.0.neg(),
                GroupAffine::<P::G2Parameters>::prime_subgroup_generator(),
            ]
            .as_ref(),
        ) == Fp12::<P::Fp12Params>::one()
        {
            Ok(())
        } else {
            Err(PrimitivesError::VerificationError(
                "Signature verification error".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::signatures::tests::{failed_verification, sign_and_verify};
    use ark_bls12_377::Parameters as Param377;
    use ark_bls12_381::Parameters as Param381;

    macro_rules! test_signature {
        ($curve_param:tt) => {
            let message = "this is a test message";
            let message_bad = "this is a wrong message";
            sign_and_verify::<BLSSignatureScheme<$curve_param>>(message.as_ref());
            failed_verification::<BLSSignatureScheme<$curve_param>>(
                message.as_ref(),
                message_bad.as_ref(),
            );
        };
    }

    #[test]
    fn test_bls_sig() {
        test_signature!(Param377);
        test_signature!(Param381);
    }
}
