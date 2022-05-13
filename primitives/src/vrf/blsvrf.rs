//! BLS signature based VRF

use super::Vrf;
use crate::{
    constants::CS_ID_BLS_VRF_NAIVE,
    errors::PrimitivesError,
    hash_to_group::SWHashToGroup,
    signatures::{
        bls::{BLSSignKey, BLSSignature, BLSVerKey},
        BLSSignatureScheme, SignatureScheme,
    },
};
use ark_ec::bls12::Bls12Parameters;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use digest::Digest;

/// BLS VRF scheme.
/// Optimized for signature size, i.e.: PK in G2 and sig in G1
pub struct BLSVRFScheme<P: Bls12Parameters> {
    pairing_friend_curve: PhantomData<P>,
}

impl<H, P> Vrf<H, P> for BLSVRFScheme<P>
where
    H: Digest,
    P: Bls12Parameters,
    P::G1Parameters: SWHashToGroup,
{
    const CS_ID: &'static str = CS_ID_BLS_VRF_NAIVE;

    /// Public Parameter.
    /// For BLS signatures, we want to use default
    /// prime subgroup generators. So here we don't need
    /// to specify which PP it is.
    type PublicParameter = ();

    /// VRF public key.
    type PublicKey = BLSVerKey<P>;

    /// VRF secret key.
    type SecretKey = BLSSignKey<P>;

    /// VRF signature.
    type Proof = BLSSignature<P>;

    /// The input of VRF proof.
    type Input = [u8; 32];

    /// The output of VRF evaluation.
    type Output = [u8; 32];

    /// generate public parameters from RNG.
    fn param_gen<R: CryptoRng + RngCore>(
        _prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError> {
        Ok(())
    }

    /// Creates a pair of VRF public and private keys.
    fn key_gen<R: CryptoRng + RngCore>(
        pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), PrimitivesError> {
        <BLSSignatureScheme<P> as SignatureScheme>::key_gen(pp, prng)
    }

    /// Creates the VRF proof associated with a VRF secret key.
    fn prove<R: CryptoRng + RngCore>(
        pp: &Self::PublicParameter,
        secret_key: &Self::SecretKey,
        input: &Self::Input,
        prng: &mut R,
    ) -> Result<Self::Proof, PrimitivesError> {
        <BLSSignatureScheme<P> as SignatureScheme>::sign(pp, secret_key, input, prng)
    }

    /// Computes the VRF output associated with a VRF proof.
    fn evaluate(
        _pp: &Self::PublicParameter,
        proof: &Self::Proof,
    ) -> Result<Self::Output, PrimitivesError> {
        let mut proof_serialized = Vec::new();
        proof.0.serialize_uncompressed(&mut proof_serialized)?;
        let mut hasher = H::new();
        hasher.update(&proof_serialized);
        let mut output = [0u8; 32];
        output.copy_from_slice(hasher.finalize().as_ref());
        Ok(output)
    }

    /// Verifies a VRF proof.
    fn verify(
        pp: &Self::PublicParameter,
        proof: &Self::Proof,
        public_key: &Self::PublicKey,
        input: &Self::Input,
    ) -> Result<bool, PrimitivesError> {
        if <BLSSignatureScheme<P> as SignatureScheme>::verify(pp, public_key, input, proof).is_err()
        {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vrf::tests::{failed_verification, sign_and_verify};
    use ark_bls12_377::Parameters as Param377;
    use ark_bls12_381::Parameters as Param381;
    use sha2::Sha256;

    macro_rules! test_bls_vrf {
        ($curve_param:tt) => {
            let message = [0u8; 32];
            let message_bad = [1u8; 32];
            sign_and_verify::<BLSVRFScheme<$curve_param>, Sha256, _>(&message);
            failed_verification::<BLSVRFScheme<$curve_param>, Sha256, _>(&message, &message_bad);
        };
    }

    #[test]
    fn test_bls_vrf() {
        test_bls_vrf!(Param377);
        test_bls_vrf!(Param381);
    }
}
