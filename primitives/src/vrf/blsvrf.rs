//! BLS signature based VRF

use super::Vrf;
use crate::{
    constants::CS_ID_BLS_VRF_NAIVE,
    errors::PrimitivesError,
    signatures::{
        bls::{BLSSignKey, BLSSignature, BLSVerKey},
        BLSSignatureScheme, SignatureScheme,
    },
};
use ark_std::rand::{CryptoRng, RngCore};
use digest::Digest;

/// BLS VRF scheme.
/// Optimized for signature size, i.e.: PK in G2 and sig in G1
pub struct BLSVRFScheme;

impl<H> Vrf<H> for BLSVRFScheme
where
    H: Digest,
{
    const CS_ID: &'static str = CS_ID_BLS_VRF_NAIVE;

    /// Public Parameter.
    /// For BLS signatures, we want to use default
    /// prime subgroup generators. So here we don't need
    /// to specify which PP it is.
    type PublicParameter = ();

    /// VRF public key.
    type PublicKey = BLSVerKey;

    /// VRF secret key.
    type SecretKey = BLSSignKey;

    /// VRF signature.
    type Proof = BLSSignature;

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
        <BLSSignatureScheme as SignatureScheme>::key_gen(pp, prng)
    }

    /// Creates the VRF proof associated with a VRF secret key.
    fn prove<R: CryptoRng + RngCore>(
        pp: &Self::PublicParameter,
        secret_key: &Self::SecretKey,
        input: &Self::Input,
        prng: &mut R,
    ) -> Result<Self::Proof, PrimitivesError> {
        <BLSSignatureScheme as SignatureScheme>::sign(pp, secret_key, input, prng)
    }

    /// Computes the VRF output associated with a VRF proof.
    fn evaluate(
        _pp: &Self::PublicParameter,
        proof: &Self::Proof,
    ) -> Result<Self::Output, PrimitivesError> {
        let proof_serialized = proof.serialize();
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
        if <BLSSignatureScheme as SignatureScheme>::verify(pp, public_key, input, proof).is_err() {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vrf::tests::{failed_verification, sign_and_verify};
    use sha2::Sha256;

    #[test]
    fn test_bls_vrf() {
        let message = [0u8; 32];
        let message_bad = [1u8; 32];
        sign_and_verify::<BLSVRFScheme, Sha256>(&message);
        failed_verification::<BLSVRFScheme, Sha256>(&message, &message_bad);
    }
}
