//! BLS signature based VRF
use core::marker::PhantomData;

use super::Vrf;
use crate::{
    errors::PrimitivesError,
    signatures::{
        bls::{BLSSignKey, BLSSignature, BLSVerKey},
        BLSSignatureScheme, SignatureScheme,
    },
};
use ark_std::{
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use digest::Digest;

/// Supported Cipher Suites for BLS VRF.
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum BLSVRFCipherSuite {
    /// using blst library and VRF output from SHA256 hashing
    VRF_BLS_12_381_SHA256,
    /// using blst library and VRF output from SHA512 hashing
    VRF_BLS_12_381_SHA512,
}

/// BLS VRF scheme.
/// Optimized for signature size, i.e.: PK in G2 and sig in G1
pub struct BLSVRFSchemeGen<H>(PhantomData<H>);

impl<H: Digest> BLSVRFSchemeGen<H> {
    /// Creates a new BLS VRF instance with the given ciphersuite.
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<H: Digest> Vrf for BLSVRFSchemeGen<H> {
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
    type Input = Vec<u8>;

    /// The output of VRF evaluation.
    type Output = Vec<u8>;

    /// generate public parameters from RNG.
    fn param_gen<R: CryptoRng + RngCore>(
        &self,
        _prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError> {
        Ok(())
    }

    /// Creates a pair of VRF public and private keys.
    fn key_gen<R: CryptoRng + RngCore>(
        &self,
        pp: &Self::PublicParameter,
        prng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), PrimitivesError> {
        <BLSSignatureScheme as SignatureScheme>::key_gen(pp, prng)
    }

    /// Creates the VRF proof associated with a VRF secret key.
    fn prove<R: CryptoRng + RngCore>(
        &self,
        pp: &Self::PublicParameter,
        secret_key: &Self::SecretKey,
        input: &Self::Input,
        prng: &mut R,
    ) -> Result<Self::Proof, PrimitivesError> {
        <BLSSignatureScheme as SignatureScheme>::sign(pp, secret_key, input, prng)
    }

    /// Computes the VRF output associated with a VRF proof.
    fn proof_to_hash(
        &mut self,
        _pp: &Self::PublicParameter,
        proof: &Self::Proof,
    ) -> Result<Self::Output, PrimitivesError> {
        let proof_serialized = proof.serialize();
        let mut hasher = H::new();
        hasher.update(proof_serialized);
        let output = hasher.finalize();
        Ok(output.to_vec())
    }

    /// Verifies a VRF proof.
    fn verify(
        &mut self,
        pp: &Self::PublicParameter,
        proof: &Self::Proof,
        public_key: &Self::PublicKey,
        input: &Self::Input,
    ) -> Result<(bool, Option<Self::Output>), PrimitivesError> {
        if <BLSSignatureScheme as SignatureScheme>::verify(pp, public_key, input, proof).is_ok() {
            Ok((true, Some(Self::proof_to_hash(self, pp, proof).unwrap())))
        } else {
            Ok((false, None))
        }
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use ark_std::{test_rng, vec};

//     pub(crate) fn sign_and_verify(
//         vrf: &mut BLSVRFScheme,
//         message: &<BLSVRFScheme as Vrf>::Input,
//         bad_message: &<BLSVRFScheme as Vrf>::Input,
//     ) {
//         let rng = &mut test_rng();

//         let parameters = vrf.param_gen(Some(rng)).unwrap();
//         let (sk, pk) = vrf.key_gen(&parameters, rng).unwrap();
//         let vrf_proof = vrf.prove(&parameters, &sk, message, rng).unwrap();
//         let _vrf_output = vrf.proof_to_hash(&parameters, &vrf_proof).unwrap();
//         let (is_correct, output) = vrf.verify(&parameters, &vrf_proof, &pk, message).unwrap();
//         assert!(is_correct);
//         // need to use the result
//         assert!(output.is_some());

//         // now test for bad message. User can choose to ignore the output if they really
//         // want to.
//         let (is_correct, _) = vrf
//             .verify(&parameters, &vrf_proof, &pk, bad_message)
//             .unwrap();
//         assert!(!is_correct);
//     }

//     #[test]
//     fn test_bls_vrf() {
//         let message = vec![0u8; 32];
//         let message_bad = vec![1u8; 32];
//         let mut blsvrf256 = BLSVRFScheme::new(BLSVRFCipherSuite::VRF_BLS_12_381_SHA256);
//         sign_and_verify(&mut blsvrf256, &message, &message_bad);

//         let mut blsvrf512 = BLSVRFScheme::new(BLSVRFCipherSuite::VRF_BLS_12_381_SHA512);
//         sign_and_verify(&mut blsvrf512, &message, &message_bad);
//     }
// }
