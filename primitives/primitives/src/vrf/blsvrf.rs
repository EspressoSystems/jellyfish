//! BLS signature based VRF
use super::Vrf;
use crate::{
    errors::PrimitivesError,
    signatures::{
        bls_over_bls12381::{BLSSignKey, BLSSignature, BLSVerKey},
        BLSSignatureScheme, SignatureScheme,
    },
};
use ark_std::{
    boxed::Box,
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use digest::{Digest, DynDigest};
use sha2::{Sha256, Sha512};

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
pub struct BLSVRFScheme {
    hasher: Box<dyn DynDigest>,
}

impl BLSVRFScheme {
    /// Creates a new BLS VRF instance with the given ciphersuite.
    pub fn new(cs_id: BLSVRFCipherSuite) -> Self {
        match cs_id {
            BLSVRFCipherSuite::VRF_BLS_12_381_SHA256 => Self {
                hasher: Box::new(Sha256::new()),
            },
            BLSVRFCipherSuite::VRF_BLS_12_381_SHA512 => Self {
                hasher: Box::new(Sha512::new()),
            },
        }
    }
}

impl Vrf for BLSVRFScheme {
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
        let mut hasher = (*self.hasher).box_clone();
        hasher.update(&proof_serialized);
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

#[cfg(test)]
mod test {
    use jf_utils::test_rng;

    use super::*;
    use ark_std::rand::Rng;

    pub(crate) fn sign_and_verify<H: Digest>(
        vrf: &mut BLSVRFScheme,
        message: &<BLSVRFScheme as Vrf>::Input,
        bad_message: &<BLSVRFScheme as Vrf>::Input,
    ) {
        let rng = &mut test_rng();

        let (sk, pk) = vrf.key_gen(&(), rng).unwrap();
        let vrf_proof = vrf.prove(&(), &sk, message, rng).unwrap();
        let vrf_output = vrf.proof_to_hash(&(), &vrf_proof).unwrap();
        let (is_correct, output) = vrf.verify(&(), &vrf_proof, &pk, message).unwrap();
        assert!(is_correct);
        // need to use the result
        assert!(output.is_some());

        // check that proof_to_hash(proof) == evaluate(sk, message)
        let out = vrf.evaluate(&(), &sk, message, rng).unwrap();
        assert_eq!(out, vrf_output);

        // check the VRF output vs. hashing the proof directly
        let mut hasher = H::new();
        hasher.update(vrf_proof.serialize());
        let direct_hash_output = hasher.finalize().to_vec();
        assert_eq!(direct_hash_output, vrf_output);

        // now test for bad message. User can choose to ignore the output if they really
        // want to.
        let (is_correct, _) = vrf.verify(&(), &vrf_proof, &pk, bad_message).unwrap();
        assert!(!is_correct);
    }

    #[test]
    fn test_bls_vrf() {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let message = rng.gen::<[u8; 32]>().to_vec();
            // bad message is truncated
            let message_bad = message.clone()[..31].to_vec();
            let mut blsvrf256 = BLSVRFScheme::new(BLSVRFCipherSuite::VRF_BLS_12_381_SHA256);

            sign_and_verify::<Sha256>(&mut blsvrf256, &message, &message_bad);

            let mut blsvrf512 = BLSVRFScheme::new(BLSVRFCipherSuite::VRF_BLS_12_381_SHA512);
            sign_and_verify::<Sha512>(&mut blsvrf512, &message, &message_bad);
        }
    }
}
