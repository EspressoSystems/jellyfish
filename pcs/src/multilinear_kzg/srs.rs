// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Structured Reference Strings (SRS) implementation for multilinear polynomial KZG.

use crate::{
    prelude::PCSError,
    univariate_kzg::srs::{
        UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam,
    },
    StructuredReferenceString,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{format, vec, vec::Vec};

/// Evaluations over {0,1}^n for G1 or G2.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Evaluations<C: AffineRepr> {
    /// The evaluations.
    pub evals: Vec<C>,
}

/// Universal Parameters for multilinear KZG.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultilinearUniversalParams<E: Pairing> {
    pub prover_param: MultilinearProverParam<E>,
    pub h_mask: Vec<E::G2Affine>, // h^randomness: h^t1, h^t2, ..., h^{t_nv}
}

/// Prover Parameters for multilinear KZG.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultilinearProverParam<E: Pairing> {
    pub num_vars: usize,
    pub powers_of_g: Vec<Evaluations<E::G1Affine>>,
    pub g: E::G1Affine,
    pub h: E::G2Affine,
}

/// Verifier Parameters for multilinear KZG.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct MultilinearVerifierParam<E: Pairing> {
    pub num_vars: usize,
    pub g: E::G1Affine,
    pub h: E::G2Affine,
    pub h_mask: Vec<E::G2Affine>, // h^randomness: h^t1, h^t2, ..., h^{t_nv}
}

impl<E: Pairing> StructuredReferenceString for MultilinearUniversalParams<E> {
    type ProverParam = MultilinearProverParam<E>;
    type VerifierParam = MultilinearVerifierParam<E>;

    fn extract_prover_param(&self, supported_num_vars: usize) -> Self::ProverParam {
        let reduced_range = self.prover_param.num_vars - supported_num_vars;
        Self::ProverParam {
            powers_of_g: self.prover_param.powers_of_g[reduced_range..].to_vec(),
            g: self.prover_param.g,
            h: self.prover_param.h,
            num_vars: supported_num_vars,
        }
    }

    fn extract_verifier_param(&self, supported_num_vars: usize) -> Self::VerifierParam {
        let reduced_range = self.prover_param.num_vars - supported_num_vars;
        Self::VerifierParam {
            num_vars: supported_num_vars,
            g: self.prover_param.g,
            h: self.prover_param.h,
            h_mask: self.h_mask[reduced_range..].to_vec(),
        }
    }

    fn trim(
        &self,
        supported_num_vars: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        if supported_num_vars > self.prover_param.num_vars {
            return Err(PCSError::InvalidParameters(format!(
                "Target number of variables ({}) exceeds limit ({})",
                supported_num_vars, self.prover_param.num_vars
            )));
        }

        let ck = self.extract_prover_param(supported_num_vars);
        let vk = self.extract_verifier_param(supported_num_vars);

        Ok((ck, vk))
    }

    fn trim_with_verifier_degree(
        &self,
        prover_supported_num_vars: usize,
        _verifier_supported_num_vars: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        self.trim(prover_supported_num_vars)
    }

    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing<R>(rng: &mut R, num_vars: usize) -> Result<Self, PCSError>
    where
        R: ark_std::rand::RngCore + ark_std::rand::CryptoRng,
    {
        tests::gen_srs_for_testing(rng, num_vars)
    }

    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing_with_verifier_degree<R>(
        rng: &mut R,
        prover_num_vars: usize,
        _verifier_num_vars: usize,
    ) -> Result<Self, PCSError>
    where
        R: ark_std::rand::RngCore + ark_std::rand::CryptoRng,
    {
        Self::gen_srs_for_testing(rng, prover_num_vars)
    }
}

// Implements SRS for multilinear and univariate KZG.
impl<E: Pairing> StructuredReferenceString
    for (MultilinearUniversalParams<E>, UnivariateUniversalParams<E>)
{
    type ProverParam = (MultilinearProverParam<E>, UnivariateProverParam<E>);
    type VerifierParam = (MultilinearVerifierParam<E>, UnivariateVerifierParam<E>);

    fn trim(
        &self,
        supported_degree: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let ml_params = self.0.trim(supported_degree)?;
        let uni_params = self.1.trim(supported_degree)?;

        Ok(((ml_params.0, uni_params.0), (ml_params.1, uni_params.1)))
    }

    fn trim_with_verifier_degree(
        &self,
        prover_supported_num_vars: usize,
        _verifier_supported_num_vars: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        self.trim(prover_supported_num_vars)
    }

    fn extract_prover_param(&self, supported_degree: usize) -> Self::ProverParam {
        (
            self.0.extract_prover_param(supported_degree),
            self.1.extract_prover_param(supported_degree),
        )
    }

    fn extract_verifier_param(&self, supported_degree: usize) -> Self::VerifierParam {
        (
            self.0.extract_verifier_param(supported_degree),
            self.1.extract_verifier_param(supported_degree),
        )
    }

    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing<R>(rng: &mut R, supported_degree: usize) -> Result<Self, PCSError>
    where
        R: ark_std::rand::RngCore + ark_std::rand::CryptoRng,
    {
        let ml_srs = MultilinearUniversalParams::gen_srs_for_testing(rng, supported_degree)?;
        let uni_srs = UnivariateUniversalParams::gen_srs_for_testing(rng, supported_degree)?;

        Ok((ml_srs, uni_srs))
    }

    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing_with_verifier_degree<R>(
        rng: &mut R,
        prover_num_vars: usize,
        _verifier_num_vars: usize,
    ) -> Result<Self, PCSError>
    where
        R: ark_std::rand::RngCore + ark_std::rand::CryptoRng,
    {
        Self::gen_srs_for_testing(rng, prover_num_vars)
    }
}
