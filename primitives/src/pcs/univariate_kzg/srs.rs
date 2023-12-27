// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementing Structured Reference Strings for univariate polynomial KZG

use crate::pcs::{PCSError, StructuredReferenceString};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{string::ToString, vec::Vec};

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
// Adapted from
// https://github.com/arkworks-rs/poly-commit/blob/c724fa666e935bbba8db5a1421603bab542e15ab/poly-commit/src/kzg10/data_structures.rs#L24
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct UnivariateUniversalParams<E: Pairing> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to
    /// `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
    /// TODO: remove h and beta_h
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// powers of \beta time the generator h of G2
    pub powers_of_h: Vec<E::G2Affine>,
}

impl<E: Pairing> UnivariateUniversalParams<E> {
    /// Returns the maximum supported degree
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len()
    }
}

/// `UnivariateProverParam` is used to generate a proof
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct UnivariateProverParam<E: Pairing> {
    /// Config
    pub powers_of_g: Vec<E::G1Affine>,
}

/// `UnivariateVerifierParam` is used to check evaluation proofs for a given
/// commitment.
#[derive(Derivative, Clone, Debug, Eq, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
#[derivative(Default)]
pub struct UnivariateVerifierParam<E: Pairing> {
    /// TODO: remove g, h and beta_h
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
    /// powers of \beta time the generator h of G2: only used for multi-point
    /// openings
    pub powers_of_h: Vec<E::G2Affine>,
    /// powers of \beta time the generator g of G1: only used for multi-point
    /// openings
    pub powers_of_g: Vec<E::G1Affine>,
}

impl<E: Pairing> StructuredReferenceString for UnivariateUniversalParams<E> {
    type ProverParam = UnivariateProverParam<E>;
    type VerifierParam = UnivariateVerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_degree: usize) -> Self::ProverParam {
        let powers_of_g = self.powers_of_g[..=supported_degree].to_vec();

        Self::ProverParam { powers_of_g }
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_degree: usize) -> Self::VerifierParam {
        Self::VerifierParam {
            g: self.powers_of_g[0],
            h: self.h,
            beta_h: self.beta_h,
            powers_of_h: self.powers_of_h[..=supported_degree].to_vec(),
            powers_of_g: self.powers_of_g[..=supported_degree].to_vec(),
        }
    }

    /// Trim the universal parameters to specialize the public parameters
    /// for univariate polynomials to the given `supported_degree`, and
    /// returns committer key and verifier key. `supported_degree` should
    /// be in range `1..params.len()`
    fn trim_with_verifier_degree(
        &self,
        prover_supported_degree: usize,
        verifier_supported_degree: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        if self.powers_of_g.len() <= prover_supported_degree {
            return Err(PCSError::InvalidParameters(ark_std::format!(
                "Largest supported prover degree by the SRS is: {}, but requested: {}",
                self.powers_of_g.len() - 1,
                prover_supported_degree,
            )));
        }
        if self.powers_of_h.len() <= verifier_supported_degree {
            return Err(PCSError::InvalidParameters(ark_std::format!(
                "Largest supported verifier degree by the SRS is: {}, but requested: {}",
                self.powers_of_h.len() - 1,
                verifier_supported_degree,
            )));
        }
        if verifier_supported_degree == 0 {
            return Err(PCSError::InvalidParameters(
                "Verifier supported degree should be larger than zero".to_string(),
            ));
        }
        let powers_of_g = self.powers_of_g[..=prover_supported_degree].to_vec();

        let pk = Self::ProverParam { powers_of_g };
        let vk = Self::VerifierParam {
            g: self.powers_of_g[0],
            h: self.h,
            beta_h: self.beta_h,
            powers_of_h: self.powers_of_h[..=verifier_supported_degree].to_vec(),
            powers_of_g: self.powers_of_g[..=verifier_supported_degree].to_vec(),
        };
        Ok((pk, vk))
    }

    /// Trim the universal parameters to specialize the public parameters
    /// for univariate polynomials to the given `supported_degree`, and
    /// returns committer key and verifier key. `supported_degree` should
    /// be in range `1..params.len()`
    fn trim(
        &self,
        supported_degree: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        self.trim_with_verifier_degree(supported_degree, 1)
    }

    // (alex): I'm not sure how to import `RngCore, CryptoRng` under `cfg(test)`
    // when they are unused by the rest. Thus, I use explicit import path.
    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing<R>(rng: &mut R, max_degree: usize) -> Result<Self, PCSError>
    where
        R: ark_std::rand::RngCore + ark_std::rand::CryptoRng,
    {
        tests::gen_srs_for_testing(rng, max_degree, 1)
    }

    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing_with_verifier_degree<
        R: ark_std::rand::prelude::RngCore + ark_std::rand::prelude::CryptoRng,
    >(
        rng: &mut R,
        prover_supported_degree: usize,
        verifier_supported_degree: usize,
    ) -> Result<Self, PCSError> {
        tests::gen_srs_for_testing(rng, prover_supported_degree, verifier_supported_degree)
    }
}

#[cfg(any(test, feature = "test-srs"))]
mod tests {
    use super::UnivariateUniversalParams;
    use crate::pcs::PCSError;
    use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup};
    use ark_ff::PrimeField;
    use ark_std::{
        end_timer,
        rand::{CryptoRng, RngCore},
        start_timer, vec, One, UniformRand,
    };

    pub(crate) fn gen_srs_for_testing<E: Pairing, R: RngCore + CryptoRng>(
        rng: &mut R,
        prover_degree: usize,
        verifier_degree: usize,
    ) -> Result<UnivariateUniversalParams<E>, PCSError> {
        let setup_time = start_timer!(|| ark_std::format!(
            "KZG10::Setup with prover degree {} and verifier degree {}",
            prover_degree,
            verifier_degree
        ));
        let beta = E::ScalarField::rand(rng);
        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);

        let mut powers_of_beta = vec![E::ScalarField::one()];

        let mut cur = beta;
        let max_degree = ark_std::cmp::max(prover_degree, verifier_degree);
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBase::get_mul_window_size(prover_degree + 1);

        let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;
        let g_time = start_timer!(|| "Generating powers of G");
        // TODO: parallelization
        let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);
        let powers_of_g =
            FixedBase::msm::<E::G1>(scalar_bits, window_size, &g_table, &powers_of_beta);
        end_timer!(g_time);

        let powers_of_g = E::G1::normalize_batch(&powers_of_g);

        let h = h.into_affine();
        let beta_h = (h * beta).into_affine();

        let powers_of_h = powers_of_beta
            .iter()
            .take(verifier_degree + 1)
            .map(|x| (h * x).into_affine())
            .collect();

        let pp = UnivariateUniversalParams {
            powers_of_g,
            h,
            beta_h,
            powers_of_h,
        };
        end_timer!(setup_time);
        Ok(pp)
    }
}
