// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementing Structured Reference Strings for univariate polynomial KZG

use crate::pcs::{PCSError, StructuredReferenceString};
use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    end_timer,
    rand::{CryptoRng, RngCore},
    start_timer, vec,
    vec::Vec,
    One, UniformRand,
};

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
// Adapted from
// https://github.com/arkworks-rs/poly-commit/blob/master/src/kzg10/data_structures.rs#L20
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct UnivariateUniversalParams<E: Pairing> {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to
    /// `degree`.
    pub powers_of_g: Vec<E::G1Affine>,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
}

impl<E: Pairing> UnivariateUniversalParams<E> {
    /// Returns the maximum supported degree
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len()
    }
}

/// `UnivariateProverParam` is used to generate a proof
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct UnivariateProverParam<C: AffineRepr> {
    /// Config
    pub powers_of_g: Vec<C>,
}

/// `UnivariateVerifierParam` is used to check evaluation proofs for a given
/// commitment.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Default(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct UnivariateVerifierParam<E: Pairing> {
    /// The generator of G1.
    pub g: E::G1Affine,
    /// The generator of G2.
    pub h: E::G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: E::G2Affine,
}

impl<E: Pairing> StructuredReferenceString for UnivariateUniversalParams<E> {
    type ProverParam = UnivariateProverParam<E::G1Affine>;
    type VerifierParam = UnivariateVerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_size: usize) -> Self::ProverParam {
        let powers_of_g = self.powers_of_g[..=supported_size].to_vec();

        Self::ProverParam { powers_of_g }
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, _supported_size: usize) -> Self::VerifierParam {
        Self::VerifierParam {
            g: self.powers_of_g[0],
            h: self.h,
            beta_h: self.beta_h,
        }
    }

    /// Trim the universal parameters to specialize the public parameters
    /// for univariate polynomials to the given `supported_size`, and
    /// returns committer key and verifier key. `supported_size` should
    /// be in range `1..params.len()`
    fn trim(
        &self,
        supported_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let powers_of_g = self.powers_of_g[..=supported_size].to_vec();

        let pk = Self::ProverParam { powers_of_g };
        let vk = Self::VerifierParam {
            g: self.powers_of_g[0],
            h: self.h,
            beta_h: self.beta_h,
        };
        Ok((pk, vk))
    }

    /// Build SRS for testing.
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        max_degree: usize,
    ) -> Result<Self, PCSError> {
        let setup_time = start_timer!(|| format!("KZG10::Setup with degree {}", max_degree));
        let beta = E::ScalarField::rand(rng);
        let g = E::G1::rand(rng);
        let h = E::G2::rand(rng);

        let mut powers_of_beta = vec![E::ScalarField::one()];

        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }

        let window_size = FixedBase::get_mul_window_size(max_degree + 1);

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

        let pp = Self {
            powers_of_g,
            h,
            beta_h,
        };
        end_timer!(setup_time);
        Ok(pp)
    }
}
