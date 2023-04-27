// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Polynomial Commitment Scheme
pub mod errors;
mod multilinear_kzg;
mod poly;
pub mod prelude;
mod structs;
mod transcript;
mod univariate_kzg;

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    hash::Hash,
    path::Path,
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use errors::PCSError;

/// This trait defines APIs for polynomial commitment schemes.
/// Note that for our usage, this PCS is not hiding.
/// TODO(#187): add hiding property.
pub trait PolynomialCommitmentScheme {
    /// Structured reference string
    type SRS: Clone + Debug + StructuredReferenceString;
    /// Polynomial and its associated types
    type Polynomial: Clone
        + Debug
        + Hash
        + PartialEq
        + Eq
        + CanonicalSerialize
        + CanonicalDeserialize;
    /// Polynomial input domain
    type Point: Clone + Ord + Debug + Sync + Hash + PartialEq + Eq;
    /// Polynomial Evaluation
    type Evaluation: Field;
    /// Commitments
    type Commitment: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;
    /// Batch commitments
    type BatchCommitment: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;
    /// Proofs
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;
    /// Batch proofs
    type BatchProof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;

    /// Setup for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCSError> {
        Self::SRS::gen_srs_for_testing(rng, supported_size)
    }

    /// Load public parameter in production environment.
    /// These parameters are loaded from files with serialized `pp` bytes, and
    /// the actual setup is usually carried out via MPC and should be
    /// implemented else where. We only load them into memory here.
    ///
    /// If `file=None`, we load the default choice of SRS.
    fn load_srs_from_file(
        supported_size: usize,
        file: Option<&Path>,
    ) -> Result<Self::SRS, PCSError> {
        Self::SRS::load_srs_from_file(supported_size, file)
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    /// ## Note on function signature
    /// Usually, data structure like SRS and ProverParam are huge and users
    /// might wish to keep them in heap using different kinds of smart pointers
    /// (instead of only in stack) therefore our `impl Borrow<_>` interface
    /// allows for passing in any pointer type, e.g.: `trim(srs: &Self::SRS,
    /// ..)` or `trim(srs: Box<Self::SRS>, ..)` or `trim(srs: Arc<Self::SRS>,
    /// ..)` etc.
    #[allow(clippy::type_complexity)]
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: usize,
        supported_num_vars: Option<usize>,
    ) -> Result<
        (
            <Self::SRS as StructuredReferenceString>::ProverParam,
            <Self::SRS as StructuredReferenceString>::VerifierParam,
        ),
        PCSError,
    >;

    /// Generate a binding (but not hiding) commitment for a polynomial
    fn commit(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError>;

    /// Batch commit a list of polynomials
    fn batch_commit(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, PCSError>;

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    fn open(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError>;

    /// Input a list of polynomials, and a same number of points,
    /// compute a batch opening for all the polynomials.
    fn batch_open(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        batch_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError>;

    /// Open a single polynomial at multiple points.
    /// The naive default implmenetation just open them individually.
    #[allow(clippy::type_complexity)]
    fn multi_open(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        points: &[Self::Point],
    ) -> Result<(Vec<Self::Proof>, Vec<Self::Evaluation>), PCSError> {
        Ok(points
            .iter()
            .map(|point| Self::open(prover_param.borrow(), polynomial, point))
            .collect::<Result<Vec<_>, _>>()
            .map_err(PCSError::from)?
            .into_iter()
            .unzip())
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn verify(
        verifier_param: &<Self::SRS as StructuredReferenceString>::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &Self::Evaluation,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError>;

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &<Self::SRS as StructuredReferenceString>::VerifierParam,
        multi_commitment: &Self::BatchCommitment,
        points: &[Self::Point],
        values: &[Self::Evaluation],
        batch_proof: &Self::BatchProof,
        rng: &mut R,
    ) -> Result<bool, PCSError>;
}

/// API definitions for structured reference string
pub trait StructuredReferenceString: Sized {
    /// Prover parameters
    type ProverParam;
    /// Verifier parameters
    type VerifierParam;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_size: usize) -> Self::ProverParam;
    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_size: usize) -> Self::VerifierParam;

    /// Trim the universal parameters to specialize the public parameters
    /// for polynomials to the given `supported_size`, and
    /// returns committer key and verifier key.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is 2 to the number of
    ///   variables.
    ///
    /// `supported_log_size` should be in range `1..=params.log_size`
    fn trim(
        &self,
        supported_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self, PCSError>;

    /// Load public parameter in production environment.
    /// These parameters are loaded from files with serialized `pp` bytes, and
    /// the actual setup is usually carried out via MPC and should be
    /// implemented else where. We only load them into memory here.
    ///
    /// If `file=None`, we load the default choice of SRS.
    fn load_srs_from_file(_supported_size: usize, _file: Option<&Path>) -> Result<Self, PCSError> {
        unimplemented!("TODO: implement loading SRS from files");
    }
}

/// Super-trait specific for univariate polynomial commitment schemes.
pub trait UnivariatePCS:
    PolynomialCommitmentScheme<Point = <Self as PolynomialCommitmentScheme>::Evaluation>
{
    /// Similar to [`PolynomialCommitmentScheme::trim()`], but trim to support
    /// the FFT operations, such as [`Self::multi_open_rou()`] or other
    /// operations that involves roots of unity.
    #[allow(clippy::type_complexity)]
    fn trim_fft_size(
        srs: impl Borrow<Self::SRS>,
        supported_degree: usize,
    ) -> Result<
        (
            <Self::SRS as StructuredReferenceString>::ProverParam,
            <Self::SRS as StructuredReferenceString>::VerifierParam,
        ),
        PCSError,
    > {
        srs.borrow().trim(checked_fft_size(supported_degree)?)
    }

    /// Same task as [`PolynomialCommitmentScheme::multi_open()`], except the
    /// points are [roots of unity](https://en.wikipedia.org/wiki/Root_of_unity).
    /// The first `num_points` of roots will be evaluated (in canonical order).
    #[allow(clippy::type_complexity)]
    fn multi_open_rou(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        num_points: usize,
    ) -> Result<(Vec<Self::Proof>, Vec<Self::Evaluation>), PCSError>;
}

// compute the fft size (i.e. `num_coeffs`) given a degree.
#[inline]
pub(crate) fn checked_fft_size(degree: usize) -> Result<usize, PCSError> {
    let err = || {
        PCSError::InvalidParameters(ark_std::format!(
            "Next power of two overflows! Got: {}",
            degree
        ))
    };
    if degree.is_power_of_two() {
        degree.checked_mul(2).ok_or_else(err)
    } else {
        degree.checked_next_power_of_two().ok_or_else(err)
    }
}
