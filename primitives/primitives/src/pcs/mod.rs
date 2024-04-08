// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Polynomial Commitment Scheme
pub mod errors;
pub(crate) mod multilinear_kzg;
mod poly;
pub mod prelude;
mod structs;
pub mod transcript;
pub(crate) mod univariate_kzg;

use ark_ff::{FftField, Field};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    cmp,
    fmt::Debug,
    hash::Hash,
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
    type Polynomial: Clone + Debug + Hash + PartialEq + Eq;
    /// Polynomial input domain
    type Point: Clone + Ord + Debug + Sync + Hash + PartialEq + Eq;
    /// Polynomial Evaluation
    type Evaluation: Field;
    /// Commitments
    type Commitment: Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Debug
        + PartialEq
        + Eq
        + Hash;
    /// Batch commitments
    type BatchCommitment: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;
    /// Proofs
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq + Hash;
    /// Batch proofs
    type BatchProof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;

    /// Setup for testing.
    ///
    /// - For univariate polynomials, `supported_degree` is the maximum degree.
    /// - For multilinear polynomials, `supported_degree` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        supported_degree: usize,
    ) -> Result<Self::SRS, PCSError> {
        Self::SRS::gen_srs_for_testing(rng, supported_degree)
    }

    /// Setup for testing.
    ///
    /// - For univariate polynomials, `prover/verifier_supported_degree` is the
    ///   maximum degree.
    /// - For multilinear polynomials, `supported_degree` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing_with_verifier_degree<R: RngCore + CryptoRng>(
        rng: &mut R,
        prover_supported_degree: usize,
        verifier_supported_degree: usize,
    ) -> Result<Self::SRS, PCSError> {
        Self::SRS::gen_srs_for_testing_with_verifier_degree(
            rng,
            prover_supported_degree,
            verifier_supported_degree,
        )
    }

    /// Load public parameter in production environment.
    /// These parameters are loaded from files with serialized `pp` bytes, and
    /// the actual setup is usually carried out via MPC and should be
    /// implemented else where. We only load them into memory here.
    ///
    /// If `file=None`, we load the default choice of SRS.
    fn load_srs_from_file(
        supported_degree: usize,
        file: Option<&str>,
    ) -> Result<Self::SRS, PCSError> {
        Self::SRS::load_srs_from_file(supported_degree, file)
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
    /// The naive default implementation just open them individually.
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
    fn extract_prover_param(&self, supported_degree: usize) -> Self::ProverParam;
    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_degree: usize) -> Self::VerifierParam;

    /// Trim the universal parameters to specialize the public parameters
    /// for polynomials to the given `supported_degree`, and
    /// returns committer key and verifier key.
    ///
    /// - For univariate polynomials, `supported_degree` is the maximum degree.
    /// - For multilinear polynomials, `supported_degree` is 2 to the number of
    ///   variables.
    ///
    /// `supported_log_size` should be in range `1..=params.log_size`
    fn trim(
        &self,
        supported_degree: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    /// Trim the universal parameters to specialize the public parameters
    /// for polynomials to the given `prover/verifier_supported_degree`, and
    /// returns committer key and verifier key.
    ///
    /// - For univariate polynomials, `prover_/verifier_supported_degree` is the
    ///   maximum degree.
    /// - For multilinear polynomials, `supported_degree` is 2 to the number of
    ///   variables.
    ///
    /// `supported_log_size` should be in range `1..=params.log_size`
    fn trim_with_verifier_degree(
        &self,
        prover_supported_degree: usize,
        verifier_supported_degree: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_degree` is the maximum degree.
    /// - For multilinear polynomials, `supported_degree` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        supported_degree: usize,
    ) -> Result<Self, PCSError>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `prover/verifier_supported_degree` is the
    ///   maximum degree.
    /// - For multilinear polynomials, `supported_degree` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    #[cfg(any(test, feature = "test-srs"))]
    fn gen_srs_for_testing_with_verifier_degree<R: RngCore + CryptoRng>(
        rng: &mut R,
        prover_supported_degree: usize,
        verifier_supported_degree: usize,
    ) -> Result<Self, PCSError>;

    /// Load public parameter in production environment.
    /// These parameters are loaded from files with serialized `pp` bytes, and
    /// the actual setup is usually carried out via MPC and should be
    /// implemented else where. We only load them into memory here.
    ///
    /// If `file=None`, we load the default choice of SRS.
    fn load_srs_from_file(_supported_degree: usize, _file: Option<&str>) -> Result<Self, PCSError> {
        unimplemented!("TODO: implement loading SRS from files");
    }
}

/// Super-trait specific for univariate polynomial commitment schemes.
pub trait UnivariatePCS: PolynomialCommitmentScheme
where
    Self::Evaluation: FftField,
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
        let fft_degree = checked_fft_size(supported_degree)?;
        srs.borrow().trim(fft_degree).map_err(|e| {
            PCSError::InvalidParameters(ark_std::format!(
                "Requesting degree of {} for FFT:\n\t\t{:?}",
                fft_degree,
                e
            ))
        })
    }

    /// Given `degree` of the committed polynomial and `num_points` to open,
    /// return the evaluation domain for faster computation of opening proofs
    /// and evaluations (both using FFT).
    fn multi_open_rou_eval_domain(
        degree: usize,
        num_points: usize,
    ) -> Result<Radix2EvaluationDomain<Self::Evaluation>, PCSError> {
        // reason for zero-padding: https://github.com/EspressoSystems/jellyfish/pull/231#issuecomment-1526488659
        let padded_degree = checked_fft_size(degree)?;

        let domain_size = cmp::max(padded_degree + 1, num_points);
        let domain = Radix2EvaluationDomain::new(domain_size).ok_or_else(|| {
            PCSError::UpstreamError(ark_std::format!(
                "Fail to init eval domain of size {}",
                domain_size
            ))
        })?;

        Ok(domain)
    }

    /// Same task as [`PolynomialCommitmentScheme::multi_open()`], except the
    /// points are [roots of unity](https://en.wikipedia.org/wiki/Root_of_unity).
    /// The first `num_points` of roots will be evaluated (in canonical order).
    #[allow(clippy::type_complexity)]
    fn multi_open_rou(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        num_points: usize,
        domain: &Radix2EvaluationDomain<Self::Evaluation>,
    ) -> Result<(Vec<Self::Proof>, Vec<Self::Evaluation>), PCSError> {
        let evals = Self::multi_open_rou_evals(polynomial, num_points, domain)?;
        let proofs = Self::multi_open_rou_proofs(prover_param, polynomial, num_points, domain)?;
        Ok((proofs, evals))
    }

    /// Compute the opening proofs in [`Self::multi_open_rou()`].
    fn multi_open_rou_proofs(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        num_points: usize,
        domain: &Radix2EvaluationDomain<Self::Evaluation>,
    ) -> Result<Vec<Self::Proof>, PCSError>;

    /// Compute the evaluations in [`Self::multi_open_rou()`].
    fn multi_open_rou_evals(
        polynomial: &Self::Polynomial,
        num_points: usize,
        domain: &Radix2EvaluationDomain<Self::Evaluation>,
    ) -> Result<Vec<Self::Evaluation>, PCSError>;

    /// Input a polynomial, and multiple evaluation points,
    /// compute a *single* opening proof for the multiple points of the same
    /// polynomial.
    fn multi_point_open(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        points: &[Self::Point],
    ) -> Result<(Self::Proof, Vec<Self::Evaluation>), PCSError>;

    /// Verifies that `values` are the evaluation at the `points` of the
    /// polynomial committed inside `comm`.
    fn multi_point_verify(
        verifier_param: impl Borrow<<Self::SRS as StructuredReferenceString>::VerifierParam>,
        commitment: &Self::Commitment,
        points: &[Self::Point],
        values: &[Self::Evaluation],
        proof: &Self::Proof,
    ) -> Result<bool, PCSError>;
}

/// compute the fft size (i.e. `num_coeffs`) given a degree.
#[inline]
pub fn checked_fft_size(degree: usize) -> Result<usize, PCSError> {
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
