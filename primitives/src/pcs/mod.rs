// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Polynomial Commitment Scheme
pub mod errors;
mod multilinear_kzg;
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
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use errors::PCSError;

/// This trait defines APIs for polynomial commitment schemes.
/// Note that for our usage, this PCS is not hiding.
/// TODO(#187): add hiding property.
pub trait PolynomialCommitmentScheme {
    /// Prover parameters
    type ProverParam: Clone;
    /// Verifier parameters
    type VerifierParam: Clone + CanonicalSerialize + CanonicalDeserialize;
    /// Structured reference string
    type SRS: Clone + Debug;
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

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCSError>;

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
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: usize,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    /// Generate a commitment for a polynomial
    /// ## Note on function signature
    /// Usually, data structure like SRS and ProverParam are huge and users
    /// might wish to keep them in heap using different kinds of smart pointers
    /// (instead of only in stack) therefore our `impl Borrow<_>` interface
    /// allows for passing in any pointer type, e.g.: `commit(prover_param:
    /// &Self::ProverParam, ..)` or `commit(prover_param:
    /// Box<Self::ProverParam>, ..)` or `commit(prover_param:
    /// Arc<Self::ProverParam>, ..)` etc.
    /// Also, the commitment is not hiding.
    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError>;

    /// Batch commit a list of polynomials
    fn batch_commit(
        prover_param: impl Borrow<Self::ProverParam>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, PCSError>;

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError>;

    /// Input a list of polynomials, and a same number of points,
    /// compute a batch opening for all the polynomials.
    fn batch_open(
        prover_param: impl Borrow<Self::ProverParam>,
        batch_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError>;

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &Self::Evaluation,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError>;

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &Self::VerifierParam,
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
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self, PCSError>;
}
