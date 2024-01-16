// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! KZG polynomial commitment in evaluation form

use ark_ec::pairing::Pairing;
use ark_std::{
    borrow::Borrow,
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    slice,
    vec::Vec,
};

use crate::pcs::{
    poly::EvalReprPolynomial,
    prelude::{Commitment, PCSError},
    PolynomialCommitmentScheme, StructuredReferenceString,
};

/// KZG PCS on univariate polynomial in evaluation form
pub struct UnivariateEvalFormKzg<E>(PhantomData<E>);

impl<E: Pairing> PolynomialCommitmentScheme for UnivariateEvalFormKzg<E> {
    type SRS = super::srs::UnivariateUniversalParams<E>; // TODO: use diff types of SRS
    type Polynomial = EvalReprPolynomial<E::ScalarField, Vec<E::ScalarField>>;
    type Point = E::ScalarField;
    type Evaluation = E::ScalarField;
    type Commitment = Commitment<E>;
    type BatchCommitment = Vec<Self::Commitment>;
    type Proof = E::G1Affine;
    type BatchProof = Vec<Self::Proof>;

    fn commit(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        unimplemented!()
    }

    fn batch_commit(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, PCSError> {
        unimplemented!()
    }

    fn open(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        unimplemented!()
    }

    fn batch_open(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        batch_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError> {
        unimplemented!()
    }

    fn verify(
        verifier_param: &<Self::SRS as StructuredReferenceString>::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &Self::Evaluation,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        unimplemented!()
    }

    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &<Self::SRS as StructuredReferenceString>::VerifierParam,
        multi_commitment: &Self::BatchCommitment,
        points: &[Self::Point],
        values: &[Self::Evaluation],
        batch_proof: &Self::BatchProof,
        rng: &mut R,
    ) -> Result<bool, PCSError> {
        unimplemented!()
    }
}
