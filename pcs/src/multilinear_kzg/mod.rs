// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

mod batching;
pub(crate) mod srs;
pub(crate) mod util;

use crate::{
    prelude::{Commitment, UnivariateUniversalParams},
    univariate_kzg::UnivariateKzgProof,
    PCSError, PolynomialCommitmentScheme, StructuredReferenceString,
};
use ark_ec::{
    pairing::Pairing,
    scalar_mul::{fixed_base::FixedBase, variable_base::VariableBaseMSM},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    end_timer, format,
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    start_timer,
    string::ToString,
    vec,
    vec::Vec,
    One, Zero,
};
use batching::{batch_open_internal, batch_verify_internal};
use srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam};
use util::merge_polynomials;

type Srs<E> = (MultilinearUniversalParams<E>, UnivariateUniversalParams<E>);
type ProverParam<E> = <Srs<E> as StructuredReferenceString>::ProverParam;
type VerifierParam<E> = <Srs<E> as StructuredReferenceString>::VerifierParam;

/// KZG Polynomial Commitment Scheme for multilinear polynomials.
pub struct MultilinearKzgPCS<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

/// Represents a proof of evaluation for multilinear KZG.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
#[derivative(Hash)]
pub struct MultilinearKzgProof<E: Pairing> {
    pub proofs: Vec<E::G1Affine>,
}

/// Represents a batch proof for multilinear KZG.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MultilinearKzgBatchProof<E: Pairing> {
    pub proof: MultilinearKzgProof<E>,
    pub q_x_commit: Commitment<E>,
    pub q_x_opens: Vec<UnivariateKzgProof<E>>,
}

#[cfg(target_has_atomic = "ptr")]
pub type MLE<F> = Arc<DenseMultilinearExtension<F>>;
#[cfg(not(target_has_atomic = "ptr"))]
pub type MLE<F> = DenseMultilinearExtension<F>;

impl<E: Pairing> PolynomialCommitmentScheme for MultilinearKzgPCS<E> {
    type SRS = Srs<E>;
    type Polynomial = MLE<E::ScalarField>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    type Commitment = Commitment<E>;
    type BatchCommitment = Commitment<E>;
    type Proof = MultilinearKzgProof<E>;
    type BatchProof = MultilinearKzgBatchProof<E>;

    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_log_degree: usize,
        supported_num_vars: Option<usize>,
    ) -> Result<(ProverParam<E>, VerifierParam<E>), PCSError> {
        let supported_num_vars = supported_num_vars.ok_or_else(|| {
            PCSError::InvalidParameters("Missing num_vars parameter for multilinear trimming.".into())
        })?;

        let (uni_ck, uni_vk) = srs.borrow().1.trim(supported_log_degree)?;
        let (ml_ck, ml_vk) = srs.borrow().0.trim(supported_num_vars)?;

        Ok(((ml_ck, uni_ck), (ml_vk, uni_vk)))
    }

    fn commit(
        prover_param: impl Borrow<ProverParam<E>>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();
        validate_poly_dims(prover_param, poly)?;

        let scalars = poly
            .to_evaluations()
            .iter()
            .map(|x| x.into_bigint())
            .collect::<Vec<_>>();

        let commitment = E::G1::msm_bigint(
            &prover_param.0.powers_of_g[0].evals,
            scalars.as_slice(),
        )
        .into_affine();

        Ok(Commitment(commitment))
    }

    fn batch_commit(
        prover_param: impl Borrow<ProverParam<E>>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::Commitment, PCSError> {
        let poly = merge_polynomials(polys)?;
        Self::commit(prover_param, &poly)
    }

    fn open(
        prover_param: impl Borrow<ProverParam<E>>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        open_internal(&prover_param.borrow().0, polynomial, point)
    }

    fn verify(
        verifier_param: &VerifierParam<E>,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        verify_internal(&verifier_param.0, commitment, point, value, proof)
    }

    fn batch_open(
        prover_param: impl Borrow<ProverParam<E>>,
        batch_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError> {
        batch_open_internal(
            &prover_param.borrow().1,
            &prover_param.borrow().0,
            polynomials,
            batch_commitment,
            points,
        )
    }

    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &VerifierParam<E>,
        batch_commitment: &Self::BatchCommitment,
        points: &[Self::Point],
        values: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        _rng: &mut R,
    ) -> Result<bool, PCSError> {
        batch_verify_internal(
            &verifier_param.1,
            &verifier_param.0,
            batch_commitment,
            points,
            values,
            batch_proof,
        )
    }
}

/// Validates the dimensions of the polynomial against the prover parameters.
fn validate_poly_dims<E: Pairing>(
    prover_param: &ProverParam<E>,
    poly: &DenseMultilinearExtension<E::ScalarField>,
) -> Result<(), PCSError> {
    if poly.num_vars > prover_param.0.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial dimensions exceed supported dimensions: {} > {}",
            poly.num_vars, prover_param.0.num_vars
        )));
    }
    Ok(())
}
