// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{
    open_internal,
    srs::{MultilinearProverParam, MultilinearVerifierParam},
    util::{build_l, compute_w_circ_l, merge_polynomials},
    verify_internal, MultilinearKzgBatchProof, MLE,
};
use crate::{
    multilinear_kzg::util::get_uni_domain,
    prelude::{Commitment, UnivariateProverParam, UnivariateVerifierParam},
    transcript::IOPTranscript,
    univariate_kzg::UnivariateKzgPCS,
    PCSError, PolynomialCommitmentScheme,
};
use ark_ec::pairing::Pairing;
use ark_poly::{EvaluationDomain, MultilinearExtension, Polynomial};
use ark_std::{end_timer, start_timer, string::ToString, vec, vec::Vec};

/// Batch opens a set of polynomials with respect to the provided points.
///
/// ### Parameters
/// - `uni_prover_param`: Prover parameters for univariate KZG.
/// - `ml_prover_param`: Prover parameters for multilinear KZG.
/// - `polynomials`: List of multilinear extensions (polynomials).
/// - `batch_commitment`: Combined commitment for the polynomials.
/// - `points`: List of points, one for each polynomial.
///
/// ### Returns
/// - A tuple containing:
///   - The batch proof (consisting of multilinear KZG opening and other elements).
///   - Evaluations of the univariate polynomial `q(x)` at the specified points.
///
/// ### Errors
/// Returns a `PCSError` if the input parameters are invalid or if there are verification mismatches.
pub(super) fn batch_open_internal<E: Pairing>(
    uni_prover_param: &UnivariateProverParam<E>,
    ml_prover_param: &MultilinearProverParam<E>,
    polynomials: &[MLE<E::ScalarField>],
    batch_commitment: &Commitment<E>,
    points: &[Vec<E::ScalarField>],
) -> Result<(MultilinearKzgBatchProof<E>, Vec<E::ScalarField>), PCSError> {
    let open_timer = start_timer!(|| "batch open");

    validate_inputs(points, polynomials)?;

    let num_vars = polynomials[0].num_vars();
    let domain = get_uni_domain::<E::ScalarField>(points.len())?;
    let uni_polys = build_l(num_vars, points, &domain)?;

    let merge_poly = merge_polynomials(polynomials)?;
    let q_x = compute_w_circ_l(&merge_poly, &uni_polys)?;

    let mut transcript = setup_transcript(batch_commitment, points, &q_x)?;
    let r = transcript.get_and_append_challenge(b"r")?;

    let (q_x_opens, q_x_evals) = generate_qx_proofs(uni_prover_param, &q_x, &domain, points)?;
    let (q_x_open, q_r_value) = UnivariateKzgPCS::<E>::open(uni_prover_param, &q_x, &r)?;

    let point = evaluate_polynomials(&uni_polys, &r);
    let (mle_opening, mle_eval) = open_internal(ml_prover_param, &merge_poly, &point)?;

    if mle_eval != q_r_value {
        return Err(PCSError::InvalidProver("Q(r) does not match W(l(r))".to_string()));
    }

    end_timer!(open_timer);

    Ok((
        MultilinearKzgBatchProof {
            proof: mle_opening,
            q_x_commit: UnivariateKzgPCS::<E>::commit(uni_prover_param, &q_x)?,
            q_x_opens: [q_x_opens, vec![q_x_open]].concat(),
        },
        [q_x_evals, vec![q_r_value]].concat(),
    ))
}

/// Validates inputs for batch opening.
fn validate_inputs<E: Pairing>(
    points: &[Vec<E::ScalarField>],
    polynomials: &[MLE<E::ScalarField>],
) -> Result<(), PCSError> {
    if points.is_empty() || points.len() != polynomials.len() {
        return Err(PCSError::InvalidParameters(
            "Mismatched points and polynomials length".to_string(),
        ));
    }

    let num_vars = polynomials[0].num_vars();
    for (poly, point) in polynomials.iter().zip(points) {
        if poly.num_vars() != num_vars || point.len() != num_vars {
            return Err(PCSError::InvalidParameters(
                "Polynomials or points have inconsistent num_vars".to_string(),
            ));
        }
    }
    Ok(())
}

/// Sets up the transcript with initial values.
fn setup_transcript<E: Pairing>(
    batch_commitment: &Commitment<E>,
    points: &[Vec<E::ScalarField>],
    q_x: &impl Polynomial<E::ScalarField>,
) -> Result<IOPTranscript, PCSError> {
    let mut transcript = IOPTranscript::new(b"ml kzg");
    transcript.append_serializable_element(b"w", batch_commitment)?;

    for point in points {
        transcript.append_serializable_element(b"points", point)?;
    }

    let q_x_commit = UnivariateKzgPCS::<E>::commit(batch_commitment.prover_param(), q_x)?;
    transcript.append_serializable_element(b"q(x)", &q_x_commit)?;

    Ok(transcript)
}

/// Generates proofs and evaluations for `q(x)` at the domain points.
fn generate_qx_proofs<E: Pairing>(
    uni_prover_param: &UnivariateProverParam<E>,
    q_x: &impl Polynomial<E::ScalarField>,
    domain: &impl EvaluationDomain<E::ScalarField>,
    points: &[Vec<E::ScalarField>],
) -> Result<(Vec<Commitment<E>>, Vec<E::ScalarField>), PCSError> {
    let mut q_x_opens = Vec::new();
    let mut q_x_evals = Vec::new();

    for (i, point) in points.iter().enumerate() {
        let domain_element = domain.element(i);
        let (q_x_open, q_x_eval) =
            UnivariateKzgPCS::<E>::open(uni_prover_param, q_x, &domain_element)?;
        q_x_opens.push(q_x_open);
        q_x_evals.push(q_x_eval);
    }

    Ok((q_x_opens, q_x_evals))
}

/// Evaluates a set of polynomials at a given point.
fn evaluate_polynomials<F: Clone>(polynomials: &[impl Polynomial<F>], r: &F) -> Vec<F> {
    polynomials.iter().map(|poly| poly.evaluate(r)).collect()
}
