// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{
    open_internal,
    srs::{MultilinearProverParam, MultilinearVerifierParam},
    util::{build_l, compute_w_circ_l, merge_polynomials},
    verify_internal, MultilinearKzgBatchProof,
};
use crate::pcs::{
    multilinear_kzg::util::get_uni_domain,
    prelude::{Commitment, UnivariateProverParam, UnivariateVerifierParam},
    transcript::IOPTranscript,
    univariate_kzg::UnivariateKzgPCS,
    PCSError, PolynomialCommitmentScheme,
};
use ark_ec::pairing::Pairing;
use ark_poly::{DenseMultilinearExtension, EvaluationDomain, MultilinearExtension, Polynomial};
use ark_std::{end_timer, format, start_timer, string::ToString, sync::Arc, vec, vec::Vec};

/// Input
/// - the prover parameters for univariate KZG,
/// - the prover parameters for multilinear KZG,
/// - a list of MLEs,
/// - a batch commitment to all MLEs
/// - and a same number of points,
/// compute a batch opening for all the polynomials.
///
/// For simplicity, this API requires each MLE to have only one point. If
/// the caller wish to use more than one points per MLE, it should be
/// handled at the caller layer.
///
/// Returns an error if the lengths do not match.
///
/// Returns the proof, consists of
/// - the multilinear KZG opening
/// - the univariate KZG commitment to q(x)
/// - the openings and evaluations of q(x) at omega^i and r
///
/// Steps:
/// 1. build `l(points)` which is a list of univariate polynomials that goes
/// through the points
/// 2. build MLE `w` which is the merge of all MLEs.
/// 3. build `q(x)` which is a univariate polynomial `W circ l`
/// 4. commit to q(x) and sample r from transcript
/// transcript contains: w commitment, points, q(x)'s commitment
/// 5. build q(omega^i) and their openings
/// 6. build q(r) and its opening
/// 7. get a point `p := l(r)`
/// 8. output an opening of `w` over point `p`
/// 9. output `w(p)`
///
/// TODO: Migrate the batching algorithm in HyperPlonk repo
pub(super) fn batch_open_internal<E: Pairing>(
    uni_prover_param: &UnivariateProverParam<E::G1Affine>,
    ml_prover_param: &MultilinearProverParam<E>,
    polynomials: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    batch_commitment: &Commitment<E>,
    points: &[Vec<E::ScalarField>],
) -> Result<(MultilinearKzgBatchProof<E>, Vec<E::ScalarField>), PCSError> {
    let open_timer = start_timer!(|| "batch open");

    // ===================================
    // Sanity checks on inputs
    // ===================================
    let points_len = points.len();
    if points_len == 0 {
        return Err(PCSError::InvalidParameters("points is empty".to_string()));
    }

    if points_len != polynomials.len() {
        return Err(PCSError::InvalidParameters(
            "polynomial length does not match point length".to_string(),
        ));
    }

    let num_var = polynomials[0].num_vars();
    for poly in polynomials.iter().skip(1) {
        if poly.num_vars() != num_var {
            return Err(PCSError::InvalidParameters(
                "polynomials do not have same num_vars".to_string(),
            ));
        }
    }
    for point in points.iter() {
        if point.len() != num_var {
            return Err(PCSError::InvalidParameters(
                "points do not have same num_vars".to_string(),
            ));
        }
    }

    let domain = get_uni_domain::<E::ScalarField>(points_len)?;

    // 1. build `l(points)` which is a list of univariate polynomials that goes
    // through the points
    let uni_polys = build_l(num_var, points, &domain)?;

    // 2. build MLE `w` which is the merge of all MLEs.
    let merge_poly = merge_polynomials(polynomials)?;

    // 3. build `q(x)` which is a univariate polynomial `W circ l`
    let q_x = compute_w_circ_l(&merge_poly, &uni_polys)?;

    // 4. commit to q(x) and sample r from transcript
    // transcript contains: w commitment, points, q(x)'s commitment
    let mut transcript = IOPTranscript::new(b"ml kzg");
    transcript.append_serializable_element(b"w", batch_commitment)?;
    for point in points {
        transcript.append_serializable_element(b"w", point)?;
    }

    let q_x_commit = UnivariateKzgPCS::<E>::commit(uni_prover_param, &q_x)?;
    transcript.append_serializable_element(b"q(x)", &q_x_commit)?;
    let r = transcript.get_and_append_challenge(b"r")?;

    // 5. build q(omega^i) and their openings
    let mut q_x_opens = vec![];
    let mut q_x_evals = vec![];
    for i in 0..points_len {
        let (q_x_open, q_x_eval) =
            UnivariateKzgPCS::<E>::open(uni_prover_param, &q_x, &domain.element(i))?;
        q_x_opens.push(q_x_open);
        q_x_evals.push(q_x_eval);

        // sanity check
        let point: Vec<E::ScalarField> = uni_polys
            .iter()
            .rev()
            .map(|poly| poly.evaluate(&domain.element(i)))
            .collect();
        let mle_eval = merge_poly.evaluate(&point).unwrap();
        if mle_eval != q_x_eval {
            return Err(PCSError::InvalidProver(
                "Q(omega) does not match W(l(omega))".to_string(),
            ));
        }
    }

    // 6. build q(r) and its opening
    let (q_x_open, q_r_value) = UnivariateKzgPCS::<E>::open(uni_prover_param, &q_x, &r)?;
    q_x_opens.push(q_x_open);
    q_x_evals.push(q_r_value);

    // 7. get a point `p := l(r)`
    let point: Vec<E::ScalarField> = uni_polys
        .iter()
        .rev()
        .map(|poly| poly.evaluate(&r))
        .collect();

    // 8. output an opening of `w` over point `p`
    let (mle_opening, mle_eval) = open_internal(ml_prover_param, &merge_poly, &point)?;

    // 9. output value that is `w` evaluated at `p` (which should match `q(r)`)
    if mle_eval != q_r_value {
        return Err(PCSError::InvalidProver(
            "Q(r) does not match W(l(r))".to_string(),
        ));
    }
    end_timer!(open_timer);

    Ok((
        MultilinearKzgBatchProof {
            proof: mle_opening,
            q_x_commit,
            q_x_opens,
        },
        q_x_evals,
    ))
}

/// Verifies that the `batch_commitment` is a valid commitment
/// to a list of MLEs for the given openings and evaluations in
/// the batch_proof.
///
/// steps:
///
/// 1. push w, points and q_com into transcript
/// 2. sample `r` from transcript
/// 3. check `q(r) == batch_proof.q_x_value.last` and
/// `q(omega^i) == batch_proof.q_x_value[i]`
/// 4. build `l(points)` which is a list of univariate
/// polynomials that goes through the points
/// 5. get a point `p := l(r)`
/// 6. verifies `p` is valid against multilinear KZG proof
pub(super) fn batch_verify_internal<E: Pairing>(
    uni_verifier_param: &UnivariateVerifierParam<E>,
    ml_verifier_param: &MultilinearVerifierParam<E>,
    batch_commitment: &Commitment<E>,
    points: &[Vec<E::ScalarField>],
    values: &[E::ScalarField],
    batch_proof: &MultilinearKzgBatchProof<E>,
) -> Result<bool, PCSError> {
    let verify_timer = start_timer!(|| "batch verify");

    // ===================================
    // Sanity checks on inputs
    // ===================================
    let points_len = points.len();
    if points_len == 0 {
        return Err(PCSError::InvalidParameters("points is empty".to_string()));
    }

    // add one here because we also have q(r) and its opening
    if points_len + 1 != batch_proof.q_x_opens.len() {
        return Err(PCSError::InvalidParameters(
            "openings length does not match point length".to_string(),
        ));
    }

    if points_len + 1 != values.len() {
        return Err(PCSError::InvalidParameters(
            "values length does not match point length".to_string(),
        ));
    }

    let num_var = points[0].len();
    for point in points.iter().skip(1) {
        if point.len() != num_var {
            return Err(PCSError::InvalidParameters(format!(
                "points do not have same num_vars ({} vs {})",
                point.len(),
                num_var,
            )));
        }
    }

    let domain = get_uni_domain::<E::ScalarField>(points_len)?;

    // 1. push w, points and q_com into transcript
    let mut transcript = IOPTranscript::new(b"ml kzg");
    transcript.append_serializable_element(b"w", batch_commitment)?;
    for point in points {
        transcript.append_serializable_element(b"w", point)?;
    }

    transcript.append_serializable_element(b"q(x)", &batch_proof.q_x_commit)?;

    // 2. sample `r` from transcript
    let r = transcript.get_and_append_challenge(b"r")?;

    // 3. check `q(r) == batch_proof.q_x_value.last` and `q(omega^i) =
    // batch_proof.q_x_value[i]`
    for (i, value) in values.iter().enumerate().take(points_len) {
        if !UnivariateKzgPCS::verify(
            uni_verifier_param,
            &batch_proof.q_x_commit,
            &domain.element(i),
            value,
            &batch_proof.q_x_opens[i],
        )? {
            #[cfg(debug_assertion)]
            println!("q(omega^{}) verification failed", i);
            return Ok(false);
        }
    }

    if !UnivariateKzgPCS::verify(
        uni_verifier_param,
        &batch_proof.q_x_commit,
        &r,
        &values[points_len],
        &batch_proof.q_x_opens[points_len],
    )? {
        #[cfg(debug_assertion)]
        println!("q(r) verification failed");
        return Ok(false);
    }

    // 4. build `l(points)` which is a list of univariate polynomials that goes
    // through the points
    let uni_polys = build_l(num_var, points, &domain)?;

    // 5. get a point `p := l(r)`
    let point: Vec<E::ScalarField> = uni_polys.iter().rev().map(|x| x.evaluate(&r)).collect();

    // 6. verifies `p` is valid against multilinear KZG proof
    let res = verify_internal(
        ml_verifier_param,
        batch_commitment,
        &point,
        &values[points_len],
        &batch_proof.proof,
    )?;

    #[cfg(debug_assertion)]
    if !res {
        println!("multilinear KZG verification failed");
    }

    end_timer!(verify_timer);

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::{
        super::{util::get_batched_nv, *},
        *,
    };
    use crate::pcs::{
        multilinear_kzg::util::{compute_qx_degree, generate_evaluations},
        prelude::UnivariateUniversalParams,
        StructuredReferenceString,
    };
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::pairing::Pairing;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::{log2, rand::RngCore, vec::Vec, UniformRand};
    use jf_utils::test_rng;
    type Fr = <E as Pairing>::ScalarField;

    fn test_batch_commit_helper<R: RngCore + CryptoRng>(
        uni_params: &UnivariateUniversalParams<E>,
        ml_params: &MultilinearUniversalParams<E>,
        polys: &[Arc<DenseMultilinearExtension<Fr>>],
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let merged_nv = get_batched_nv(polys[0].num_vars(), polys.len());
        let qx_degree = compute_qx_degree(merged_nv, polys.len());
        let padded_qx_degree = 1usize << log2(qx_degree);

        let (uni_ck, uni_vk) = uni_params.trim(padded_qx_degree)?;
        let (ml_ck, ml_vk) = ml_params.trim(merged_nv)?;

        let mut points = Vec::new();
        for poly in polys.iter() {
            let point = (0..poly.num_vars())
                .map(|_| Fr::rand(rng))
                .collect::<Vec<Fr>>();
            points.push(point);
        }

        let evals = generate_evaluations(polys, &points)?;

        let com = MultilinearKzgPCS::batch_commit(&(ml_ck.clone(), uni_ck.clone()), polys)?;
        let (batch_proof, evaluations) =
            batch_open_internal(&uni_ck, &ml_ck, polys, &com, &points)?;

        for (a, b) in evals.iter().zip(evaluations.iter()) {
            assert_eq!(a, b)
        }

        // good path
        assert!(batch_verify_internal(
            &uni_vk,
            &ml_vk,
            &com,
            &points,
            &evaluations,
            &batch_proof,
        )?);

        // bad commitment
        assert!(!batch_verify_internal(
            &uni_vk,
            &ml_vk,
            &Commitment(<E as Pairing>::G1Affine::default()),
            &points,
            &evaluations,
            &batch_proof,
        )?);

        // bad points
        assert!(
            batch_verify_internal(&uni_vk, &ml_vk, &com, &points[1..], &[], &batch_proof,).is_err()
        );

        // bad proof
        assert!(batch_verify_internal(
            &uni_vk,
            &ml_vk,
            &com,
            &points,
            &evaluations,
            &MultilinearKzgBatchProof {
                proof: MultilinearKzgProof { proofs: Vec::new() },
                q_x_commit: Commitment(<E as Pairing>::G1Affine::default()),
                q_x_opens: vec![],
            },
        )
        .is_err());

        // bad value
        let mut wrong_evals = evaluations.clone();
        wrong_evals[0] = Fr::default();
        assert!(!batch_verify_internal(
            &uni_vk,
            &ml_vk,
            &com,
            &points,
            &wrong_evals,
            &batch_proof
        )?);

        // bad q(x) commit
        let mut wrong_proof = batch_proof;
        wrong_proof.q_x_commit = Commitment(<E as Pairing>::G1Affine::default());
        assert!(!batch_verify_internal(
            &uni_vk,
            &ml_vk,
            &com,
            &points,
            &evaluations,
            &wrong_proof,
        )?);
        Ok(())
    }

    #[test]
    fn test_batch_commit_internal() -> Result<(), PCSError> {
        let mut rng = test_rng();

        let uni_params =
            UnivariateUniversalParams::<E>::gen_srs_for_testing(&mut rng, 1usize << 15)?;
        let ml_params = MultilinearUniversalParams::<E>::gen_srs_for_testing(&mut rng, 15)?;

        // normal polynomials
        let polys1: Vec<_> = (0..5)
            .map(|_| Arc::new(DenseMultilinearExtension::rand(4, &mut rng)))
            .collect();
        test_batch_commit_helper(&uni_params, &ml_params, &polys1, &mut rng)?;

        // single-variate polynomials
        let polys1: Vec<_> = (0..5)
            .map(|_| Arc::new(DenseMultilinearExtension::rand(1, &mut rng)))
            .collect();
        test_batch_commit_helper(&uni_params, &ml_params, &polys1, &mut rng)?;

        Ok(())
    }
}
