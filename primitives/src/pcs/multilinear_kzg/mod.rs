// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Main module for multilinear KZG commitment scheme

mod batching;
pub(crate) mod srs;
pub(crate) mod util;

use crate::pcs::{
    prelude::{
        Commitment, UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam,
    },
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
    sync::Arc,
    vec,
    vec::Vec,
    One, Zero,
};
use batching::{batch_open_internal, batch_verify_internal};
use srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam};
use util::merge_polynomials;

/// KZG Polynomial Commitment Scheme on multilinear polynomials.
pub struct MultilinearKzgPCS<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of opening
pub struct MultilinearKzgProof<E: Pairing> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
/// proof of batch opening
pub struct MultilinearKzgBatchProof<E: Pairing> {
    /// The actual proof
    pub proof: MultilinearKzgProof<E>,
    /// Commitment to q(x):= w(l(x)) where
    /// - `w` is the merged MLE
    /// - `l` is the list of univariate polys that goes through all points
    pub q_x_commit: Commitment<E>,
    /// openings of q(x) at 1, omega, ..., and r
    pub q_x_opens: Vec<UnivariateKzgProof<E>>,
}

impl<E: Pairing> PolynomialCommitmentScheme for MultilinearKzgPCS<E> {
    // Config
    type ProverParam = (
        MultilinearProverParam<E>,
        UnivariateProverParam<E::G1Affine>,
    );
    type VerifierParam = (MultilinearVerifierParam<E>, UnivariateVerifierParam<E>);
    type SRS = (MultilinearUniversalParams<E>, UnivariateUniversalParams<E>);
    // Polynomial and its associated types
    type Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    // Commitments and proofs
    type Commitment = Commitment<E>;
    type BatchCommitment = Commitment<E>;
    type Proof = MultilinearKzgProof<E>;
    type BatchProof = MultilinearKzgBatchProof<E>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `log_size` is the log of maximum degree.
    /// - For multilinear polynomials, `log_size` is the number of variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: RngCore + CryptoRng>(
        rng: &mut R,
        log_size: usize,
    ) -> Result<Self::SRS, PCSError> {
        Ok((
            MultilinearUniversalParams::<E>::gen_srs_for_testing(rng, log_size)?,
            UnivariateUniversalParams::<E>::gen_srs_for_testing(rng, log_size)?,
        ))
    }

    /// Trim the universal parameters to specialize the public parameters.
    /// Input both `supported_log_degree` for univariate and
    /// `supported_num_vars` for multilinear.
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_log_degree: usize,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let supported_num_vars = match supported_num_vars {
            Some(p) => p,
            None => {
                return Err(PCSError::InvalidParameters(
                    "multilinear should receive a num_var param".to_string(),
                ))
            },
        };
        let (uni_ck, uni_vk) = srs.borrow().1.trim(supported_log_degree)?;
        let (ml_ck, ml_vk) = srs.borrow().0.trim(supported_num_vars)?;

        Ok(((ml_ck, uni_ck), (ml_vk, uni_vk)))
    }

    /// Generate a commitment for a polynomial.
    ///
    /// This function takes `2^num_vars` number of scalar multiplications over
    /// G1.
    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();
        let commit_timer = start_timer!(|| "commit");
        if prover_param.0.num_vars < poly.num_vars {
            return Err(PCSError::InvalidParameters(format!(
                "Poly length ({}) exceeds param limit ({})",
                poly.num_vars, prover_param.0.num_vars
            )));
        }
        let ignored = prover_param.0.num_vars - poly.num_vars;
        let scalars: Vec<_> = poly
            .to_evaluations()
            .into_iter()
            .map(|x| x.into_bigint())
            .collect();
        let commitment = E::G1::msm_bigint(
            &prover_param.0.powers_of_g[ignored].evals,
            scalars.as_slice(),
        )
        .into_affine();

        end_timer!(commit_timer);
        Ok(Commitment(commitment))
    }

    /// Batch commit a list of polynomials.
    ///
    /// This function takes `2^(num_vars + log(polys.len())` number of scalar
    /// multiplications over G1.
    fn batch_commit(
        prover_param: impl Borrow<Self::ProverParam>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();
        let commit_timer = start_timer!(|| "multi commit");
        let poly = merge_polynomials(polys)?;

        let scalars: Vec<_> = poly
            .to_evaluations()
            .iter()
            .map(|x| x.into_bigint())
            .collect();

        let commitment =
            E::G1::msm_bigint(&prover_param.0.powers_of_g[0].evals, scalars.as_slice())
                .into_affine();

        end_timer!(commit_timer);
        Ok(Commitment(commitment))
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same. This function does not need to take the evaluation value as an
    /// input.
    ///
    /// This function takes 2^{num_var +1} number of scalar multiplications over
    /// G1:
    /// - it prodceeds with `num_var` number of rounds,
    /// - at round i, we compute an MSM for `2^{num_var - i + 1}` number of G2
    ///   elements.
    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        open_internal(&prover_param.borrow().0, polynomial, point)
    }

    /// Input
    /// - the prover parameters for univariate KZG,
    /// - the prover parameters for multilinear KZG,
    /// - a list of polynomials,
    /// - a (batch) commitment to all polynomials,
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
    fn batch_open(
        prover_param: impl Borrow<Self::ProverParam>,
        batch_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError> {
        batch_open_internal::<E>(
            &prover_param.borrow().1,
            &prover_param.borrow().0,
            polynomials,
            batch_commitment,
            points,
        )
    }

    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    ///
    /// This function takes
    /// - num_var number of pairing product.
    /// - num_var number of MSM
    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        verify_internal(&verifier_param.0, commitment, point, value, proof)
    }

    /// Verifies that `value` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `commitment`.
    /// steps:
    ///
    /// 1. put `q(x)`'s evaluations over `(1, omega,...)` into transcript
    /// 2. sample `r` from transcript
    /// 3. check `q(r) == value`
    /// 4. build `l(points)` which is a list of univariate polynomials that goes
    /// through the points
    /// 5. get a point `p := l(r)`
    /// 6. verifies `p` is verifies against proof
    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &Self::VerifierParam,
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

/// On input a polynomial `p` and a point `point`, outputs a proof for the
/// same. This function does not need to take the evaluation value as an
/// input.
///
/// This function takes 2^{num_var} number of scalar multiplications over
/// G1:
/// - it proceeds with `num_var` number of rounds,
/// - at round i, we compute an MSM for `2^{num_var - i}` number of G1 elements.
fn open_internal<E: Pairing>(
    prover_param: &MultilinearProverParam<E>,
    polynomial: &DenseMultilinearExtension<E::ScalarField>,
    point: &[E::ScalarField],
) -> Result<(MultilinearKzgProof<E>, E::ScalarField), PCSError> {
    let open_timer = start_timer!(|| format!("open mle with {} variable", polynomial.num_vars));

    if polynomial.num_vars() > prover_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} exceed the limit {}",
            polynomial.num_vars, prover_param.num_vars
        )));
    }

    if polynomial.num_vars() != point.len() {
        return Err(PCSError::InvalidParameters(format!(
            "Polynomial num_vars {} does not match point len {}",
            polynomial.num_vars,
            point.len()
        )));
    }

    let nv = polynomial.num_vars();
    // the first `ignored` SRS vectors are unused
    let ignored = prover_param.num_vars - nv + 1;

    let mut f = polynomial.to_evaluations();

    let mut proofs = Vec::new();

    for (i, (&point_at_k, gi)) in point
        .iter()
        .zip(prover_param.powers_of_g[ignored..ignored + nv].iter())
        .enumerate()
    {
        let ith_round = start_timer!(|| format!("{}-th round", i));

        let k = nv - 1 - i;
        let cur_dim = 1 << k;
        let mut q = vec![E::ScalarField::zero(); cur_dim];
        let mut r = vec![E::ScalarField::zero(); cur_dim];

        let ith_round_eval = start_timer!(|| format!("{}-th round eval", i));
        for b in 0..(1 << k) {
            // q[b] = f[1, b] - f[0, b]
            q[b] = f[(b << 1) + 1] - f[b << 1];

            // r[b] = f[0, b] + q[b] * p
            r[b] = f[b << 1] + (q[b] * point_at_k);
        }
        f = r;
        end_timer!(ith_round_eval);
        let scalars: Vec<_> = q.iter().map(|x| x.into_bigint()).collect();

        // this is a MSM over G1 and is likely to be the bottleneck
        let msm_timer = start_timer!(|| format!("msm of size {} at round {}", gi.evals.len(), i));

        proofs.push(E::G1::msm_bigint(&gi.evals, &scalars).into_affine());
        end_timer!(msm_timer);

        end_timer!(ith_round);
    }
    let eval = polynomial
        .evaluate(point)
        .ok_or_else(|| PCSError::InvalidParameters("fail to eval poly at the point".to_string()))?;
    end_timer!(open_timer);
    Ok((MultilinearKzgProof { proofs }, eval))
}

/// Verifies that `value` is the evaluation at `x` of the polynomial
/// committed inside `comm`.
///
/// This function takes
/// - num_var number of pairing product.
/// - num_var number of MSM
fn verify_internal<E: Pairing>(
    verifier_param: &MultilinearVerifierParam<E>,
    commitment: &Commitment<E>,
    point: &[E::ScalarField],
    value: &E::ScalarField,
    proof: &MultilinearKzgProof<E>,
) -> Result<bool, PCSError> {
    let verify_timer = start_timer!(|| "verify");
    let num_var = point.len();

    if num_var > verifier_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "point length ({}) exceeds param limit ({})",
            num_var, verifier_param.num_vars
        )));
    }

    let prepare_inputs_timer = start_timer!(|| "prepare pairing inputs");

    let scalar_size = E::ScalarField::MODULUS_BIT_SIZE as usize;
    let window_size = FixedBase::get_mul_window_size(num_var);

    let h_table =
        FixedBase::get_window_table(scalar_size, window_size, verifier_param.h.into_group());
    let h_mul: Vec<E::G2> = FixedBase::msm(scalar_size, window_size, &h_table, point);

    // the first `ignored` G2 parameters are unused
    let ignored = verifier_param.num_vars - num_var;
    let h_vec: Vec<_> = (0..num_var)
        .map(|i| verifier_param.h_mask[ignored + i].into_group() - h_mul[i])
        .collect();
    let h_vec: Vec<E::G2Affine> = E::G2::normalize_batch(&h_vec);
    end_timer!(prepare_inputs_timer);

    let pairing_product_timer = start_timer!(|| "pairing product");

    let mut pairings_l: Vec<E::G1Prepared> = proof
        .proofs
        .iter()
        .map(|&x| E::G1Prepared::from(x))
        .collect();

    let mut pairings_r: Vec<E::G2Prepared> = h_vec
        .into_iter()
        .take(num_var)
        .map(E::G2Prepared::from)
        .collect();
    pairings_l.push(E::G1Prepared::from(
        (verifier_param.g * (*value) - commitment.0.into_group()).into_affine(),
    ));
    pairings_r.push(E::G2Prepared::from(verifier_param.h));

    let res = E::multi_pairing(pairings_l, pairings_r).0 == E::TargetField::one();

    end_timer!(pairing_product_timer);
    end_timer!(verify_timer);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::{rand::RngCore, vec::Vec, UniformRand};
    use jf_utils::test_rng;
    type E = Bls12_381;
    type Fr = <E as Pairing>::ScalarField;

    fn test_single_helper<R: RngCore + CryptoRng>(
        params: &(MultilinearUniversalParams<E>, UnivariateUniversalParams<E>),
        poly: &Arc<DenseMultilinearExtension<Fr>>,
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let uni_degree = 1;
        let (ck, vk) = MultilinearKzgPCS::trim(params, uni_degree, Some(nv))?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = MultilinearKzgPCS::commit(&ck, poly)?;
        let (proof, value) = MultilinearKzgPCS::open(&ck, poly, &point)?;

        assert!(MultilinearKzgPCS::verify(
            &vk, &com, &point, &value, &proof
        )?);

        let value = Fr::rand(rng);
        assert!(!MultilinearKzgPCS::verify(
            &vk, &com, &point, &value, &proof
        )?);

        Ok(())
    }

    #[test]
    fn test_single_commit() -> Result<(), PCSError> {
        let mut rng = test_rng();

        let params = MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 10)?;

        // normal polynomials
        let poly1 = Arc::new(DenseMultilinearExtension::rand(8, &mut rng));
        test_single_helper(&params, &poly1, &mut rng)?;

        // single-variate polynomials
        let poly2 = Arc::new(DenseMultilinearExtension::rand(1, &mut rng));
        test_single_helper(&params, &poly2, &mut rng)?;

        Ok(())
    }

    #[test]
    fn setup_commit_verify_constant_polynomial() {
        let mut rng = test_rng();

        // normal polynomials
        assert!(MultilinearKzgPCS::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
    }
}
