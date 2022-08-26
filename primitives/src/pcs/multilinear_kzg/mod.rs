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
    univariate_kzg::KZGUnivariateOpening,
    PCSError, PolynomialCommitmentScheme, StructuredReferenceString,
};
use ark_ec::{
    msm::{FixedBaseMSM, VariableBaseMSM},
    AffineCurve, PairingEngine, ProjectiveCurve,
};
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{
    end_timer, format, marker::PhantomData, rand::RngCore, rc::Rc, start_timer, string::ToString,
    vec, vec::Vec, One, Zero,
};
use batching::{batch_verify_internal, multi_open_internal};
use srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam};
use util::merge_polynomials;

/// KZG Polynomial Commitment Scheme on multilinear polynomials.
pub struct KZGMultilinearPCS<E: PairingEngine> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
/// proof of opening
pub struct Proof<E: PairingEngine> {
    /// Evaluation of quotients
    pub proofs: Vec<E::G1Affine>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
/// proof of batch opening
pub struct BatchProof<E: PairingEngine> {
    /// The actual proof
    pub proof: Proof<E>,
    /// Commitment to q(x):= w(l(x)) where
    /// - `w` is the merged MLE
    /// - `l` is the list of univariate polys that goes through all points
    pub q_x_commit: Commitment<E>,
    /// openings of q(x) at 1, omega, ..., and r
    pub q_x_opens: Vec<KZGUnivariateOpening<E>>,
}

impl<E: PairingEngine> PolynomialCommitmentScheme<E> for KZGMultilinearPCS<E> {
    // Parameters
    type ProverParam = (
        MultilinearProverParam<E>,
        UnivariateProverParam<E::G1Affine>,
    );
    type VerifierParam = (MultilinearVerifierParam<E>, UnivariateVerifierParam<E>);
    type SRS = (MultilinearUniversalParams<E>, UnivariateUniversalParams<E>);
    // Polynomial and its associated types
    type Polynomial = Rc<DenseMultilinearExtension<E::Fr>>;
    type Point = Vec<E::Fr>;
    type Evaluation = E::Fr;
    // Commitments and proofs
    type Commitment = Commitment<E>;
    type BatchCommitment = Commitment<E>;
    type Proof = Proof<E>;
    type BatchProof = BatchProof<E>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `log_size` is the log of maximum degree.
    /// - For multilinear polynomials, `log_size` is the number of variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: RngCore>(
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
        srs: &Self::SRS,
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
        let (uni_ck, uni_vk) = srs.1.trim(supported_log_degree)?;
        let (ml_ck, ml_vk) = srs.0.trim(supported_num_vars)?;

        Ok(((ml_ck, uni_ck), (ml_vk, uni_vk)))
    }

    /// Generate a commitment for a polynomial.
    ///
    /// This function takes `2^num_vars` number of scalar multiplications over
    /// G1.
    fn commit(
        prover_param: &Self::ProverParam,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
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
            .map(|x| x.into_repr())
            .collect();
        let commitment = VariableBaseMSM::multi_scalar_mul(
            &prover_param.0.powers_of_g[ignored].evals,
            scalars.as_slice(),
        )
        .into_affine();

        end_timer!(commit_timer);
        Ok(Commitment(commitment))
    }

    /// Generate a commitment for a list of polynomials.
    ///
    /// This function takes `2^(num_vars + log(polys.len())` number of scalar
    /// multiplications over G1.
    fn multi_commit(
        prover_param: &Self::ProverParam,
        polys: &[Self::Polynomial],
    ) -> Result<Self::Commitment, PCSError> {
        let commit_timer = start_timer!(|| "multi commit");
        let poly = merge_polynomials(polys)?;

        let scalars: Vec<_> = poly
            .to_evaluations()
            .iter()
            .map(|x| x.into_repr())
            .collect();

        let commitment = VariableBaseMSM::multi_scalar_mul(
            &prover_param.0.powers_of_g[0].evals,
            scalars.as_slice(),
        )
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
        prover_param: &Self::ProverParam,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        open_internal(&prover_param.0, polynomial, point)
    }

    /// Input
    /// - the prover parameters for univariate KZG,
    /// - the prover parameters for multilinear KZG,
    /// - a list of MLEs,
    /// - a commitment to all MLEs
    /// - and a same number of points,
    /// compute a multi-opening for all the polynomials.
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
    fn multi_open(
        prover_param: &Self::ProverParam,
        multi_commitment: &Self::Commitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError> {
        multi_open_internal::<E>(
            &prover_param.1,
            &prover_param.0,
            polynomials,
            multi_commitment,
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
        value: &E::Fr,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        verify_internal(&verifier_param.0, commitment, point, value, proof)
    }

    /// Verifies that `value` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    /// steps:
    ///
    /// 1. put `q(x)`'s evaluations over `(1, omega,...)` into transcript
    /// 2. sample `r` from transcript
    /// 3. check `q(r) == value`
    /// 4. build `l(points)` which is a list of univariate polynomials that goes
    /// through the points
    /// 5. get a point `p := l(r)`
    /// 6. verifies `p` is verifies against proof
    fn batch_verify<R: RngCore>(
        verifier_param: &Self::VerifierParam,
        multi_commitment: &Self::BatchCommitment,
        points: &[Self::Point],
        values: &[E::Fr],
        batch_proof: &Self::BatchProof,
        _rng: &mut R,
    ) -> Result<bool, PCSError> {
        batch_verify_internal(
            &verifier_param.1,
            &verifier_param.0,
            multi_commitment,
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
/// This function takes 2^{num_var +1} number of scalar multiplications over
/// G1:
/// - it proceeds with `num_var` number of rounds,
/// - at round i, we compute an MSM for `2^{num_var - i + 1}` number of G2
///   elements.
fn open_internal<E: PairingEngine>(
    prover_param: &MultilinearProverParam<E>,
    polynomial: &DenseMultilinearExtension<E::Fr>,
    point: &[E::Fr],
) -> Result<(Proof<E>, E::Fr), PCSError> {
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
    let ignored = prover_param.num_vars - nv;
    let mut r: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();
    let mut q: Vec<Vec<E::Fr>> = (0..nv + 1).map(|_| Vec::new()).collect();

    r[nv] = polynomial.to_evaluations();

    let mut proofs = Vec::new();

    for (i, (&point_at_k, gi)) in point
        .iter()
        .zip(prover_param.powers_of_g[ignored..].iter())
        .take(nv)
        .enumerate()
    {
        let ith_round = start_timer!(|| format!("{}-th round", i));

        let k = nv - i;
        let cur_dim = 1 << (k - 1);
        let mut cur_q = vec![E::Fr::zero(); cur_dim];
        let mut cur_r = vec![E::Fr::zero(); cur_dim];

        for b in 0..(1 << (k - 1)) {
            // q_b = pre_r [2^b + 1] - pre_r [2^b]
            cur_q[b] = r[k][(b << 1) + 1] - r[k][b << 1];

            // r_b = pre_r [2^b]*(1-p) + pre_r [2^b + 1] * p
            cur_r[b] =
                r[k][b << 1] * (E::Fr::one() - point_at_k) + (r[k][(b << 1) + 1] * point_at_k);
        }

        let scalars: Vec<_> = (0..(1 << k)).map(|x| cur_q[x >> 1].into_repr()).collect();

        q[k] = cur_q;
        r[k - 1] = cur_r;

        // this is a MSM over G1 and is likely to be the bottleneck
        proofs.push(VariableBaseMSM::multi_scalar_mul(&gi.evals, &scalars).into_affine());
        end_timer!(ith_round);
    }
    let eval = polynomial.evaluate(point).ok_or_else(|| {
        PCSError::InvalidParameters("fail to evaluate the polynomial".to_string())
    })?;
    end_timer!(open_timer);
    Ok((Proof { proofs }, eval))
}

/// Verifies that `value` is the evaluation at `x` of the polynomial
/// committed inside `comm`.
///
/// This function takes
/// - num_var number of pairing product.
/// - num_var number of MSM
fn verify_internal<E: PairingEngine>(
    verifier_param: &MultilinearVerifierParam<E>,
    commitment: &Commitment<E>,
    point: &[E::Fr],
    value: &E::Fr,
    proof: &Proof<E>,
) -> Result<bool, PCSError> {
    let verify_timer = start_timer!(|| "verify");
    let num_var = point.len();

    if num_var > verifier_param.num_vars {
        return Err(PCSError::InvalidParameters(format!(
            "point length ({}) exceeds param limit ({})",
            num_var, verifier_param.num_vars
        )));
    }

    let ignored = verifier_param.num_vars - num_var;
    let prepare_inputs_timer = start_timer!(|| "prepare pairing inputs");

    let scalar_size = E::Fr::size_in_bits();
    let window_size = FixedBaseMSM::get_mul_window_size(num_var);

    let h_table = FixedBaseMSM::get_window_table(
        scalar_size,
        window_size,
        verifier_param.h.into_projective(),
    );
    let h_mul: Vec<E::G2Projective> =
        FixedBaseMSM::multi_scalar_mul(scalar_size, window_size, &h_table, point);

    let h_vec: Vec<_> = (0..num_var)
        .map(|i| verifier_param.h_mask[ignored + i].into_projective() - h_mul[i])
        .collect();
    let h_vec: Vec<E::G2Affine> = E::G2Projective::batch_normalization_into_affine(&h_vec);
    end_timer!(prepare_inputs_timer);

    let pairing_product_timer = start_timer!(|| "pairing product");

    let mut pairings: Vec<_> = proof
        .proofs
        .iter()
        .map(|&x| E::G1Prepared::from(x))
        .zip(h_vec.into_iter().take(num_var).map(E::G2Prepared::from))
        .collect();

    pairings.push((
        E::G1Prepared::from(
            (verifier_param.g.mul(*value) - commitment.0.into_projective()).into_affine(),
        ),
        E::G2Prepared::from(verifier_param.h),
    ));

    let res = E::product_of_pairings(pairings.iter()) == E::Fqk::one();

    end_timer!(pairing_product_timer);
    end_timer!(verify_timer);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::PairingEngine;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::{rand::RngCore, test_rng, vec::Vec, UniformRand};
    type E = Bls12_381;
    type Fr = <E as PairingEngine>::Fr;

    fn test_single_helper<R: RngCore>(
        params: &(MultilinearUniversalParams<E>, UnivariateUniversalParams<E>),
        poly: &Rc<DenseMultilinearExtension<Fr>>,
        rng: &mut R,
    ) -> Result<(), PCSError> {
        let nv = poly.num_vars();
        assert_ne!(nv, 0);
        let uni_degree = 1;
        let (ck, vk) = KZGMultilinearPCS::trim(params, uni_degree, Some(nv + 1))?;
        let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
        let com = KZGMultilinearPCS::commit(&ck, poly)?;
        let (proof, value) = KZGMultilinearPCS::open(&ck, poly, &point)?;

        assert!(KZGMultilinearPCS::verify(
            &vk, &com, &point, &value, &proof
        )?);

        let value = Fr::rand(rng);
        assert!(!KZGMultilinearPCS::verify(
            &vk, &com, &point, &value, &proof
        )?);

        Ok(())
    }

    #[test]
    fn test_single_commit() -> Result<(), PCSError> {
        let mut rng = test_rng();

        let params = KZGMultilinearPCS::<E>::gen_srs_for_testing(&mut rng, 10)?;

        // normal polynomials
        let poly1 = Rc::new(DenseMultilinearExtension::rand(8, &mut rng));
        test_single_helper(&params, &poly1, &mut rng)?;

        // single-variate polynomials
        let poly2 = Rc::new(DenseMultilinearExtension::rand(1, &mut rng));
        test_single_helper(&params, &poly2, &mut rng)?;

        Ok(())
    }

    #[test]
    fn setup_commit_verify_constant_polynomial() {
        let mut rng = test_rng();

        // normal polynomials
        assert!(KZGMultilinearPCS::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
    }
}
