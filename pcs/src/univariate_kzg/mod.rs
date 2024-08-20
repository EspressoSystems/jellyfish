// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Main module for univariate KZG commitment scheme

use crate::{
    poly::GeneralDensePolynomial, prelude::Commitment, toeplitz::ToeplitzMatrix, PCSError,
    PolynomialCommitmentScheme, StructuredReferenceString, UnivariatePCS,
};
use ark_ec::{
    pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr, CurveGroup,
};
use ark_ff::{FftField, Field, PrimeField};
#[cfg(not(feature = "seq-fk-23"))]
use ark_poly::EvaluationDomain;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, Polynomial, Radix2EvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    end_timer, format,
    marker::PhantomData,
    ops::Mul,
    rand::{CryptoRng, RngCore},
    start_timer,
    string::ToString,
    vec,
    vec::Vec,
    One, UniformRand, Zero,
};
use core::any::TypeId;
use jf_utils::par_utils::parallelizable_slice_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use srs::{UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam};

pub(crate) mod srs;
#[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
mod succinct;

/// KZG Polynomial Commitment Scheme on univariate polynomial.
pub struct UnivariateKzgPCS<E> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
#[derivative(Hash)]
/// proof of opening
pub struct UnivariateKzgProof<E: Pairing> {
    /// Evaluation of quotients
    pub proof: E::G1Affine,
}
/// batch proof
pub type UnivariateKzgBatchProof<E> = Vec<UnivariateKzgProof<E>>;

impl<E: Pairing> PolynomialCommitmentScheme for UnivariateKzgPCS<E> {
    // Config
    type SRS = UnivariateUniversalParams<E>;
    // Polynomial and its associated types
    type Polynomial = DensePolynomial<E::ScalarField>;
    type Point = E::ScalarField;
    type Evaluation = E::ScalarField;
    // Polynomial and its associated types
    type Commitment = Commitment<E>;
    type BatchCommitment = Vec<Self::Commitment>;
    type Proof = UnivariateKzgProof<E>;
    type BatchProof = UnivariateKzgBatchProof<E>;

    /// Trim the universal parameters to specialize the public parameters.
    /// Input `max_degree` for univariate.
    /// `supported_num_vars` must be None or an error is returned.
    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: usize,
        supported_num_vars: Option<usize>,
    ) -> Result<(UnivariateProverParam<E>, UnivariateVerifierParam<E>), PCSError> {
        if supported_num_vars.is_some() {
            return Err(PCSError::InvalidParameters(
                "univariate should not receive a num_var param".to_string(),
            ));
        }
        srs.borrow().trim(supported_degree)
    }

    /// Generate a commitment for a polynomial
    /// Note that the scheme is not hiding
    fn commit(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();

        #[cfg(feature = "kzg-print-trace")]
        let commit_time =
            start_timer!(|| format!("Committing to polynomial of degree {} ", poly.degree()));

        if poly.degree() > prover_param.powers_of_g.len() {
            return Err(PCSError::InvalidParameters(format!(
                "poly degree {} is larger than allowed {}",
                poly.degree(),
                prover_param.powers_of_g.len()
            )));
        }

        #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
        if TypeId::of::<E>() == TypeId::of::<ark_bn254::Bn254>() {
            let points = &prover_param.powers_of_g as _ as &[ark_bn254::G1Affine];
            let scalars = poly.coeffs() as _ as &[ark_bn254::Fr];
            let commitment = succinct::msm(points, scalars);
            return Ok(Commitment(commitment));
        }
        let (num_leading_zeros, plain_coeffs) = skip_leading_zeros_and_convert_to_bigints(poly);

        #[cfg(feature = "kzg-print-trace")]
        let msm_time = start_timer!(|| "MSM to compute commitment to plaintext
        poly");

        let commitment = E::G1::msm_bigint(
            &prover_param.powers_of_g[num_leading_zeros..],
            &plain_coeffs,
        )
        .into_affine();

        #[cfg(feature = "kzg-print-trace")]
        end_timer!(msm_time);
        #[cfg(feature = "kzg-print-trace")]
        end_timer!(commit_time);
        Ok(Commitment(commitment))
    }

    /// Generate a commitment for a list of polynomials
    fn batch_commit(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        polys: &[Self::Polynomial],
    ) -> Result<Self::BatchCommitment, PCSError> {
        let prover_param = prover_param.borrow();
        let commit_time = start_timer!(|| format!("batch commit {} polynomials", polys.len()));
        let res = parallelizable_slice_iter(polys)
            .map(|poly| Self::commit(prover_param, poly))
            .collect::<Result<Vec<Self::Commitment>, PCSError>>()?;

        end_timer!(commit_time);
        Ok(res)
    }

    /// On input a polynomial `p` and a point `point`, outputs a proof for the
    /// same.
    fn open(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        #[cfg(feature = "kzg-print-trace")]
        let open_time =
            start_timer!(|| format!("Opening polynomial of degree {}", polynomial.degree()));

        let divisor = Self::Polynomial::from_coefficients_vec(vec![-*point, E::ScalarField::one()]);

        #[cfg(feature = "kzg-print-trace")]
        let witness_time = start_timer!(|| "Computing witness polynomial");

        let witness_polynomial = polynomial / &divisor;

        #[cfg(feature = "kzg-print-trace")]
        end_timer!(witness_time);

        let (num_leading_zeros, witness_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);

        let proof: E::G1Affine = E::G1::msm_bigint(
            &prover_param.borrow().powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        )
        .into_affine();

        // TODO offer an `open()` that doesn't also evaluate
        // https://github.com/EspressoSystems/jellyfish/issues/426
        let eval = polynomial.evaluate(point);

        #[cfg(feature = "kzg-print-trace")]
        end_timer!(open_time);

        Ok((Self::Proof { proof }, eval))
    }

    /// Input a list of polynomials, and a same number of points,
    /// compute a multi-opening for all the polynomials.
    // This is a naive approach
    // TODO: to implement the more efficient batch opening algorithm
    // (e.g., the appendix C.4 in https://eprint.iacr.org/2020/1536.pdf)
    fn batch_open(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        _multi_commitment: &Self::BatchCommitment,
        polynomials: &[Self::Polynomial],
        points: &[Self::Point],
    ) -> Result<(Self::BatchProof, Vec<Self::Evaluation>), PCSError> {
        let open_time = start_timer!(|| format!("batch opening {} polynomials", polynomials.len()));
        if polynomials.len() != points.len() {
            return Err(PCSError::InvalidParameters(format!(
                "poly length {} is different from points length {}",
                polynomials.len(),
                points.len()
            )));
        }
        let mut batch_proof = vec![];
        let mut evals = vec![];
        for (poly, point) in polynomials.iter().zip(points.iter()) {
            let (proof, eval) = Self::open(prover_param.borrow(), poly, point)?;
            batch_proof.push(proof);
            evals.push(eval);
        }

        end_timer!(open_time);
        Ok((batch_proof, evals))
    }
    /// Verifies that `value` is the evaluation at `x` of the polynomial
    /// committed inside `comm`.
    fn verify(
        verifier_param: &UnivariateVerifierParam<E>,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        let check_time = start_timer!(|| "Checking evaluation");
        let pairing_inputs_l: Vec<E::G1Prepared> = vec![
            (verifier_param.g * value - proof.proof * point - commitment.0.into_group())
                .into_affine()
                .into(),
            proof.proof.into(),
        ];
        let pairing_inputs_r: Vec<E::G2Prepared> =
            vec![verifier_param.h.into(), verifier_param.beta_h.into()];

        let res = E::multi_pairing(pairing_inputs_l, pairing_inputs_r)
            .0
            .is_one();

        end_timer!(check_time, || format!("Result: {res}"));
        Ok(res)
    }

    /// Verifies that `value_i` is the evaluation at `x_i` of the polynomial
    /// `poly_i` committed inside `comm`.
    // This is a naive approach
    // TODO: to implement the more efficient batch verification algorithm
    // (e.g., the appendix C.4 in https://eprint.iacr.org/2020/1536.pdf)
    fn batch_verify<R: RngCore + CryptoRng>(
        verifier_param: &UnivariateVerifierParam<E>,
        multi_commitment: &Self::BatchCommitment,
        points: &[Self::Point],
        values: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        rng: &mut R,
    ) -> Result<bool, PCSError> {
        let check_time =
            start_timer!(|| format!("Checking {} evaluation proofs", multi_commitment.len()));

        let mut total_c = <E::G1>::zero();
        let mut total_w = <E::G1>::zero();

        let combination_time = start_timer!(|| "Combining commitments and proofs");
        let mut randomizer = E::ScalarField::one();
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = E::ScalarField::zero();
        for (((c, z), v), proof) in multi_commitment
            .iter()
            .zip(points)
            .zip(values)
            .zip(batch_proof)
        {
            let w = proof.proof;
            let mut temp = w.mul(*z);
            temp += &c.0;
            let c = temp;
            g_multiplier += &(randomizer * v);
            total_c += c * randomizer;
            total_w += w * randomizer;
            // We don't need to sample randomizers from the full field,
            // only from 128-bit strings.
            randomizer = u128::rand(rng).into();
        }
        total_c -= &verifier_param.g.mul(g_multiplier);
        end_timer!(combination_time);

        let to_affine_time = start_timer!(|| "Converting results to affine for pairing");
        let affine_points = E::G1::normalize_batch(&[-total_w, total_c]);
        let (total_w, total_c) = (affine_points[0], affine_points[1]);
        end_timer!(to_affine_time);

        let pairing_time = start_timer!(|| "Performing product of pairings");
        let result = E::multi_pairing(
            [total_w, total_c],
            [verifier_param.beta_h, verifier_param.h],
        )
        .0
        .is_one();
        end_timer!(pairing_time);
        end_timer!(check_time, || format!("Result: {result}"));
        Ok(result)
    }

    /// Fast computation of batch opening for a single polynomial at multiple
    /// arbitrary points.
    /// Details see Sec 2.1~2.3 of [FK23](https://eprint.iacr.org/2023/033.pdf).
    ///
    /// Only accept `polynomial` with power-of-two degree, no constraint on the
    /// size of `points`
    fn multi_open(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        polynomial: &Self::Polynomial,
        points: &[Self::Point],
    ) -> Result<(Vec<Self::Proof>, Vec<Self::Evaluation>), PCSError> {
        let h_poly = Self::compute_h_poly_in_fk23(prover_param, &polynomial.coeffs)?;
        let proofs: Vec<_> = h_poly
            .batch_evaluate(points)
            .into_iter()
            .map(|g| UnivariateKzgProof {
                proof: g.into_affine(),
            })
            .collect();

        // Evaluate at all points
        let evals =
            GeneralDensePolynomial::from_coeff_slice(&polynomial.coeffs).batch_evaluate(points);
        Ok((proofs, evals))
    }
}

impl<E: Pairing> UnivariatePCS for UnivariateKzgPCS<E> {
    fn multi_open_rou_proofs(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        num_points: usize,
        domain: &Radix2EvaluationDomain<Self::Evaluation>,
    ) -> Result<Vec<Self::Proof>, PCSError> {
        #[cfg(not(feature = "seq-fk-23"))]
        {
            let h_poly_timer = start_timer!(|| "compute h_poly");
            let h_poly = Self::compute_h_poly_parallel(prover_param, &polynomial.coeffs)?;
            end_timer!(h_poly_timer);
            let small_domain: Radix2EvaluationDomain<Self::Evaluation> =
                Radix2EvaluationDomain::new(h_poly.degree() + 1).ok_or_else(|| {
                    PCSError::InvalidParameters(format!(
                        "failed to create a domain of size {}",
                        h_poly.degree() + 1,
                    ))
                })?;
            let parallel_factor = domain.size() / small_domain.size();

            let mut offsets = Vec::with_capacity(parallel_factor);
            offsets.push(Self::Evaluation::one());
            for _ in 1..parallel_factor {
                offsets.push(domain.group_gen() * offsets.last().unwrap());
            }
            let proofs_timer = start_timer!(|| format!(
                "gen eval proofs with parallel_factor {} and num_points {}",
                parallel_factor, num_points,
            ));
            let proofs: Vec<Vec<_>> = parallelizable_slice_iter(&offsets)
                .map(|&offset| {
                    small_domain
                        .get_coset(offset)
                        .unwrap()
                        .fft(&h_poly.coeffs[..])
                })
                .collect();
            end_timer!(proofs_timer);
            let mut res = vec![];
            for j in 0..small_domain.size() {
                for proof in proofs.iter() {
                    res.push(UnivariateKzgProof {
                        proof: proof[j].into_affine(),
                    });
                }
            }
            res = res.into_iter().take(num_points).collect();
            Ok(res)
        }

        #[cfg(feature = "seq-fk-23")]
        {
            let h_poly_timer = start_timer!(|| "compute h_poly");
            let mut h_poly = Self::compute_h_poly_in_fk23(prover_param, &polynomial.coeffs)?;
            end_timer!(h_poly_timer);
            let proofs_timer = start_timer!(|| "gen eval proofs");
            let proofs: Vec<_> = h_poly
                .batch_evaluate_rou(domain)?
                .into_iter()
                .take(num_points)
                .map(|g| UnivariateKzgProof {
                    proof: g.into_affine(),
                })
                .collect();
            end_timer!(proofs_timer);
            Ok(proofs)
        }
    }

    /// Compute the evaluations in [`Self::multi_open_rou()`].
    fn multi_open_rou_evals(
        polynomial: &Self::Polynomial,
        num_points: usize,
        domain: &Radix2EvaluationDomain<Self::Evaluation>,
    ) -> Result<Vec<Self::Evaluation>, PCSError> {
        let evals = GeneralDensePolynomial::from_coeff_slice(&polynomial.coeffs)
            .batch_evaluate_rou(domain)?
            .into_iter()
            .take(num_points)
            .collect();
        Ok(evals)
    }

    /// Input a polynomial, and multiple evaluation points,
    /// compute a batch opening proof for the multiple points of the same
    /// polynomial.
    ///
    /// Warning: don't use it when `points.len()` is large
    fn multi_point_open(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        points: &[Self::Point],
    ) -> Result<(Self::Proof, Vec<Self::Evaluation>), PCSError> {
        if points.is_empty() {
            return Err(PCSError::InvalidParameters(
                "no point to evaluate and open".to_string(),
            ));
        }
        let open_time = start_timer!(|| format!(
            "Opening polynomial of degree {} at {} points",
            polynomial.degree(),
            points.len()
        ));

        let evals_time = start_timer!(|| "Computing polynomial evaluations");
        let evals: Vec<Self::Evaluation> = points
            .iter()
            .map(|point| polynomial.evaluate(point))
            .collect();
        end_timer!(evals_time);

        // Compute the polynomial \prod_i (X-point_i)
        // O(|points|^2) complexity and we assume the number of points is small
        // TODO: optimize complexity if support large number of points
        // https://github.com/EspressoSystems/jellyfish/issues/436
        let vanish_poly =
            Self::Polynomial::from_coefficients_vec(vec![-points[0], E::ScalarField::one()]);
        let divisor: Self::Polynomial = points.iter().skip(1).fold(vanish_poly, |acc, point| {
            &acc * &Self::Polynomial::from_coefficients_vec(vec![-*point, E::ScalarField::one()])
        });

        // Compute quotient poly
        // Quadratic complexity as Arkworks is using naive long division
        // TODO: using FFTs for division
        // https://github.com/EspressoSystems/jellyfish/issues/436
        let witness_time = start_timer!(|| "Computing witness polynomial");
        let witness_polynomial = polynomial / &divisor;
        end_timer!(witness_time);

        let (num_leading_zeros, witness_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);

        let proof: E::G1Affine = E::G1::msm_bigint(
            &prover_param.borrow().powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        )
        .into_affine();

        end_timer!(open_time);
        Ok((Self::Proof { proof }, evals))
    }

    /// Verifies that `values` are the evaluation at the `points` of the
    /// polynomial committed inside `comm`.
    ///
    /// Warning: don't use it when `points.len()` is large
    fn multi_point_verify(
        verifier_param: impl Borrow<<Self::SRS as StructuredReferenceString>::VerifierParam>,
        commitment: &Self::Commitment,
        points: &[Self::Point],
        values: &[Self::Evaluation],
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        if points.is_empty() {
            return Err(PCSError::InvalidParameters(
                "no evaluation to check".to_string(),
            ));
        }
        if points.len() != values.len() {
            return Err(PCSError::InvalidParameters(format!(
                "the number of points {} is different from the number of evaluation values {}",
                points.len(),
                values.len(),
            )));
        }
        if verifier_param.borrow().powers_of_h.len() < points.len() + 1 {
            return Err(PCSError::InvalidParameters(format!(
                "the number of powers of beta times h {} in SRS <= the number of evaluation points {}",
                verifier_param.borrow().powers_of_h.len(),
                points.len(),
            )));
        }

        let check_time = start_timer!(|| "Checking evaluations");

        // Compute the commitment to I(X) = sum_i eval_i * L_{point_i}(X)
        // O(|points|^2) complexity and we assume the number of points is small
        // TODO: optimize complexity if support large number of points
        // https://github.com/EspressoSystems/jellyfish/issues/436
        let evals_poly = values
            .iter()
            .enumerate()
            .fold(Self::Polynomial::zero(), |acc, (i, &value)| {
                acc + lagrange_poly(points, i, value)
            });

        let (num_leading_zeros, evals_poly_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&evals_poly);

        let evals_cm: E::G1Affine = E::G1::msm_bigint(
            &verifier_param.borrow().powers_of_g[num_leading_zeros..],
            &evals_poly_coeffs,
        )
        .into_affine();

        // Compute the commitment to Z(X) = prod_i (X-point_i)
        // O(|points|^2) complexity and we assume the number of points is small
        // TODO: optimize complexity if support large number of points
        // https://github.com/EspressoSystems/jellyfish/issues/436
        let vanish_poly =
            Self::Polynomial::from_coefficients_vec(vec![-points[0], E::ScalarField::one()]);
        let vanish_poly: Self::Polynomial =
            points.iter().skip(1).fold(vanish_poly, |acc, point| {
                &acc * &Self::Polynomial::from_coefficients_vec(vec![
                    -*point,
                    E::ScalarField::one(),
                ])
            });

        let (num_leading_zeros, vanish_poly_coeffs) =
            skip_leading_zeros_and_convert_to_bigints(&vanish_poly);

        let vanish_cm: E::G2Affine = E::G2::msm_bigint(
            &verifier_param.borrow().powers_of_h[num_leading_zeros..],
            &vanish_poly_coeffs,
        )
        .into_affine();

        // Check the pairing
        let pairing_inputs_l: Vec<E::G1Prepared> = vec![
            (evals_cm.into_group() - commitment.0.into_group())
                .into_affine()
                .into(),
            proof.proof.into(),
        ];
        let pairing_inputs_r: Vec<E::G2Prepared> =
            vec![verifier_param.borrow().h.into(), vanish_cm.into()];

        let res = E::multi_pairing(pairing_inputs_l, pairing_inputs_r)
            .0
            .is_one();

        end_timer!(check_time, || format!("Result: {res}"));
        Ok(res)
    }
}

impl<E, F> UnivariateKzgPCS<E>
where
    E: Pairing<ScalarField = F>,
    F: FftField,
{
    // Computes h_poly as the matrix-vector product on page 3 of https://eprint.iacr.org/2023/033.pdf via naive row-column inner products in parallel
    #[cfg(not(feature = "seq-fk-23"))]
    fn compute_h_poly_parallel(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        poly_coeffs: &[E::ScalarField],
    ) -> Result<GeneralDensePolynomial<E::G1, F>, PCSError> {
        if poly_coeffs.is_empty() {
            return Ok(GeneralDensePolynomial::from_coeff_vec(vec![]));
        }
        let h_poly_deg = poly_coeffs.len() - 1;
        let srs_vec: Vec<E::G1Affine> = prover_param
            .borrow()
            .powers_of_g
            .iter()
            .take(h_poly_deg)
            .rev()
            .cloned()
            .collect();

        let matrix: Vec<Vec<E::ScalarField>> = (0..h_poly_deg)
            .map(|i| {
                poly_coeffs
                    .iter()
                    .rev()
                    .take(h_poly_deg - i)
                    .copied()
                    .collect()
            })
            .collect();
        let h_vec: Vec<E::G1> = parallelizable_slice_iter(&matrix)
            .map(|coeffs| E::G1::msm(&srs_vec[h_poly_deg - coeffs.len()..], &coeffs[..]).unwrap())
            .collect();
        Ok(GeneralDensePolynomial::from_coeff_vec(h_vec))
    }

    // Sec 2.2. of <https://eprint.iacr.org/2023/033>
    fn compute_h_poly_in_fk23(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        poly_coeffs: &[E::ScalarField],
    ) -> Result<GeneralDensePolynomial<E::G1, F>, PCSError> {
        // First, pad to power_of_two, since Toeplitz mul only works for 2^k
        let mut padded_coeffs: Vec<F> = poly_coeffs.to_vec();
        let padded_degree = padded_coeffs
            .len()
            .saturating_sub(1)
            .checked_next_power_of_two()
            .ok_or_else(|| {
                PCSError::InvalidParameters(ark_std::format!(
                    "Next power of two overflows! Got: {}",
                    padded_coeffs.len().saturating_sub(1)
                ))
            })?;
        let padded_len = padded_degree + 1;
        padded_coeffs.resize(padded_len, F::zero());

        // Step 1. compute \vec{h} using fast Toeplitz matrix multiplication
        // 1.1 Toeplitz matrix A (named `poly_coeff_matrix` here)
        let mut toep_col = vec![*padded_coeffs
            .last()
            .ok_or_else(|| PCSError::InvalidParameters("poly degree should >= 1".to_string()))?];
        toep_col.resize(padded_degree, <<E as Pairing>::ScalarField as Field>::ZERO);
        let toep_row = padded_coeffs.iter().skip(1).rev().cloned().collect();
        let poly_coeff_matrix = ToeplitzMatrix::new(toep_col, toep_row)?;

        // 1.2 vector s (named `srs_vec` here)
        let srs_vec: Vec<E::G1> = prover_param
            .borrow()
            .powers_of_g
            .iter()
            .take(padded_degree)
            .rev()
            .cloned()
            .map(|g| g.into_group())
            .collect();

        // 1.3 compute \vec{h}
        let h_vec = poly_coeff_matrix.fast_vec_mul(&srs_vec)?;

        Ok(GeneralDensePolynomial::from_coeff_vec(h_vec))
    }
}

#[cfg(feature = "icicle")]
pub(crate) mod icicle {
    use super::*;
    use crate::icicle_deps::{curves::*, *};
    use itertools::Itertools;

    /// Trait for GPU-accelerated PCS.commit APIs
    pub trait GPUCommittable<E: Pairing> {
        /// Equivalent Curve from ICICLE
        type IC: IcicleCurve + MSM<Self::IC>;

        /// The full cycle of computing poly-commit on GPU
        fn gpu_commit(
            prover_param: impl Borrow<UnivariateProverParam<E>>,
            poly: &DensePolynomial<E::ScalarField>,
        ) -> Result<Commitment<E>, PCSError> {
            let stream = warmup_new_stream().unwrap();

            #[cfg(feature = "kzg-print-trace")]
            let commit_time =
                start_timer!(|| format!("Committing to polynomial of degree {} ", poly.degree()));

            let mut srs_on_gpu = Self::load_prover_param_to_gpu(prover_param, poly.degree())?;
            let comm = Self::gpu_commit_with_loaded_prover_param(&mut srs_on_gpu, poly, &stream)?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(commit_time);

            Ok(comm)
        }

        /// Compute `PCS::commit()` with SRS already loaded on GPU
        /// Return the commitment on CPU
        ///
        /// # NOTE
        /// - we assume a stream is already prepared, you can create one if not
        /// via `warmup_new_stream()`
        fn gpu_commit_with_loaded_prover_param(
            prover_param_on_gpu: &mut HostOrDeviceSlice<'_, IcicleAffine<Self::IC>>,
            poly: &DensePolynomial<E::ScalarField>,
            stream: &CudaStream,
        ) -> Result<Commitment<E>, PCSError> {
            let poly_on_gpu = Self::load_poly_to_gpu(poly)?;
            let msm_result_on_gpu =
                Self::commit_on_gpu(prover_param_on_gpu, &poly_on_gpu, 1, stream)?;
            let comm = Self::load_commitments_to_host(msm_result_on_gpu, stream)?[0];

            Ok(comm)
        }

        /// Similar to [`Self::gpu_commit()`] but for a batch of polys
        fn gpu_batch_commit(
            prover_param: impl Borrow<UnivariateProverParam<E>>,
            polys: &[DensePolynomial<E::ScalarField>],
        ) -> Result<Vec<Commitment<E>>, PCSError> {
            if polys.len() == 0 {
                return Ok(vec![]);
            }

            let stream = warmup_new_stream().unwrap();

            let degree = polys.iter().map(|poly| poly.degree()).max().unwrap_or(0);

            #[cfg(feature = "kzg-print-trace")]
            let commit_time = start_timer!(|| format!(
                "Committing to {} polys of degree {} ",
                polys.len(),
                degree,
            ));
            let mut srs_on_gpu = Self::load_prover_param_to_gpu(prover_param, degree)?;
            let comms =
                Self::gpu_batch_commit_with_loaded_prover_param(&mut srs_on_gpu, polys, &stream)?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(commit_time);

            Ok(comms)
        }

        /// Compute `PCS::commit()` with SRS already loaded on GPU
        /// Return a vector of commitments on CPU
        fn gpu_batch_commit_with_loaded_prover_param(
            prover_param_on_gpu: &mut HostOrDeviceSlice<'_, IcicleAffine<Self::IC>>,
            polys: &[DensePolynomial<E::ScalarField>],
            stream: &CudaStream,
        ) -> Result<Vec<Commitment<E>>, PCSError> {
            if polys.len() == 0 {
                return Ok(vec![]);
            }

            let poly_on_gpu = Self::load_batch_poly_to_gpu(polys)?;
            let msm_result_on_gpu =
                Self::commit_on_gpu(prover_param_on_gpu, &poly_on_gpu, polys.len(), stream)?;
            let comms = Self::load_commitments_to_host(msm_result_on_gpu, stream)?;

            Ok(comms)
        }

        /// type conversion (specializable/overridable for concrete types) from
        /// field in arkworks to icicle
        ///
        /// # NOTE
        /// returned icicle field is in normal affine (not montgomery) form
        fn ark_field_to_icicle(f: E::ScalarField) -> <Self::IC as IcicleCurve>::ScalarField;

        /// type conversion (specializable/overridable for concrete types) from
        /// affine point in arkworks to icicle
        ///
        /// # NOTE
        /// returned icicle field is in normal affine (not montgomery) form
        fn ark_affine_to_icicle(p: E::G1Affine) -> IcicleAffine<Self::IC>;

        /// type conversion from icicle Projective to arkworks' G1Affine
        fn icicle_projective_to_ark(p: IcicleProjective<Self::IC>) -> E::G1Affine;

        /// load SRS for prover onto GPU once, and reuse for future poly-commit
        /// of degree<=`supported_degree`
        fn load_prover_param_to_gpu<'srs>(
            prover_param: impl Borrow<UnivariateProverParam<E>>,
            supported_degree: usize,
        ) -> Result<HostOrDeviceSlice<'srs, IcicleAffine<Self::IC>>, PCSError> {
            let prover_param = prover_param.borrow();
            if supported_degree > prover_param.powers_of_g.len() - 1 {
                return Err(PCSError::InvalidParameters(format!(
                    "supported degree {} is larger than allowed {}",
                    supported_degree,
                    prover_param.powers_of_g.len() - 1
                )));
            }

            let mut bases_on_device =
                HostOrDeviceSlice::<'_, IcicleAffine<Self::IC>>::cuda_malloc(supported_degree + 1)?;

            #[cfg(feature = "kzg-print-trace")]
            let conv_time = start_timer!(|| "Type Conversion: ark->ICICLE: Group");
            let bases: Vec<IcicleAffine<Self::IC>> = prover_param.powers_of_g
                [..supported_degree + 1]
                .par_iter()
                .map(|&p| Self::ark_affine_to_icicle(p))
                .collect();
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(conv_time);

            #[cfg(feature = "kzg-print-trace")]
            let load_time = start_timer!(|| "Load group elements: CPU->GPU");
            bases_on_device.copy_from_host(&bases)?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(load_time);

            Ok(bases_on_device)
        }

        /// Load polynomial's coefficients onto GPU, preparing for poly-commit
        /// on GPU later
        fn load_poly_to_gpu<'poly>(
            poly: &DensePolynomial<E::ScalarField>,
        ) -> Result<HostOrDeviceSlice<'poly, <Self::IC as IcicleCurve>::ScalarField>, PCSError>
        {
            let size = poly.degree() + 1;
            let mut scalars_on_device =
                HostOrDeviceSlice::<'_, <Self::IC as IcicleCurve>::ScalarField>::cuda_malloc(size)?;

            #[cfg(feature = "kzg-print-trace")]
            let conv_time = start_timer!(|| "Type Conversion: ark->ICICLE: Scalar");
            // We assume that two types use the same underline repr.
            let scalars = unsafe {
                poly.coeffs()[..size]
                    .align_to::<<Self::IC as IcicleCurve>::ScalarField>()
                    .1
            };
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(conv_time);

            #[cfg(feature = "kzg-print-trace")]
            let load_time = start_timer!(|| "Load scalars: CPU->GPU");
            scalars_on_device.copy_from_host(scalars)?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(load_time);

            Ok(scalars_on_device)
        }

        /// Similar to [`Self::load_poly_to_gpu()`] but handling a batch of
        /// polys at once
        fn load_batch_poly_to_gpu<'poly>(
            polys: &[DensePolynomial<E::ScalarField>],
        ) -> Result<HostOrDeviceSlice<'poly, <Self::IC as IcicleCurve>::ScalarField>, PCSError>
        {
            if polys.is_empty() {
                return Err(PCSError::InvalidParameters(
                    "number of polys must be positive".to_string(),
                ));
            }

            let num_coeffs = polys
                .iter()
                .map(|poly| poly.degree() + 1)
                .max()
                .unwrap_or(1);

            let mut scalars_on_device = HostOrDeviceSlice::<
                '_,
                <Self::IC as IcicleCurve>::ScalarField,
            >::cuda_malloc(num_coeffs * polys.len())?;

            #[cfg(feature = "kzg-print-trace")]
            let conv_time = start_timer!(|| "Type Conversion: ark->ICICLE: Scalar");
            let zero_for_padding = E::ScalarField::zero();
            let scalars: Vec<<Self::IC as IcicleCurve>::ScalarField> = polys
                .iter()
                .flat_map(|poly| {
                    poly.coeffs()
                        .iter()
                        .pad_using(num_coeffs, |_| &zero_for_padding)
                })
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|&s| Self::ark_field_to_icicle(s))
                .collect();
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(conv_time);

            #[cfg(feature = "kzg-print-trace")]
            let load_time = start_timer!(|| "Load scalars: CPU->GPU");
            scalars_on_device.copy_from_host(&scalars)?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(load_time);

            Ok(scalars_on_device)
        }

        /// Comupte PCS commit using GPU
        /// Similar to [`Self::commit()`] but with ICICE's GPU-accelerated MSM
        ///
        /// - `stream` is a `CudaStream`, you should consider using
        /// `crate::icicle_deps::warmup_new_stream()` to create one
        /// - `batch_size`: by default is 1, during batch_commit it could be
        ///   greater
        ///
        /// # NOTE
        /// - if you pass in `HostOrDeviceSlice::Host`, then `icicle_core::msm`
        ///   will push them onto GPU first; if they are already on GPU, i.e.
        ///   `HostOrDeviceSlice::Device`, then msm will be executed directly
        /// - the result is also temporarily on GPU, you can use
        ///   `Self::load_commitments_to_host()` to load back to host CPU.
        /// - this function is async/non-blocking, thus returns a CudaStream
        ///   handle
        /// - default implementation assume normal(non-montgomery) affine for
        ///   bases and scalars, consider overwrite this function if you want
        ///   otherwise
        fn commit_on_gpu<'comm>(
            prover_param: &mut HostOrDeviceSlice<'_, IcicleAffine<Self::IC>>,
            poly: &HostOrDeviceSlice<'_, <Self::IC as IcicleCurve>::ScalarField>,
            batch_size: usize,
            stream: &CudaStream,
        ) -> Result<HostOrDeviceSlice<'comm, IcicleProjective<Self::IC>>, PCSError> {
            let trimmed_prover_param = match prover_param {
                HostOrDeviceSlice::Device(ck, device_id) => {
                    HostOrDeviceSlice::Device(&mut ck[..poly.len()], *device_id)
                },
                HostOrDeviceSlice::Host(ck) => HostOrDeviceSlice::Host(ck[..poly.len()].to_vec()),
            };

            let mut msm_result =
                HostOrDeviceSlice::<'_, IcicleProjective<Self::IC>>::cuda_malloc(batch_size)?;

            let mut cfg = MSMConfig::default();
            cfg.ctx.stream = &stream;
            cfg.is_async = true; // non-blocking

            #[cfg(feature = "kzg-print-trace")]
            let msm_time = start_timer!(|| "GPU-accelerated MSM dispatched");

            icicle_core::msm::msm(poly, &trimmed_prover_param, &cfg, &mut msm_result)?;

            #[cfg(feature = "kzg-print-trace")]
            end_timer!(msm_time);

            ark_std::mem::forget(trimmed_prover_param);
            Ok(msm_result)
        }

        /// After `Self::commit_on_gpu()`, you can choose to load the result
        /// back to host CPU
        fn load_commitments_to_host(
            commitments_on_gpu: HostOrDeviceSlice<'_, IcicleProjective<Self::IC>>,
            stream: &CudaStream,
        ) -> Result<Vec<Commitment<E>>, PCSError> {
            #[cfg(feature = "kzg-print-trace")]
            let sync_time = start_timer!(|| "Sync MSM result");
            // Since `commit_on_gpu()` is conducting the MSM in async way, we need to
            // synchronize it first.
            stream.synchronize()?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(sync_time);

            #[cfg(feature = "kzg-print-trace")]
            let load_time = start_timer!(|| "Load MSM result GPU->CPU");
            let mut msm_host_result =
                vec![IcicleProjective::<Self::IC>::zero(); commitments_on_gpu.len()];
            commitments_on_gpu.copy_to_host(&mut msm_host_result[..])?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(load_time);

            #[cfg(feature = "kzg-print-trace")]
            let conv_time = start_timer!(|| "Type Conversion: ICICLE->ark: Group");
            let comms = msm_host_result
                .par_iter()
                .map(|&p| Commitment(Self::icicle_projective_to_ark(p)))
                .collect();
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(conv_time);

            Ok(comms)
        }
    }

    impl GPUCommittable<Bn254> for UnivariateKzgPCS<Bn254> {
        type IC = IcicleBn254;
        // NOTE: we are directly using montgomery form, different from default!
        fn ark_field_to_icicle(f: ark_bn254::Fr) -> icicle_bn254::curve::ScalarField {
            icicle_bn254::curve::ScalarField::from(f.0 .0)
        }

        // NOTE: we are directly using montgomery form, different from default!
        fn ark_affine_to_icicle(p: ark_bn254::G1Affine) -> icicle_bn254::curve::G1Affine {
            icicle_bn254::curve::G1Affine {
                x: icicle_bn254::curve::BaseField::from(p.x.0 .0),
                y: icicle_bn254::curve::BaseField::from(p.y.0 .0),
            }
        }

        fn icicle_projective_to_ark(p: icicle_bn254::curve::G1Projective) -> ark_bn254::G1Affine {
            use ark_ff::biginteger::BigInteger256;

            let ic_affine: icicle_bn254::curve::G1Affine = p.into();
            let x_limbs: [u64; 4] = ic_affine.x.into();
            let y_limbs: [u64; 4] = ic_affine.y.into();

            if ic_affine == icicle_bn254::curve::G1Affine::zero() {
                ark_bn254::G1Affine::zero()
            } else {
                ark_bn254::G1Affine {
                    x: BigInteger256::new(x_limbs).into(),
                    y: BigInteger256::new(y_limbs).into(),
                    infinity: false,
                }
            }
        }

        // NOTE: both bases and scalars are in montgomery form on GPU
        fn commit_on_gpu<'comm>(
            prover_param: &mut HostOrDeviceSlice<'_, icicle_bn254::curve::G1Affine>,
            poly: &HostOrDeviceSlice<'_, icicle_bn254::curve::ScalarField>,
            batch_size: usize,
            stream: &CudaStream,
        ) -> Result<HostOrDeviceSlice<'comm, icicle_bn254::curve::G1Projective>, PCSError> {
            let trimmed_srs_size = poly.len() / batch_size;
            let trimmed_prover_param = match prover_param {
                HostOrDeviceSlice::Device(ck, device_id) => {
                    HostOrDeviceSlice::Device(&mut ck[..trimmed_srs_size], *device_id)
                },
                HostOrDeviceSlice::Host(ck) => {
                    HostOrDeviceSlice::Host(ck[..trimmed_srs_size].to_vec())
                },
            };
            let mut msm_result =
                HostOrDeviceSlice::<'_, icicle_bn254::curve::G1Projective>::cuda_malloc(
                    batch_size,
                )?;

            let mut cfg = MSMConfig::default();
            cfg.ctx.stream = stream;
            cfg.is_async = true;
            cfg.are_scalars_montgomery_form = true;
            cfg.are_points_montgomery_form = true;

            #[cfg(feature = "kzg-print-trace")]
            let msm_time = start_timer!(|| "GPU-accelerated MSM");
            icicle_core::msm::msm(poly, &trimmed_prover_param, &cfg, &mut msm_result)?;
            #[cfg(feature = "kzg-print-trace")]
            end_timer!(msm_time);

            // TODO: update after https://github.com/ingonyama-zk/icicle/pull/412
            // FIXME: even though `trimmed_prover_param` is an internal, temporary variable
            // there's still risk of double-free if `msm()` above panic. Switching to
            // `ManuallyDrop<HostOrDeviceSlice>` would fix this issue but aren't supported
            // by ICICLE's msm API.
            ark_std::mem::forget(trimmed_prover_param);
            Ok(msm_result)
        }
    }
}

fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: DenseUVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    #[cfg(feature = "kzg-print-trace")]
    let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to
    bigints");

    let coeffs = p.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();

    #[cfg(feature = "kzg-print-trace")]
    end_timer!(to_bigint_time);

    coeffs
}

// Compute Lagrange poly `value * prod_{j!=i} (X-point_j)/(point_i-point_j)`
// We assume i < points.len()
fn lagrange_poly<F: PrimeField>(points: &[F], i: usize, value: F) -> DensePolynomial<F> {
    let mut res = DensePolynomial::from_coefficients_vec(vec![value]);
    let point_i = points[i];
    for (j, &point) in points.iter().enumerate() {
        if j != i {
            let z_inv = (point_i - point).inverse().unwrap();
            res = &res * &DensePolynomial::from_coefficients_vec(vec![-point * z_inv, z_inv]);
        }
    }
    res
}

#[cfg(test)]
mod tests {
    pub use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::Rng;
    pub use jf_utils::test_rng;

    fn end_to_end_test_template<E>() -> Result<(), PCSError>
    where
        E: Pairing,
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(rng, degree)?;
            let (ck, vk) = pp.trim(degree)?;
            let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                degree, rng,
            );
            let comm = UnivariateKzgPCS::<E>::commit(&ck, &p)?;
            let point = E::ScalarField::rand(rng);
            let (proof, value) = UnivariateKzgPCS::<E>::open(&ck, &p, &point)?;
            assert!(
                UnivariateKzgPCS::<E>::verify(&vk, &comm, &point, &value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                p.degree(),
            );
        }
        Ok(())
    }

    fn linear_polynomial_test_template<E>() -> Result<(), PCSError>
    where
        E: Pairing,
    {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let degree = 50;

            let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(rng, degree)?;
            let (ck, vk) = pp.trim(degree)?;
            let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                degree, rng,
            );
            let comm = UnivariateKzgPCS::<E>::commit(&ck, &p)?;
            let point = E::ScalarField::rand(rng);
            let (proof, value) = UnivariateKzgPCS::<E>::open(&ck, &p, &point)?;
            assert!(
                UnivariateKzgPCS::<E>::verify(&vk, &comm, &point, &value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                p.degree(),
            );
        }
        Ok(())
    }

    fn batch_check_test_template<E>() -> Result<(), PCSError>
    where
        E: Pairing,
    {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(rng, degree)?;
            let (ck, vk) = UnivariateKzgPCS::<E>::trim(&pp, degree, None)?;
            let mut comms = Vec::new();
            let mut values = Vec::new();
            let mut points = Vec::new();
            let mut proofs = Vec::new();
            for _ in 0..10 {
                let p =
                    <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                        degree, rng,
                    );
                let comm = UnivariateKzgPCS::<E>::commit(&ck, &p)?;
                let point = E::ScalarField::rand(rng);
                let (proof, value) = UnivariateKzgPCS::<E>::open(&ck, &p, &point)?;

                assert!(UnivariateKzgPCS::<E>::verify(
                    &vk, &comm, &point, &value, &proof
                )?);
                comms.push(comm);
                values.push(value);
                points.push(point);
                proofs.push(proof);
            }
            assert!(UnivariateKzgPCS::<E>::batch_verify(
                &vk, &comms, &points, &values, &proofs, rng
            )?);
        }
        Ok(())
    }

    fn multi_point_open_test_template<E>() -> Result<(), PCSError>
    where
        E: Pairing,
    {
        let rng = &mut test_rng();
        let degree = 20;
        let verifier_degree = 10;
        let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing_with_verifier_degree(
            rng,
            degree,
            verifier_degree,
        )?;
        let (ck, vk) = pp
            .borrow()
            .trim_with_verifier_degree(degree, verifier_degree)?;
        for _ in 0..10 {
            let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                degree, rng,
            );
            let comm = UnivariateKzgPCS::<E>::commit(&ck, &p)?;
            let points: Vec<E::ScalarField> = (0..5).map(|_| E::ScalarField::rand(rng)).collect();
            let (proof, values) = UnivariateKzgPCS::<E>::multi_point_open(&ck, &p, &points[..])?;

            assert!(UnivariateKzgPCS::<E>::multi_point_verify(
                &vk,
                &comm,
                &points[..],
                &values[..],
                &proof
            )?);
        }
        Ok(())
    }

    #[test]
    fn end_to_end_test() {
        end_to_end_test_template::<Bls12_381>().expect("test failed for bls12-381");
    }

    #[test]
    fn linear_polynomial_test() {
        linear_polynomial_test_template::<Bls12_381>().expect("test failed for bls12-381");
    }
    #[test]
    fn batch_check_test() {
        batch_check_test_template::<Bls12_381>().expect("test failed for bls12-381");
    }

    #[test]
    fn multi_point_open_test() {
        multi_point_open_test_template::<Bls12_381>().expect("test failed for bls12-381");
    }

    #[test]
    fn test_multi_open() -> Result<(), PCSError> {
        type E = Bls12_381;
        type Fr = ark_bls12_381::Fr;

        let mut rng = test_rng();
        let max_degree = 33;
        let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, max_degree)?;
        let degrees = [14, 15, 16, 17, 18];

        for degree in degrees {
            let num_points = rng.gen_range(5..30); // should allow more points than degree
            ark_std::println!(
                "Multi-opening: poly deg: {}, num of points: {}",
                degree,
                num_points
            );

            // NOTE: THIS IS IMPORTANT FOR USER OF `multi_open()`!
            // since we will pad your polynomial degree to the next_power_of_two, you will
            // need to trim to the correct padded degree as follows:
            let (ck, _) = UnivariateKzgPCS::<E>::trim_fft_size(&pp, degree)?;
            let poly = <DensePolynomial<Fr> as DenseUVPolynomial<Fr>>::rand(degree, &mut rng);
            let points: Vec<Fr> = (0..num_points).map(|_| Fr::rand(&mut rng)).collect();

            // First, test general points
            let (proofs, evals) = UnivariateKzgPCS::<E>::multi_open(&ck, &poly, &points)?;
            assert!(
                proofs.len() == evals.len() && proofs.len() == num_points,
                "fn multi_open() should return the correct number of proofs and evals"
            );
            points
                .iter()
                .zip(proofs.into_iter())
                .zip(evals.into_iter())
                .for_each(|((point, proof), eval)| {
                    assert_eq!(
                        UnivariateKzgPCS::<E>::open(&ck, &poly, point).unwrap(),
                        (proof, eval)
                    );
                });
            // Second, test roots-of-unity points
            let domain: Radix2EvaluationDomain<Fr> =
                UnivariateKzgPCS::<E>::multi_open_rou_eval_domain(degree, num_points)?;
            let (proofs, evals) =
                UnivariateKzgPCS::<E>::multi_open_rou(&ck, &poly, num_points, &domain)?;
            assert!(
                proofs.len() == evals.len() && proofs.len() == num_points,
                "fn multi_open_rou() should return the correct number of proofs and evals"
            );

            domain
                .elements()
                .take(num_points)
                .zip(proofs.into_iter())
                .zip(evals.into_iter())
                .for_each(|((point, proof), eval)| {
                    assert_eq!(
                        UnivariateKzgPCS::<E>::open(&ck, &poly, &point).unwrap(),
                        (proof, eval)
                    );
                });
        }

        Ok(())
    }

    #[cfg(feature = "icicle")]
    mod icicle {
        use super::*;
        #[cfg(feature = "kzg-print-trace")]
        use crate::icicle_deps::warmup_new_stream;
        use crate::{
            icicle_deps::{curves::*, IcicleCurve},
            pcs::univariate_kzg::icicle::GPUCommittable,
        };
        use core::mem::size_of;
        use icicle_core::traits::{ArkConvertible, MontgomeryConvertible};
        use icicle_cuda_runtime::{error::CudaResultWrap, memory::HostOrDeviceSlice};

        #[cfg(feature = "kzg-print-trace")]
        fn gpu_profiling<E: Pairing>() -> Result<(), PCSError>
        where
            UnivariateKzgPCS<E>: GPUCommittable<E>,
        {
            let rng = &mut test_rng();
            let stream = warmup_new_stream().unwrap();
            let degree = 2usize.pow(22);

            let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(rng, degree)?;
            let (ck, _vk) = pp.trim(degree)?;
            let mut srs_on_gpu =
                <UnivariateKzgPCS<E> as GPUCommittable<E>>::load_prover_param_to_gpu(&ck, degree)?;

            let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                degree, rng,
            );

            let _comm =
                <UnivariateKzgPCS<E> as GPUCommittable<E>>::gpu_commit_with_loaded_prover_param(
                    &mut srs_on_gpu,
                    &p,
                    &stream,
                )?;

            let polys: Vec<_> = (0..8)
                .map(|_| {
                    <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                        degree / 8,
                        rng,
                    )
                })
                .collect();
            let _comms =
                <UnivariateKzgPCS<E> as GPUCommittable<E>>::gpu_batch_commit_with_loaded_prover_param(
                    &mut srs_on_gpu,
                    &polys,
                    &stream,
                )?;

            Ok(())
        }

        fn test_gpu_e2e_template<E: Pairing>() -> Result<(), PCSError>
        where
            UnivariateKzgPCS<E>: GPUCommittable<E>,
        {
            let rng = &mut test_rng();
            let supported_degree = 2usize.pow(12);
            let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(rng, supported_degree)?;

            // testing on smaller degree for correctness
            for _ in 0..10 {
                let degree = usize::rand(rng) % 1025;
                let (ck, vk) = pp.trim(degree)?;
                let p =
                    <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                        degree, rng,
                    );
                let comm_gpu = <UnivariateKzgPCS<E> as GPUCommittable<E>>::gpu_commit(&ck, &p)?;
                let comm_cpu = UnivariateKzgPCS::<E>::commit(&ck, &p)?;
                assert_eq!(comm_gpu, comm_cpu);

                let point = E::ScalarField::rand(rng);
                let (proof, value) = UnivariateKzgPCS::<E>::open(&ck, &p, &point)?;
                assert!(
                    UnivariateKzgPCS::<E>::verify(&vk, &comm_gpu, &point, &value, &proof)?,
                    "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                    degree,
                    p.degree(),
                );

                // batch commit
                for i in 0..5 {
                    let batch_size = 10 + i;
                    let polys: Vec<_> = (0..batch_size)
                        .map(|_| {
                            <DensePolynomial<E::ScalarField> as DenseUVPolynomial<
                                    E::ScalarField,
                                >>::rand(degree, rng)
                        })
                        .collect();
                    let comms_gpu =
                        <UnivariateKzgPCS<E> as GPUCommittable<E>>::gpu_batch_commit(&ck, &polys)?;
                    let comms_cpu = UnivariateKzgPCS::<E>::batch_commit(&ck, &polys)?;
                    assert_eq!(comms_gpu, comms_cpu);
                    assert!(
                        <UnivariateKzgPCS<E> as GPUCommittable<E>>::gpu_batch_commit(&ck, &[])
                            .is_ok()
                    );
                }
            }
            Ok(())
        }

        #[test]
        fn test_gpu_e2e() {
            test_gpu_e2e_template::<Bn254>().unwrap();
        }

        fn test_gpu_ark_conversion_template<E: Pairing>()
        where
            UnivariateKzgPCS<E>: GPUCommittable<E>,
            <<UnivariateKzgPCS<E> as GPUCommittable<E>>::IC as IcicleCurve>::ScalarField:
                ArkConvertible<ArkEquivalent = E::ScalarField> + MontgomeryConvertible,
        {
            type ICScalarField<E> =
                <<UnivariateKzgPCS<E> as GPUCommittable<E>>::IC as IcicleCurve>::ScalarField;
            assert_eq!(size_of::<E::ScalarField>(), size_of::<ICScalarField<E>>());
            let size = 100usize;
            let mut rng = test_rng();
            let scalars: Vec<_> = (0..size)
                .map(|_| {
                    let mut bytes = [0u8; 32];
                    rng.fill_bytes(&mut bytes);
                    E::ScalarField::from_le_bytes_mod_order(&bytes)
                })
                .collect();
            let mut ic_scalars: Vec<_> = scalars
                .iter()
                .copied()
                .map(ICScalarField::<E>::from_ark)
                .collect();
            let mut d_scalars = HostOrDeviceSlice::cuda_malloc(size).unwrap();
            d_scalars.copy_from_host(&ic_scalars).unwrap();
            ICScalarField::<E>::to_mont(&mut d_scalars).wrap().unwrap();
            d_scalars.copy_to_host(&mut ic_scalars).unwrap();
            let transformed_scalars = unsafe { scalars.align_to::<ICScalarField<E>>().1 };
            assert_eq!(ic_scalars, transformed_scalars);
        }

        #[test]
        /// This test checks whether the scalar field type in Ark has the size
        /// with the one in icicle. So that we could do direct reinterpret_cast
        /// between them.
        fn test_gpu_ark_conversion() {
            test_gpu_ark_conversion_template::<Bn254>();
        }

        #[cfg(feature = "kzg-print-trace")]
        #[test]
        fn profile_gpu_commit() {
            // testing on large degree for profiling
            gpu_profiling::<Bn254>().unwrap();
        }
    }
}
