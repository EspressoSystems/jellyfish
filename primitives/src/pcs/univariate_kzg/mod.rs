// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Main module for univariate KZG commitment scheme

use crate::{
    pcs::{
        poly::GeneralDensePolynomial, prelude::Commitment, PCSError, PolynomialCommitmentScheme,
        StructuredReferenceString, UnivariatePCS,
    },
    toeplitz::ToeplitzMatrix,
};
use ark_ec::{
    pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr, CurveGroup,
};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
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
use jf_utils::par_utils::parallelizable_slice_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use srs::{UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam};

pub(crate) mod srs;

/// KZG Polynomial Commitment Scheme on univariate polynomial.
pub struct UnivariateKzgPCS<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
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
    /// Note that the scheme is not hidding
    fn commit(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        let prover_param = prover_param.borrow();
        let commit_time =
            start_timer!(|| format!("Committing to polynomial of degree {} ", poly.degree()));

        if poly.degree() > prover_param.powers_of_g.len() {
            return Err(PCSError::InvalidParameters(format!(
                "poly degree {} is larger than allowed {}",
                poly.degree(),
                prover_param.powers_of_g.len()
            )));
        }

        let (num_leading_zeros, plain_coeffs) = skip_leading_zeros_and_convert_to_bigints(poly);

        let msm_time = start_timer!(|| "MSM to compute commitment to plaintext poly");
        let commitment = E::G1::msm_bigint(
            &prover_param.powers_of_g[num_leading_zeros..],
            &plain_coeffs,
        )
        .into_affine();
        end_timer!(msm_time);

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
        let open_time =
            start_timer!(|| format!("Opening polynomial of degree {}", polynomial.degree()));
        let divisor = Self::Polynomial::from_coefficients_vec(vec![-*point, E::ScalarField::one()]);

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

        let eval = polynomial.evaluate(point);

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
    fn multi_open_rou(
        prover_param: impl Borrow<<Self::SRS as StructuredReferenceString>::ProverParam>,
        polynomial: &Self::Polynomial,
        num_points: usize,
    ) -> Result<(Vec<Self::Proof>, Vec<Self::Evaluation>), PCSError> {
        let h_poly = Self::compute_h_poly_in_fk23(prover_param, &polynomial.coeffs)?;
        let proofs: Vec<_> = h_poly
            .batch_evaluate_rou(num_points)
            .into_iter()
            .map(|g| UnivariateKzgProof {
                proof: g.into_affine(),
            })
            .collect();

        let evals = GeneralDensePolynomial::from_coeff_slice(&polynomial.coeffs)
            .batch_evaluate_rou(num_points);
        Ok((proofs, evals))
    }
}

impl<E, F> UnivariateKzgPCS<E>
where
    E: Pairing<ScalarField = F>,
    F: FftField,
{
    // Sec 2.2. of <https://eprint.iacr.org/2023/033>
    fn compute_h_poly_in_fk23(
        prover_param: impl Borrow<UnivariateProverParam<E>>,
        poly_coeffs: &[E::ScalarField],
    ) -> Result<GeneralDensePolynomial<E::G1, F>, PCSError> {
        // First, pad to power_of_two, since Toeplitz mul only works for 2^k
        let mut padded_coeffs: Vec<F> = poly_coeffs.to_vec();
        let padded_degree = (padded_coeffs.len() - 1)
            .checked_next_power_of_two()
            .ok_or_else(|| {
                PCSError::InvalidParameters(ark_std::format!(
                    "Next power of two overflows! Got: {}",
                    (padded_coeffs.len() - 1)
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

        // Step 2. evaluate h(X) with coeffs \vec{h} at `points` using FFT
        let mut h_poly = GeneralDensePolynomial::from_coeff_vec(h_vec);
        // NOTE: this resizing is to ensure that when computing the proofs by evaluting
        // h(X), we are using the same roots-of-unity as evaluation points of f(X) which
        // uses FFT, therefore we resize to the `fft_size`.
        h_poly.coeffs.resize(
            super::checked_fft_size(poly_coeffs.len() - 1)?,
            E::G1::zero(),
        );

        Ok(h_poly)
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
    let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to bigints");
    let coeffs = p.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();
    end_timer!(to_bigint_time);
    coeffs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcs::{poly::tests::get_roots_of_unity, StructuredReferenceString};
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_poly::univariate::DensePolynomial;
    use ark_std::{rand::Rng, UniformRand};
    use jf_utils::test_rng;

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
    fn test_multi_open() -> Result<(), PCSError> {
        type E = Bls12_381;
        type Fr = ark_bls12_381::Fr;

        let mut rng = test_rng();
        let max_degree = 33;
        let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, max_degree)?;
        let degrees = [14, 15, 16, 17, 18];

        for degree in degrees {
            let num_points = rng.gen_range(5..degree);
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
            points
                .iter()
                .zip(proofs.into_iter())
                .zip(evals.into_iter())
                .for_each(|((point, proof), eval)| {
                    assert_eq!(
                        UnivariateKzgPCS::<E>::open(&ck, &poly, &point).unwrap(),
                        (proof, eval)
                    );
                });

            // Second, test roots-of-unity points
            let fft_size = crate::pcs::checked_fft_size(degree)?;
            let (proofs, evals) = UnivariateKzgPCS::<E>::multi_open_rou(&ck, &poly, num_points)?;

            let roots_of_unity: Vec<Fr> = get_roots_of_unity(fft_size);

            roots_of_unity
                .iter()
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
}
