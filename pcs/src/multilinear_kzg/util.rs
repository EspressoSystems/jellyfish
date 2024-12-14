// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Utilities for KZG Polynomial Commitment Scheme (PCS)

use crate::prelude::PCSError;
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension, EvaluationDomain, Evaluations,
    MultilinearExtension, Polynomial, Radix2EvaluationDomain,
};
use ark_std::{end_timer, log2, start_timer, vec, vec::Vec, string::ToString};

use super::MLE;

#[cfg(any(test, feature = "test-srs"))]
pub(crate) fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> Result<F, PCSError> {
    if x.len() != y.len() {
        return Err(PCSError::InvalidParameters(
            "Mismatched input lengths for eq_eval.".to_string(),
        ));
    }
    let timer = start_timer!(|| "eq_eval");
    let result = x.iter().zip(y.iter()).fold(F::one(), |acc, (&xi, &yi)| {
        acc * (xi * yi + xi * yi - xi - yi + F::one())
    });
    end_timer!(timer);
    Ok(result)
}

/// Decompose an integer into a binary vector (little-endian).
pub(crate) fn bit_decompose(mut input: u64, num_vars: usize) -> Vec<bool> {
    let mut result = Vec::with_capacity(num_vars);
    for _ in 0..num_vars {
        result.push(input & 1 == 1);
        input >>= 1;
    }
    result
}

/// Compute the degree of the univariate polynomial `q(x) := w(l(x))`.
#[inline]
#[cfg(test)]
pub fn compute_qx_degree(mle_num_vars: usize, point_len: usize) -> usize {
    mle_num_vars * point_len
}

/// Get a radix-2 evaluation domain for the univariate polynomial.
#[inline]
pub(crate) fn get_uni_domain<F: PrimeField>(
    uni_poly_degree: usize,
) -> Result<Radix2EvaluationDomain<F>, PCSError> {
    Radix2EvaluationDomain::<F>::new(uni_poly_degree).ok_or_else(|| {
        PCSError::InvalidParameters("Failed to construct Radix-2 evaluation domain.".to_string())
    })
}

/// Compose MLE `W` with a list of univariate polynomials `l`.
pub(crate) fn compute_w_circ_l<F: PrimeField>(
    w: &DenseMultilinearExtension<F>,
    l: &[DensePolynomial<F>],
) -> Result<DensePolynomial<F>, PCSError> {
    if w.num_vars != l.len() {
        return Err(PCSError::InvalidParameters(format!(
            "Mismatch: W has {} variables but l has {} polynomials.",
            w.num_vars,
            l.len()
        )));
    }

    let timer = start_timer!(|| "compute W ∘ l");
    let uni_degree = (l.len() - w.num_vars + log2(l.len()) as usize + 2) * l[0].degree();
    let domain = get_uni_domain::<F>(uni_degree)?;
    let res_eval: Vec<F> = domain
        .elements()
        .map(|point| {
            let l_eval: Vec<F> = l.iter().rev().map(|poly| poly.evaluate(&point)).collect();
            w.evaluate(&l_eval).unwrap()
        })
        .collect();
    let result = Evaluations::from_vec_and_domain(res_eval, domain).interpolate();
    end_timer!(timer);
    Ok(result)
}

/// Compute the number of variables needed to batch a list of MLEs.
#[inline]
pub fn get_batched_nv(num_vars: usize, num_polys: usize) -> usize {
    num_vars + log2(num_polys) as usize
}

/// Merge a set of polynomials into a single polynomial.
pub fn merge_polynomials<F: PrimeField>(
    polynomials: &[MLE<F>],
) -> Result<DenseMultilinearExtension<F>, PCSError> {
    let num_vars = polynomials[0].num_vars();
    if polynomials.iter().any(|poly| poly.num_vars() != num_vars) {
        return Err(PCSError::InvalidParameters("Inconsistent num_vars in polynomials.".to_string()));
    }

    let merged_num_vars = get_batched_nv(num_vars, polynomials.len());
    let scalars = polynomials
        .iter()
        .flat_map(|poly| poly.to_evaluations())
        .chain(vec![F::zero(); (1 << merged_num_vars) - (1 << num_vars) * polynomials.len()])
        .collect();

    Ok(DenseMultilinearExtension::from_evaluations_vec(
        merged_num_vars,
        scalars,
    ))
}

/// Build `l(points)` as a list of univariate polynomials going through the points.
pub(crate) fn build_l<F: PrimeField>(
    num_vars: usize,
    points: &[Vec<F>],
    domain: &Radix2EvaluationDomain<F>,
) -> Result<Vec<DensePolynomial<F>>, PCSError> {
    let prefix_len = log2(points.len()) as usize;

    let indexes: Vec<Vec<bool>> = (0..points.len())
        .map(|x| bit_decompose(x as u64, prefix_len))
        .collect();

    let mut univariate_polys = (0..prefix_len)
        .map(|i| {
            let eval: Vec<F> = indexes.iter().map(|x| F::from(x[prefix_len - i - 1])).collect();
            Evaluations::from_vec_and_domain(eval, *domain).interpolate()
        })
        .collect::<Vec<_>>();

    for i in 0..num_vars {
        let eval = points.iter().map(|x| x[i]).chain(vec![F::zero(); domain.size as usize - points.len()]).collect();
        univariate_polys.push(Evaluations::from_vec_and_domain(eval, *domain).interpolate());
    }

    Ok(univariate_polys)
}

/// Generate evaluations for polynomials at given points.
#[cfg(test)]
pub(crate) fn generate_evaluations<F: PrimeField>(
    polynomials: &[MLE<F>],
    points: &[Vec<F>],
) -> Result<Vec<F>, PCSError> {
    if polynomials.len() != points.len() {
        return Err(PCSError::InvalidParameters(
            "Mismatched polynomials and points.".to_string(),
        ));
    }

    let num_vars = polynomials[0].num_vars();
    let merge_poly = merge_polynomials(polynomials)?;
    let domain = get_uni_domain::<F>(points.len())?;
    let uni_polys = build_l(num_vars, points, &domain)?;

    let evaluations = (0..points.len())
        .map(|i| {
            let point: Vec<F> = uni_polys.iter().rev().map(|poly| poly.evaluate(&domain.element(i))).collect();
            merge_poly.evaluate(&point).unwrap()
        })
        .collect();

    Ok(evaluations)
}
