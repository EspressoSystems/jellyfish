// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for erasure code

use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::{format, vec, vec::Vec};
use core::borrow::Borrow;

/// Encode `data` into `data.len() + parity_size` shares.
/// Treating the input data as the coefficients of a polynomial,
/// Returns the evaluations of this polynomial over [1, data.len() +
/// parity_size]. If `F` is a `FftField`, the encoding can be done using FFT on
/// a `GeneralEvaluationDomain` (E.g. when num_shares = 3):
/// ```
/// use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
/// use ark_bn254::Fr as F;
/// use ark_std::{vec, One, Zero};
/// use jf_primitives::reed_solomon_code::reed_solomon_erasure_decode;
///
/// let domain = GeneralEvaluationDomain::<F>::new(3).unwrap();
/// let input = vec![F::one(), F::one()];
/// let mut result = domain.fft(&input); // FFT encoding
/// let mut eval_points = domain.elements().collect::<Vec<_>>(); // Evaluation points
/// // test decoding
/// result.remove(1);
/// eval_points.remove(1);
/// let output = reed_solomon_erasure_decode(eval_points, result, 2).unwrap();
/// assert_eq!(input, output);
/// ```
pub fn reed_solomon_encode<F, D>(data: D, parity_size: usize) -> Result<Vec<F>, PrimitivesError>
where
    F: Field,
    D: IntoIterator,
    D::Item: Borrow<F>,
    D::IntoIter: ExactSizeIterator + Clone,
{
    let data_iter = data.into_iter();
    let num_shares = data_iter.len() + parity_size;

    // view `data` as coefficients of a polynomial
    // make shares by evaluating this polynomial at 1..=num_shares
    Ok((1..=num_shares)
        .map(|index| {
            let mut value = F::zero();
            let mut x = F::one();
            data_iter.clone().for_each(|coef| {
                value += x * coef.borrow();
                x *= F::from(index as u64);
            });
            value
        })
        .collect())
}

/// Decode into `data_size` data elements via polynomial interpolation.
/// The degree of the interpolated polynomial is `data_size - 1`.
/// Returns a data vector of length `data_size`.
/// Time complexity of O(n^2).
pub fn reed_solomon_erasure_decode<F, D>(
    eval_points: D,
    values: D,
    data_size: usize,
) -> Result<Vec<F>, PrimitivesError>
where
    F: Field,
    D: IntoIterator,
    D::Item: Borrow<F>,
    D::IntoIter: ExactSizeIterator + Clone,
{
    let eval_points_iter = eval_points.into_iter();
    let values_iter = values.into_iter();
    if eval_points_iter.len() < data_size {
        return Err(PrimitivesError::ParameterError(format!(
            "Insufficient evaluation points: got {} expected at least {}",
            eval_points_iter.len(),
            data_size
        )));
    }
    if eval_points_iter.len() != values_iter.len() {
        return Err(PrimitivesError::ParameterError(format!(
            "Malformed input, received {} evaluation points but {} values.",
            eval_points_iter.len(),
            values_iter.len()
        )));
    }
    let shares_iter = eval_points_iter.zip(values_iter).take(data_size);

    // Lagrange interpolation:
    // Given a list of points (x_1, y_1) ... (x_n, y_n)
    //  1. Define l(x) = \prod (x - x_i)
    //  2. Calculate the barycentric weight w_i = \prod_{j \neq i} 1 / (x_i -
    // x_j)
    //  3. Calculate l_i(x) = w_i * l(x) / (x - x_i)
    //  4. Return f(x) = \sum_i y_i * l_i(x)
    let x = shares_iter
        .clone()
        .map(|share| *share.0.borrow())
        .collect::<Vec<_>>();
    // Calculating l(x) = \prod (x - x_i)
    let mut l = vec![F::zero(); data_size + 1];
    l[0] = F::one();
    for i in 1..data_size + 1 {
        l[i] = F::one();
        for j in (1..i).rev() {
            l[j] = l[j - 1] - x[i - 1] * l[j];
        }
        l[0] = -x[i - 1] * l[0];
    }
    // Calculate the barycentric weight w_i
    let w = (0..data_size)
        .map(|i| {
            let mut ret = F::one();
            (0..data_size).for_each(|j| {
                if i != j {
                    ret /= x[i] - x[j];
                }
            });
            ret
        })
        .collect::<Vec<_>>();
    // Calculate f(x) = \sum_i l_i(x)
    let mut f = vec![F::zero(); data_size];
    // for i in 0..shares.len() {
    for (i, share) in shares_iter.enumerate() {
        let mut li = vec![F::zero(); data_size];
        li[data_size - 1] = F::one();
        for j in (0..data_size - 1).rev() {
            li[j] = l[j + 1] + x[i] * li[j + 1];
        }
        let weight = w[i] * share.1.borrow();
        for j in 0..data_size {
            f[j] += weight * li[j];
        }
    }
    Ok(f)
}

#[cfg(test)]
mod test {
    use ark_bls12_377::Fr as Fr377;
    use ark_bls12_381::Fr as Fr381;
    use ark_bn254::Fr as Fr254;
    use ark_ff::{FftField, Field};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_std::{vec, vec::Vec};

    use crate::reed_solomon_code::{reed_solomon_encode, reed_solomon_erasure_decode};

    fn test_rs_code_helper<F: Field>() {
        // Encoded as a polynomial 2x + 1
        let data = vec![F::from(1u64), F::from(2u64)];
        // Evaluation of the above polynomial on (1, 2, 3) is (3, 5, 7)
        let expected = vec![F::from(3u64), F::from(5u64), F::from(7u64)];
        let code = reed_solomon_encode(&data, 1).unwrap();
        assert_eq!(code, expected);

        for to_be_removed in 0..code.len() {
            let mut indices = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
            let mut new_code = code.clone();
            indices.remove(to_be_removed);
            new_code.remove(to_be_removed);
            let decode = reed_solomon_erasure_decode(&indices, &new_code, 2).unwrap();
            assert_eq!(data, decode);
        }
    }

    #[test]
    fn test_rs_code() {
        test_rs_code_helper::<Fr254>();
        test_rs_code_helper::<Fr377>();
        test_rs_code_helper::<Fr381>();
    }

    fn test_rs_code_fft_helper<F: FftField>() {
        let domain = GeneralEvaluationDomain::<F>::new(3).unwrap();
        let input = vec![F::from(1u64), F::from(2u64)];
        let mut code = domain.fft(&input);
        let mut eval_points = domain.elements().collect::<Vec<_>>();
        eval_points.remove(1);
        code.remove(1);
        let output = reed_solomon_erasure_decode(eval_points, code, 2).unwrap();
        assert_eq!(input, output);
    }

    #[test]
    fn test_rs_code_fft() {
        test_rs_code_fft_helper::<Fr254>();
        test_rs_code_fft_helper::<Fr377>();
        test_rs_code_fft_helper::<Fr381>();
    }
}