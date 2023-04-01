// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for Reed Solomon Erasure Code

use crate::errors::PrimitivesError;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, string::ToString, vec, vec::Vec};
use core::marker::PhantomData;

use super::ErasureCode;

/// Very naive implementation of Reed Solomon erasure code.
///  * `reconstruction_size`: and the minimum number of shards required for
///    reconstruction
///  * `num_shards`: the block (codeword) length
/// The encoding of a message is the evaluation on (1..num_shards) of the
/// polynomial whose coefficients are the message entries. Decoding is a naive
/// Lagrange interpolation.
pub struct ReedSolomonErasureCode<F: PrimeField> {
    reconstruction_size: usize,
    num_shards: usize,
    phantom_f: PhantomData<F>,
}

/// Shards for Reed Solomon erasure code
#[derive(Clone, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "F: PrimeField"))]
pub struct ReedSolomonErasureCodeShard<F: PrimeField> {
    /// Index of shard shard
    pub index: usize,
    /// Value of this shard
    pub values: Vec<F>,
}

impl<F: PrimeField> ReedSolomonErasureCodeShard<F> {
    /// Create a new shard
    pub fn new(index: usize, values: Vec<F>) -> Self {
        Self { index, values }
    }
}

impl<F: PrimeField> ErasureCode for ReedSolomonErasureCode<F> {
    type Field = F;
    type Shard = ReedSolomonErasureCodeShard<F>;

    fn new(reconstruction_size: usize, num_shards: usize) -> Result<Self, PrimitivesError> {
        if reconstruction_size > num_shards {
            Err(PrimitivesError::ParameterError(
                "Number of shards must be at least the message length.".to_string(),
            ))
        } else {
            Ok(ReedSolomonErasureCode {
                reconstruction_size,
                num_shards,
                phantom_f: PhantomData,
            })
        }
    }

    /// The encoding will split the data into chunks of length
    /// `reconstruction_size`. And represent each chunk as a polynomial. The
    /// codeword composes of evaluations of those polynomials on
    /// (1..num_shards).
    fn encode(&self, data: &[Self::Field]) -> Result<Vec<Self::Shard>, PrimitivesError> {
        let result = (1..self.num_shards + 1)
            .map(|i| {
                let mut vals = vec![];
                let mut val = F::zero();
                let mut x = F::one();
                let mut cnt: usize = 0;
                data.iter().for_each(|coef| {
                    val += x * coef.borrow();
                    x *= F::from(i as u64);
                    cnt += 1;
                    if cnt % self.reconstruction_size == 0 {
                        vals.push(val);
                        val = F::zero();
                        x = F::one();
                    }
                });
                if cnt % self.reconstruction_size != 0 {
                    vals.push(val);
                }
                ReedSolomonErasureCodeShard::new(i, vals)
            })
            .collect::<Vec<_>>();
        Ok(result)
    }

    /// Lagrange interpolation
    /// Given a list of points (x_1, y_1) ... (x_n, y_n)
    ///  1. Define l(x) = \prod (x - x_i)
    ///  2. Calculate the barycentric weight w_i = \prod_{j \neq i} 1 / (x_i -
    /// x_j)  
    ///  3. Calculate l_i(x) = w_i * l(x) / (x - x_i)
    ///  4. Return f(x) = \sum_i y_i * l_i(x)
    /// This function always returns a vector length multiple of
    /// `self.reconstuction_size`. It has a time complexity of O(n^2)
    fn decode(&self, shards: &[Self::Shard]) -> Result<Vec<Self::Field>, PrimitivesError> {
        if shards.len() < self.reconstruction_size {
            Err(PrimitivesError::ParameterError(
                "No sufficient data for decoding.".to_string(),
            ))
        } else {
            let num_chunks = shards[0].borrow().values.len();
            if !shards.iter().all(|shard| shard.values.len() == num_chunks) {
                return Err(PrimitivesError::InconsistentStructureError(
                    "Each shard should provide the same number of data".to_string(),
                ));
            }
            let x = shards
                .iter()
                .take(self.reconstruction_size)
                .map(|shard| F::from(shard.index as u64))
                .collect::<Vec<_>>();
            // Calculating l(x) = \prod (x - x_i)
            let mut l = vec![F::zero(); self.reconstruction_size + 1];
            l[0] = F::one();
            for i in 1..self.reconstruction_size + 1 {
                l[i] = F::one();
                for j in (1..i).rev() {
                    l[j] = l[j - 1] - x[i - 1] * l[j];
                }
                l[0] = -x[i - 1] * l[0];
            }
            // Calculate the barycentric weight w_i
            let w = (0..self.reconstruction_size)
                .map(|i| {
                    let mut ret = F::one();
                    (0..self.reconstruction_size).for_each(|j| {
                        if i != j {
                            ret /= x[i] - x[j];
                        }
                    });
                    ret
                })
                .collect::<Vec<_>>();
            // Calculate f(x) = \sum_i l_i(x)
            let mut f = vec![F::zero(); num_chunks * self.reconstruction_size];
            for k in 0..num_chunks {
                let offset = k * self.reconstruction_size;
                for i in 0..self.reconstruction_size {
                    let mut li = vec![F::zero(); self.reconstruction_size];
                    li[self.reconstruction_size - 1] = F::one();
                    for j in (0..self.reconstruction_size - 1).rev() {
                        li[j] = l[j + 1] + x[i] * li[j + 1];
                    }
                    let weight = w[i] * shards[i].borrow().values[k];
                    for j in 0..self.reconstruction_size {
                        f[offset + j] += weight * li[j];
                    }
                }
            }
            Ok(f)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::erasure_code::{
        reed_solomon_erasure::{ReedSolomonErasureCode, ReedSolomonErasureCodeShard},
        ErasureCode,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_bls12_381::Fq as Fq381;
    use ark_bn254::Fq as Fq254;
    use ark_ff::PrimeField;
    use ark_std::vec;

    fn test_rs_code_helper<F: PrimeField>() {
        let rs = ReedSolomonErasureCode::<F>::new(2, 3).unwrap();
        // Encoded as a polynomial 2x + 1
        let data = vec![F::from(1u64), F::from(2u64)];
        // Evaluation of the above polynomial on (1, 2, 3) is (3, 5, 7)
        let expected = vec![
            ReedSolomonErasureCodeShard::new(1, vec![F::from(3u64)]),
            ReedSolomonErasureCodeShard::new(2, vec![F::from(5u64)]),
            ReedSolomonErasureCodeShard::new(3, vec![F::from(7u64)]),
        ];
        let code = rs.encode(&data).unwrap();
        assert_eq!(code, expected);

        for to_be_removed in 0..code.len() {
            let mut new_code = code.clone();
            new_code.remove(to_be_removed);
            let decode = rs.decode(&new_code).unwrap();
            assert_eq!(data, decode);
        }

        // Test for extra long input
        let data = vec![F::from(1u64); 10];
        let code = rs.encode(&data).unwrap();
        assert_eq!(code[0].values.len(), 5);
        let decode = rs.decode(&code).unwrap();
        assert_eq!(data, decode);

        // Extra long input test 2
        let mut data = vec![F::from(1u64); 11];
        let code = rs.encode(&data).unwrap();
        assert_eq!(code[0].values.len(), 6);
        let decode = rs.decode(&code).unwrap();
        data.push(F::zero());
        assert_eq!(data, decode);
    }

    #[test]
    fn test_rs_code() {
        test_rs_code_helper::<Fq254>();
        test_rs_code_helper::<Fq377>();
        test_rs_code_helper::<Fq381>();
    }
}
