// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for Reed Solomon Erasure Code

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, vec, vec::Vec};
use core::marker::PhantomData;

use super::ErasureCode;

/// Very naive implementation of Reed Solomon erasure code.
///  * `reconstruction_size`: and the minimum number of shards required for
///    reconstruction
///  * `num_shards`: the block (codeword) length
/// The encoding of a message is the evaluation on (1..num_shards) of the
/// polynomial whose coefficients are the message entries. Decoding is a naive
/// Lagrange interpolation.
pub struct ReedSolomonErasureCode<F> {
    phantom_f: PhantomData<F>,
}

/// Shards for Reed Solomon erasure code
#[derive(Clone, Eq, Debug, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "F: Field"))]
pub struct ReedSolomonErasureCodeShard<F: Field> {
    /// Index of shard shard
    pub index: usize,
    /// Value of this shard
    pub value: F,
}

impl<F> ErasureCode<F> for ReedSolomonErasureCode<F>
where
    F: Field,
{
    type Shard = ReedSolomonErasureCodeShard<F>;

    /// Encode into `data.len() + parity_size` shards.
    fn encode(data: &[F], parity_size: usize) -> Vec<Self::Shard> {
        let num_shards = data.len() + parity_size;

        // view `data` as coefficients of a polynomial
        // make shards by evaluating this polynomial at 1..=num_shards
        (1..=num_shards)
            .map(|index| {
                let mut value = F::zero();
                let mut x = F::one();
                data.iter().for_each(|coef| {
                    value += x * coef.borrow();
                    x *= F::from(index as u64);
                });
                ReedSolomonErasureCodeShard { index, value }
            })
            .collect()
    }

    /// Decode into `shards.len()` data elements.
    /// Lagrange interpolation
    /// Given a list of points (x_1, y_1) ... (x_n, y_n)
    ///  1. Define l(x) = \prod (x - x_i)
    ///  2. Calculate the barycentric weight w_i = \prod_{j \neq i} 1 / (x_i -
    /// x_j)  
    ///  3. Calculate l_i(x) = w_i * l(x) / (x - x_i)
    ///  4. Return f(x) = \sum_i y_i * l_i(x)
    /// This function always returns a vector of length `shards.len()`
    /// It has a time complexity of O(n^2)
    fn decode(shards: &[Self::Shard]) -> Vec<F> {
        let x = shards
            .iter()
            .map(|shard| F::from(shard.index as u64))
            .collect::<Vec<_>>();
        // Calculating l(x) = \prod (x - x_i)
        let mut l = vec![F::zero(); shards.len() + 1];
        l[0] = F::one();
        for i in 1..shards.len() + 1 {
            l[i] = F::one();
            for j in (1..i).rev() {
                l[j] = l[j - 1] - x[i - 1] * l[j];
            }
            l[0] = -x[i - 1] * l[0];
        }
        // Calculate the barycentric weight w_i
        let w = (0..shards.len())
            .map(|i| {
                let mut ret = F::one();
                (0..shards.len()).for_each(|j| {
                    if i != j {
                        ret /= x[i] - x[j];
                    }
                });
                ret
            })
            .collect::<Vec<_>>();
        // Calculate f(x) = \sum_i l_i(x)
        let mut f = vec![F::zero(); shards.len()];
        for i in 0..shards.len() {
            let mut li = vec![F::zero(); shards.len()];
            li[shards.len() - 1] = F::one();
            for j in (0..shards.len() - 1).rev() {
                li[j] = l[j + 1] + x[i] * li[j + 1];
            }
            let weight = w[i] * shards[i].borrow().value;
            for j in 0..shards.len() {
                f[j] += weight * li[j];
            }
        }
        f
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
    use ark_ff::Field;
    use ark_std::vec;

    fn test_rs_code_helper<F: Field>() {
        // Encoded as a polynomial 2x + 1
        let data = vec![F::from(1u64), F::from(2u64)];
        // Evaluation of the above polynomial on (1, 2, 3) is (3, 5, 7)
        let expected = vec![
            ReedSolomonErasureCodeShard {
                index: 1,
                value: F::from(3u64),
            },
            ReedSolomonErasureCodeShard {
                index: 2,
                value: F::from(5u64),
            },
            ReedSolomonErasureCodeShard {
                index: 3,
                value: F::from(7u64),
            },
        ];
        let code = ReedSolomonErasureCode::encode(&data, 1);
        assert_eq!(code, expected);

        for to_be_removed in 0..code.len() {
            let mut new_code = code.clone();
            new_code.remove(to_be_removed);
            let decode = ReedSolomonErasureCode::decode(&new_code);
            assert_eq!(data, decode);
        }
    }

    #[test]
    fn test_rs_code() {
        test_rs_code_helper::<Fq254>();
        test_rs_code_helper::<Fq377>();
        test_rs_code_helper::<Fq381>();
    }
}
