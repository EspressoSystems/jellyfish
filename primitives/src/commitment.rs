// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implements a rescue hash based commitment scheme.

use crate::errors::PrimitivesError;
use ark_std::{format, string::String, vec};
use jf_rescue::{Permutation, RescueParameter, RATE};
use jf_utils::pad_with_zeros;

#[derive(Default)]
/// Commitment instance for user defined input size (in scalar elements)
pub struct Commitment<F: RescueParameter> {
    hash: Permutation<F>,
    input_len: usize,
}

impl<F: RescueParameter> Commitment<F> {
    /// Create a new commitment instance for inputs of length `input_len`
    pub fn new(input_len: usize) -> Commitment<F> {
        assert!(input_len > 0, "input_len must be positive");
        Commitment {
            hash: Permutation::default(),
            input_len,
        }
    }
    /// Commits to `input` slice using blinding `blind`. Return
    /// Err(PrimitivesError::ParameterError) if input.len() !=
    /// self.input_len
    pub fn commit(&self, input: &[F], blind: &F) -> Result<F, PrimitivesError> {
        if input.len() != self.input_len {
            return Err(PrimitivesError::ParameterError(format!(
                "Commitment error: expected input length ({}). It must match \
                instance's message length ({})",
                self.input_len,
                input.len(),
            )));
        }
        let mut msg = vec![*blind];
        msg.extend_from_slice(input);
        // Ok to pad with 0's since input length is fixed for the commitment instance
        pad_with_zeros(&mut msg, RATE);
        let result_vec = self.hash.sponge_no_padding(msg.as_slice(), 1)?;
        Ok(result_vec[0])
    }
    /// Verifies `commitment` against `input` and `blind`.
    /// Returns Ok(()) on success. Otherwise, returns
    /// PrimitivesError::ParameterError if input.len() != self.input_len,
    /// and PrimitivesError::VerificationError if commitment is not valid.
    pub fn verify(&self, input: &[F], blind: &F, commitment: &F) -> Result<(), PrimitivesError> {
        if self.commit(input, blind)? == *commitment {
            Ok(())
        } else {
            Err(PrimitivesError::VerificationError(String::from(
                "Commitment verification failed",
            )))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::commitment::Commitment;
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::UniformRand;
    use core::ops::Add;

    macro_rules! test_commit {
        ($tr:tt) => {
            let mut prng = ark_std::test_rng();
            let commitment = Commitment::new(3);

            let input = [$tr::from(1u64), $tr::from(2u64), $tr::from(3u64)];
            let blind = $tr::rand(&mut prng);
            let c = commitment.commit(&input, &blind).unwrap();
            assert!(commitment.verify(&input, &blind, &c).is_ok());
            // smaller input size
            assert!(commitment.verify(&input[0..2], &blind, &c).is_err());
            // bad blinding factor
            let bad_blind = blind.add($tr::from(1u8));
            assert!(commitment.verify(&input, &bad_blind, &c).is_err());
            // bad input
            let bad_input = [$tr::from(2u64), $tr::from(1u64), $tr::from(3u64)];
            assert!(commitment.verify(&bad_input, &blind, &c).is_err());

            // smaller input size
            let bad_size_input = [$tr::from(2u64), $tr::from(1u64)];
            assert!(commitment.commit(&bad_size_input, &blind).is_err());
            // greater input size
            let bad_size_input = [
                $tr::from(2u64),
                $tr::from(1u64),
                $tr::from(1u64),
                $tr::from(1u64),
            ];
            assert!(commitment.commit(&bad_size_input, &blind).is_err());
        };
    }

    #[test]
    fn test_commit() {
        test_commit!(FqEd254);
        test_commit!(FqEd377);
        test_commit!(FqEd381);
        test_commit!(FqEd381b);
        test_commit!(Fq377);
    }
}
