// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implements a rescue hash based commitment scheme.

use ark_std::marker::PhantomData;

use crate::{
    crhf::{FixedLengthRescueCRHF, CRHF},
    errors::PrimitivesError,
    rescue::RescueParameter,
};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    hash::Hash,
    string::{String, ToString},
    UniformRand,
};

/// A trait for cryptographic commitment scheme
pub trait CommitmentScheme {
    /// Input to the commitment
    type Input;
    /// The type of output commitment value
    type Output: Clone + Debug + PartialEq + Eq + Hash;
    /// The type of the hiding/blinding factor
    type Randomness: Clone + Debug + PartialEq + Eq + UniformRand;

    /// Commit algorithm that takes `input` and blinding randomness `r`
    /// (optional for hiding commitment schemes), outputs a commitment.
    fn commit<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
    ) -> Result<Self::Output, PrimitivesError>;

    /// Verify algorithm that output `Ok` if accepted, or `Err` if rejected.
    fn verify<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
        comm: &Self::Output,
    ) -> Result<(), PrimitivesError>;
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// Rescue-based Commitment instance for fixed-length input
///
/// ## Note
/// the current ugly existence of `INPUT_LEN_PLUS_ONE` is due to unstable
/// feature of using const generic in expression (namely can't use `INPUT_LEN +
/// 1` in code).
// FIXME: (alex) when `feature(generic_const_exprs)` is stable, we should remove
// the third generic param. See more: https://github.com/rust-lang/rust/issues/76560
pub struct FixedLengthRescueCommitment<
    F: RescueParameter,
    const INPUT_LEN: usize,
    const INPUT_LEN_PLUS_ONE: usize,
>(PhantomData<F>);

impl<F: RescueParameter, const INPUT_LEN: usize, const INPUT_LEN_PLUS_ONE: usize> CommitmentScheme
    for FixedLengthRescueCommitment<F, INPUT_LEN, INPUT_LEN_PLUS_ONE>
{
    type Input = [F; INPUT_LEN];
    type Output = F;
    type Randomness = F;

    fn commit<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
    ) -> Result<Self::Output, PrimitivesError> {
        let mut msg = [F::zero(); INPUT_LEN_PLUS_ONE];
        msg[0] = *r.ok_or_else(|| {
            PrimitivesError::ParameterError("Expecting a blinding factor".to_string())
        })?;
        msg[1..INPUT_LEN_PLUS_ONE].copy_from_slice(&input.borrow()[..(INPUT_LEN)]);

        Ok(FixedLengthRescueCRHF::<F, INPUT_LEN_PLUS_ONE, 1>::evaluate(&msg)?[0])
    }

    fn verify<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
        comm: &Self::Output,
    ) -> Result<(), PrimitivesError> {
        if <Self as CommitmentScheme>::commit(input, r)? == *comm {
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
    use crate::{
        commitment::{CommitmentScheme, FixedLengthRescueCommitment},
        rescue::{sponge::RescueCRHF, CRHF_RATE},
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::UniformRand;
    use ark_std::vec;

    macro_rules! test_commit {
        ($tr:tt) => {
            let mut prng = jf_utils::test_rng();

            let input = [$tr::from(1u64), $tr::from(2u64), $tr::from(3u64)];
            let blind = $tr::rand(&mut prng);

            let c = FixedLengthRescueCommitment::<$tr, 3, 4>::commit(&input, Some(&blind)).unwrap();
            assert!(
                FixedLengthRescueCommitment::<$tr, 3, 4>::verify(&input, Some(&blind), &c).is_ok()
            );
            // test for correctness
            let mut msg = vec![blind];
            msg.extend_from_slice(&input);
            if (input.len() + 1) % CRHF_RATE == 0 {
                assert_eq!(c, RescueCRHF::sponge_no_padding(&msg, 1).unwrap()[0])
            } else {
                assert_eq!(c, RescueCRHF::sponge_with_zero_padding(&msg, 1)[0])
            }

            // smaller input size
            let bad_input = [input[0], input[1]];
            assert!(
                FixedLengthRescueCommitment::<$tr, 2, 3>::verify(&bad_input, Some(&blind), &c)
                    .is_err()
            );
            // bad blinding factor
            let bad_blind = blind + $tr::from(1u8);
            assert!(
                FixedLengthRescueCommitment::<$tr, 3, 4>::verify(&input, Some(&bad_blind), &c)
                    .is_err()
            );
            // bad input
            let bad_input = [$tr::from(2u64), $tr::from(1u64), $tr::from(3u64)];
            assert!(
                FixedLengthRescueCommitment::<$tr, 3, 4>::verify(&bad_input, Some(&blind), &c)
                    .is_err()
            );
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
