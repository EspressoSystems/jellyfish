// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implements a rescue hash based commitment scheme.

use crate::{crhf::FixedLengthRescueCRHF, RescueError, RescueParameter};
use ark_std::{borrow::Borrow, marker::PhantomData, string::ToString};
use jf_primitives_core::{commitment::CommitmentScheme, crhf::CRHF, VerificationResult};

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
    type Error = RescueError;

    fn commit<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
    ) -> Result<Self::Output, Self::Error> {
        let mut msg = [F::zero(); INPUT_LEN_PLUS_ONE];
        msg[0] = *r.ok_or_else(|| {
            RescueError::ParameterError("Expecting a blinding factor".to_string())
        })?;
        msg[1..INPUT_LEN_PLUS_ONE].copy_from_slice(&input.borrow()[..(INPUT_LEN)]);

        Ok(FixedLengthRescueCRHF::<F, INPUT_LEN_PLUS_ONE, 1>::evaluate(&msg)?[0])
    }

    fn verify<T: Borrow<Self::Input>>(
        input: T,
        r: Option<&Self::Randomness>,
        comm: &Self::Output,
    ) -> Result<VerificationResult, Self::Error> {
        if <Self as CommitmentScheme>::commit(input, r)? == *comm {
            Ok(Ok(()))
        } else {
            Ok(Err(()))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        commitment::{CommitmentScheme, FixedLengthRescueCommitment},
        crhf::RescueCRHF,
        CRHF_RATE,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_bn254::Fq as Fq254;
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
                FixedLengthRescueCommitment::<$tr, 3, 4>::verify(&input, Some(&blind), &c)
                    .unwrap()
                    .is_ok()
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
                    .unwrap()
                    .is_err()
            );
            // bad blinding factor
            let bad_blind = blind + $tr::from(1u8);
            assert!(
                FixedLengthRescueCommitment::<$tr, 3, 4>::verify(&input, Some(&bad_blind), &c)
                    .unwrap()
                    .is_err()
            );
            // bad input
            let bad_input = [$tr::from(2u64), $tr::from(1u64), $tr::from(3u64)];
            assert!(
                FixedLengthRescueCommitment::<$tr, 3, 4>::verify(&bad_input, Some(&blind), &c)
                    .unwrap()
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
        test_commit!(Fq254);
    }
}
