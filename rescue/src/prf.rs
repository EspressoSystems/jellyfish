// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A rescue PRF implementation

use crate::{RescueError, RescueParameter, RescueSponge, CRHF_RATE};
use ark_ff::BigInteger;
use ark_std::{borrow::Borrow, marker::PhantomData, string::ToString, vec, vec::Vec};
use jf_prf::PRF;
use jf_utils::pad_with_zeros;
use spongefish::duplex_sponge::DuplexSpongeInterface;

/// Rescue PRF Core Implementation
///
/// # Migration Note
/// This implementation was migrated from ark-sponge (additive absorption) to
/// spongefish (overwrite absorption). The original implementation used rate=4
/// (STATE_SIZE) with additive absorption semantics where input elements
/// were added to the sponge state. The new implementation uses rate=3 with
/// overwrite absorption semantics where input elements overwrite the rate
/// portion of the sponge state, maintaining capacity=1 for security.
///
/// This change means:
/// - Input padding and length validation now expect multiples of 3 instead of 4
/// - The absorption semantics changed from additive (state += input) to
///   overwrite (state[0..rate] = input)
/// - PRF outputs may differ from the previous implementation due to these
///   semantic differences
#[derive(Clone)]
pub(crate) struct RescuePRFCore<F: RescueParameter>(PhantomData<F>);

impl<F: RescueParameter> RescuePRFCore<F> {
    /// Keyed sponge-based pseudorandom function with zero padding.
    /// The padding scheme adds "0" until the length of padded input is a
    /// multiple of `CRHF_RATE` (3)
    pub(crate) fn keyed_sponge_with_zero_padding(
        key: &F,
        input: &[F],
        num_outputs: usize,
    ) -> Result<Vec<F>, RescueError> {
        let mut padded = input.to_vec();
        pad_with_zeros(&mut padded, CRHF_RATE); // Rate is CRHF_RATE (3)
        Self::keyed_sponge_no_padding(key, padded.as_slice(), num_outputs)
    }

    /// Keyed sponge-based pseudorandom function using rescue permutation with rate=3.
    /// It allows inputs with length that is a multiple of `CRHF_RATE` and returns a
    /// vector of `num_outputs` elements.
    pub(crate) fn keyed_sponge_no_padding(
        key: &F,
        input: &[F],
        num_outputs: usize,
    ) -> Result<Vec<F>, RescueError> {
        if input.len() % CRHF_RATE != 0 {
            return Err(RescueError::ParameterError(
                "Rescue PRF Error: input to prf function is not multiple of CRHF_RATE (3)."
                    .to_string(),
            ));
        }

        // Convert field element to bytes for spongefish IV
        let key_bigint_bytes = key.into_bigint().to_bytes_be();
        let mut key_bytes_be = [0u8; 32];
        let copy_len = usize::min(32, key_bigint_bytes.len());
        key_bytes_be[32 - copy_len..]
            .copy_from_slice(&key_bigint_bytes[key_bigint_bytes.len() - copy_len..]);

        // Use rate=3 (same as CRHF) to ensure capacity=1 for spongefish compatibility
        let mut sponge = RescueSponge::<F, CRHF_RATE>::new(key_bytes_be);
        sponge.absorb_unchecked(&input);

        let mut output = vec![F::default(); num_outputs];
        sponge.squeeze_unchecked(&mut output);
        Ok(output)
    }
}

#[derive(Debug, Clone)]
/// A rescue-based PRF that uses a keyed sponge construction with rate=3
pub struct RescuePRF<F: RescueParameter, const INPUT_LEN: usize, const OUTPUT_LEN: usize>(
    PhantomData<F>,
);

impl<F: RescueParameter, const INPUT_LEN: usize, const OUTPUT_LEN: usize> PRF
    for RescuePRF<F, INPUT_LEN, OUTPUT_LEN>
{
    type Input = [F; INPUT_LEN];
    type Output = [F; OUTPUT_LEN];
    type Seed = F;
    type Error = RescueError;

    fn evaluate<S: Borrow<Self::Seed>, I: Borrow<Self::Input>>(
        seed: S,
        input: I,
    ) -> Result<Self::Output, Self::Error> {
        let mut output = [F::zero(); OUTPUT_LEN];
        output.clone_from_slice(&RescuePRFCore::keyed_sponge_with_zero_padding(
            seed.borrow(),
            input.borrow(),
            OUTPUT_LEN,
        )?);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crhf::RescueCRHF,
        prf::{RescuePRF, RescuePRFCore, PRF},
        RescueParameter,
    };
    use ark_bls12_377::{Fq as Fq377, Fr as Fr377};
    use ark_bls12_381::Fr as Fr381;
    use ark_bn254::{Fq as Fq254, Fr as Fr254};
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::{vec, UniformRand};
    macro_rules! test_prf {
        ($tr:tt) => {
            let mut rng = jf_utils::test_rng();
            let seed = $tr::rand(&mut rng);
            let input = [$tr::from(1u8)];

            assert!(RescuePRF::<$tr, 1, 15>::evaluate(&seed, &input).is_ok());
            // check correctness
            assert_eq!(
                RescuePRF::<$tr, 1, 15>::evaluate(&seed, &input)
                    .unwrap()
                    .to_vec(),
                RescuePRFCore::keyed_sponge_with_zero_padding(&seed, &input, 15)
                    .unwrap()
            );
        };
    }

    #[test]
    pub fn test_prf() {
        test_prf!(FqEd254);
        test_prf!(FqEd377);
        test_prf!(FqEd381);
        test_prf!(Fq377);
        test_prf!(Fq254);
    }

    #[test]
    fn test_fsks_no_padding_errors() {
        test_fsks_no_padding_errors_helper::<Fq254>();
        test_fsks_no_padding_errors_helper::<Fr254>();
        test_fsks_no_padding_errors_helper::<Fr377>();
        test_fsks_no_padding_errors_helper::<Fr381>();
        test_fsks_no_padding_errors_helper::<Fq377>();
    }
    fn test_fsks_no_padding_errors_helper<F: RescueParameter>() {
        let key = F::rand(&mut jf_utils::test_rng());

        // Test inputs that are multiples of 3 (rate) - should succeed
        let input = vec![F::from(9u64); 3];
        assert!(
            RescuePRFCore::keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );
        let input = vec![F::from(9u64); 12];
        assert!(
            RescuePRFCore::keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );

        // Test inputs that are NOT multiples of 3 (rate) - should fail
        let input = vec![F::from(9u64); 4]; // 4 % 3 != 0
        assert!(
            RescuePRFCore::keyed_sponge_no_padding(&key, input.as_slice(), 1).is_err()
        );
        let input = vec![F::from(9u64); 10]; // 10 % 3 != 0
        assert!(
            RescuePRFCore::keyed_sponge_no_padding(&key, input.as_slice(), 1).is_err()
        );
        let input = vec![F::from(9u64)]; // 1 % 3 != 0
        assert!(
            RescuePRFCore::keyed_sponge_no_padding(&key, input.as_slice(), 1).is_err()
        );

        // Empty input (0 % 3 == 0) should succeed
        let input = vec![];
        assert!(
            RescuePRFCore::keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );
    }

    #[test]
    fn test_variable_output_sponge_and_fsks() {
        test_variable_output_sponge_and_fsks_helper::<Fq254>();
        test_variable_output_sponge_and_fsks_helper::<Fr254>();
        test_variable_output_sponge_and_fsks_helper::<Fr377>();
        test_variable_output_sponge_and_fsks_helper::<Fr381>();
        test_variable_output_sponge_and_fsks_helper::<Fq377>();
    }
    fn test_variable_output_sponge_and_fsks_helper<F: RescueParameter>() {
        let input = [F::zero(), F::one(), F::zero()];
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 0).len(), 0);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 1).len(), 1);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 2).len(), 2);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 3).len(), 3);
        assert_eq!(RescueCRHF::sponge_with_bit_padding(&input, 10).len(), 10);

        assert_eq!(RescueCRHF::sponge_no_padding(&input, 0).unwrap().len(), 0);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 1).unwrap().len(), 1);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 2).unwrap().len(), 2);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 3).unwrap().len(), 3);
        assert_eq!(RescueCRHF::sponge_no_padding(&input, 10).unwrap().len(), 10);

        let key = F::rand(&mut jf_utils::test_rng());
        let input = [F::zero(), F::one(), F::zero()];
        assert_eq!(
            RescuePRFCore::keyed_sponge_with_zero_padding(&key, &input, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_with_zero_padding(&key, &input, 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_with_zero_padding(&key, &input, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_with_zero_padding(&key, &input, 4)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_with_zero_padding(&key, &input, 10)
                .unwrap()
                .len(),
            10
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_no_padding(&key, &input, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_no_padding(&key, &input, 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_no_padding(&key, &input, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_no_padding(&key, &input, 4)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            RescuePRFCore::keyed_sponge_no_padding(&key, &input, 10)
                .unwrap()
                .len(),
            10
        );
    }
}
