// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A rescue PRF implementation

use crate::{
    sponge::RescueSponge, Permutation, RescueError, RescueParameter, RescueVector, STATE_SIZE,
};
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge, SpongeExt,
};
use ark_std::{borrow::Borrow, marker::PhantomData, string::ToString, vec::Vec};
use jf_primitives_core::prf::PRF;
use jf_utils::pad_with_zeros;

/// Rescue PRF
#[derive(Debug, Clone)]
pub(crate) struct RescuePRFCore<F: RescueParameter> {
    sponge: RescueSponge<F, STATE_SIZE>,
}

impl<F: RescueParameter> RescuePRFCore<F> {
    /// Similar to [`Self::full_state_keyed_sponge_with_bit_padding`] except the
    /// padding scheme are all "0" until the length of padded input is a
    /// multiple of `STATE_SIZE`
    pub(crate) fn full_state_keyed_sponge_with_zero_padding(
        key: &F,
        input: &[F],
        num_outputs: usize,
    ) -> Result<Vec<F>, RescueError> {
        let mut padded = input.to_vec();
        pad_with_zeros(&mut padded, STATE_SIZE);
        Self::full_state_keyed_sponge_no_padding(key, padded.as_slice(), num_outputs)
    }

    /// Pseudorandom function based on rescue permutation for RATE 4. It allows
    /// inputs with length that is a multiple of `STATE_SIZE` and returns a
    /// vector of `num_outputs` elements.
    pub(crate) fn full_state_keyed_sponge_no_padding(
        key: &F,
        input: &[F],
        num_outputs: usize,
    ) -> Result<Vec<F>, RescueError> {
        if input.len() % STATE_SIZE != 0 {
            return Err(RescueError::ParameterError(
                "Rescue FSKS PRF Error: input to prf function is not multiple of STATE_SIZE."
                    .to_string(),
            ));
        }
        // ABSORB PHASE
        let mut state = RescueVector::zero();
        state.vec[STATE_SIZE - 1] = *key;
        let mut r = Self {
            sponge: RescueSponge::from_state(state, &Permutation::default()),
        };
        r.sponge.absorb(&input);

        // SQUEEZE PHASE
        Ok(r.sponge.squeeze_native_field_elements(num_outputs))
    }
}

#[derive(Debug, Clone)]
/// A rescue-based PRF that leverages on Full State Keyed (FSK) sponge
/// construction
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
        output.clone_from_slice(&RescuePRFCore::full_state_keyed_sponge_with_zero_padding(
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
                RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&seed, &input, 15)
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
        let input = vec![F::from(9u64); 4];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );
        let input = vec![F::from(9u64); 12];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
        );

        // test should panic because number of inputs is not multiple of 3
        let input = vec![F::from(9u64); 10];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_err()
        );
        let input = vec![F::from(9u64)];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_err()
        );

        let input = vec![];
        assert!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1).is_ok()
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
        let input = [F::zero(), F::one(), F::zero(), F::zero()];
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 4)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&key, &input, 10)
                .unwrap()
                .len(),
            10
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 4)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            RescuePRFCore::full_state_keyed_sponge_no_padding(&key, &input, 10)
                .unwrap()
                .len(),
            10
        );
    }
}
