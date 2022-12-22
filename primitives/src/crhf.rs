// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Collision-resistant Hash Functions (CRHF) definitions and implementations.

use ark_std::{
    borrow::Borrow, fmt::Debug, hash::Hash, marker::PhantomData, string::ToString, vec::Vec,
};

use crate::{
    errors::PrimitivesError,
    rescue::{sponge::RescueCRHF, RescueParameter, CRHF_RATE},
};

/// A trait for CRHF
/// (based on ark-primitives' definition, but self-declared for minimal
/// dependency and easier future upgradability.)
pub trait CRHF {
    /// Input to the CRHF
    type Input;
    /// Output of the CRHF
    // FIXME: (alex) wait until arkwork 0.4.0 to add the following:
    // + Default + CanonicalSerialize + CanonicalDeserialize;
    // right now, const-generic are not supported yet.
    type Output: Clone + PartialEq + Eq + Hash + Debug;

    /// evaluate inputs and return hash output
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, PrimitivesError>;
}

#[derive(Debug, Clone)]
/// A rescue-sponge-based CRHF with fixed-input size (if not multiple of 3 will
/// get auto-padded) and variable-output size
pub struct FixedLengthRescueCRHF<
    F: RescueParameter,
    const INPUT_LEN: usize,
    const OUTPUT_LEN: usize,
>(PhantomData<F>);

impl<F: RescueParameter, const INPUT_LEN: usize, const OUTPUT_LEN: usize> CRHF
    for FixedLengthRescueCRHF<F, INPUT_LEN, OUTPUT_LEN>
{
    type Input = [F; INPUT_LEN];
    type Output = [F; OUTPUT_LEN];

    /// ## Padding
    /// if `input` length is not a multiple of `CRHF_RATE`, then it will be
    /// padded. By default, we use "zero padding"-style where as many "0" as
    /// required are added.
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, PrimitivesError> {
        let mut output = [F::zero(); OUTPUT_LEN];

        let res = match INPUT_LEN % CRHF_RATE {
            0 => RescueCRHF::<F>::sponge_no_padding(input.borrow(), OUTPUT_LEN)?,
            _ => RescueCRHF::<F>::sponge_with_zero_padding(input.borrow(), OUTPUT_LEN),
        };
        if res.len() != OUTPUT_LEN {
            return Err(PrimitivesError::InternalError(
                "Unexpected rescue sponge return length".to_string(),
            ));
        }

        output.copy_from_slice(&res[..]);
        Ok(output)
    }
}

#[derive(Debug, Clone)]
/// A rescue-sponge-based CRHF with variable-input and variable-output size
pub struct VariableLengthRescueCRHF<F: RescueParameter, const OUTPUT_LEN: usize>(PhantomData<F>);

impl<F: RescueParameter, const OUTPUT_LEN: usize> CRHF for VariableLengthRescueCRHF<F, OUTPUT_LEN> {
    type Input = Vec<F>;
    type Output = [F; OUTPUT_LEN];

    /// ## Padding
    /// if `input` length is not a multiple of `CRHF_RATE`, then it will be
    /// padded. By default, we use "bit padding"-style where "1" is always
    /// appended, then as many "0" as required are added for the overall
    /// length to be a multiple of `CRHF_RATE`.
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, PrimitivesError> {
        let mut output = [F::zero(); OUTPUT_LEN];
        let res = RescueCRHF::<F>::sponge_with_bit_padding(input.borrow(), OUTPUT_LEN);
        if res.len() != OUTPUT_LEN {
            return Err(PrimitivesError::InternalError(
                "Unexpected rescue sponge return length".to_string(),
            ));
        }
        output.copy_from_slice(&res[..]);
        Ok(output)
    }
}
