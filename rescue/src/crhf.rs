// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! A rescue CRHF implementation

use crate::{
    sponge::RescueSponge, Permutation, RescueError, RescueParameter, RescueVector, CRHF_RATE,
};
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge, SpongeExt,
};
use ark_std::{borrow::Borrow, marker::PhantomData, string::ToString, vec::Vec};
use jf_crhf::CRHF;
use jf_utils::pad_with_zeros;

/// CRHF
#[derive(Debug, Clone)]
pub struct RescueCRHF<F: RescueParameter> {
    sponge: RescueSponge<F, CRHF_RATE>,
}

impl<F: RescueParameter> RescueCRHF<F> {
    /// Sponge hashing based on rescue permutation for RATE 3. It allows
    /// unrestricted variable length input and returns a vector of
    /// `num_outputs` elements.
    ///
    /// we use ["bit padding"-style][padding] where "1" is always appended, then
    /// as many "0" as required are added for the overall length to be a
    /// multiple of RATE
    ///
    /// [padding]: https://en.wikipedia.org/wiki/Padding_(cryptography)#Bit_padding
    pub fn sponge_with_bit_padding(input: &[F], num_outputs: usize) -> Vec<F> {
        let mut padded = input.to_vec();
        padded.push(F::one());
        pad_with_zeros(&mut padded, CRHF_RATE);
        Self::sponge_no_padding(padded.as_slice(), num_outputs)
            .expect("Bug in JF Primitives : bad padding of input for FSKS construction")
    }

    /// Similar to [`RescueCRHF::sponge_with_bit_padding`] except we use ["zero
    /// padding"][padding] where as many "0" as required are added for the
    /// overall length to be a multiple of RATE.
    ///
    /// [padding]: https://en.wikipedia.org/wiki/Padding_(cryptography)#Zero_padding
    pub fn sponge_with_zero_padding(input: &[F], num_outputs: usize) -> Vec<F> {
        let mut padded = input.to_vec();
        pad_with_zeros(&mut padded, CRHF_RATE);
        Self::sponge_no_padding(padded.as_slice(), num_outputs)
            .expect("Bug in JF Primitives : bad padding of input for FSKS construction")
    }

    /// Sponge hashing based on rescue permutation for RATE 3 and CAPACITY 1. It
    /// allows inputs with length that is a multiple of `CRHF_RATE` and
    /// returns a vector of `num_outputs` elements.
    pub fn sponge_no_padding(input: &[F], num_output: usize) -> Result<Vec<F>, RescueError> {
        if input.len() % CRHF_RATE != 0 {
            return Err(RescueError::ParameterError(
                "Rescue sponge Error : input to sponge hashing function is not multiple of RATE."
                    .to_string(),
            ));
        }
        // ABSORB PHASE
        let mut r = Self {
            sponge: RescueSponge::from_state(RescueVector::zero(), &Permutation::default()),
        };
        r.sponge.absorb(&input);

        // SQUEEZE PHASE
        Ok(r.sponge.squeeze_native_field_elements(num_output))
    }
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
    type Error = RescueError;

    /// ## Padding
    /// if `input` length is not a multiple of `CRHF_RATE`, then it will be
    /// padded. By default, we use "zero padding"-style where as many "0" as
    /// required are added.
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, Self::Error> {
        let mut output = [F::zero(); OUTPUT_LEN];

        let res = match INPUT_LEN % CRHF_RATE {
            0 => RescueCRHF::<F>::sponge_no_padding(input.borrow(), OUTPUT_LEN)?,
            _ => RescueCRHF::<F>::sponge_with_zero_padding(input.borrow(), OUTPUT_LEN),
        };
        if res.len() != OUTPUT_LEN {
            return Err(RescueError::ParameterError(
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
    type Error = RescueError;

    /// ## Padding
    /// if `input` length is not a multiple of `CRHF_RATE`, then it will be
    /// padded. By default, we use "bit padding"-style where "1" is always
    /// appended, then as many "0" as required are added for the overall
    /// length to be a multiple of `CRHF_RATE`.
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, Self::Error> {
        let mut output = [F::zero(); OUTPUT_LEN];
        let res = RescueCRHF::<F>::sponge_with_bit_padding(input.borrow(), OUTPUT_LEN);
        if res.len() != OUTPUT_LEN {
            return Err(RescueError::ParameterError(
                "Unexpected rescue sponge return length".to_string(),
            ));
        }
        output.copy_from_slice(&res[..]);
        Ok(output)
    }
}
