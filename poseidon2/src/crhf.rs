//! Collision-resistant Hash Function (CRHF) based on Poseidon2 permutation

use core::marker::PhantomData;

use ark_ff::{Field, PrimeField};
use ark_std::{borrow::Borrow, string::ToString, vec::Vec};
use jf_crhf::CRHF;
use spongefish::{
    duplex_sponge::{DuplexSponge, Permutation},
    DuplexSpongeInterface, Unit,
};

use crate::{sponge::Poseidon2Sponge, Poseidon2Error};

/// Sponge-based CRHF where the Sponge uses Poseidon2 permutation
/// Input length is fixed: the actual input can be shorter, but will internally
/// be zero-padded to `INPUT_SIZE`
///
/// Example:
/// `FixedLenPoseidon2Hash<ark_bn254::Fr, Poseidon2SpongeStateBnN3R1, 6, 2>`
#[derive(Clone)]
pub struct FixedLenPoseidon2Hash<F, S, const INPUT_SIZE: usize, const OUTPUT_SIZE: usize>
where
    F: PrimeField + Unit,
    S: Permutation<U = F> + Poseidon2Sponge,
{
    _field: PhantomData<F>,
    _sponge: PhantomData<S>,
}

impl<F, S, const IN: usize, const OUT: usize> CRHF for FixedLenPoseidon2Hash<F, S, IN, OUT>
where
    F: PrimeField + Unit,
    S: Permutation<U = F> + Poseidon2Sponge,
{
    type Input = [F]; // length should be <= IN
    type Output = [F; OUT];
    type Error = Poseidon2Error;

    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, Self::Error> {
        let input = input.borrow();
        if input.len() > IN {
            return Err(Poseidon2Error::ParamErr("hash input too long".to_string()));
        }

        let mut padded = Vec::from(input);
        zero_padding(&mut padded, IN);

        let mut sponge = DuplexSponge::<S>::default();
        sponge.absorb_unchecked(&padded);
        let mut output = [F::default(); OUT];
        sponge.squeeze_unchecked(&mut output);
        Ok(output)
    }
}

/// Sponge-based CRHF where the Sponge uses Poseidon2 permutation, with
/// variable-length input
#[derive(Debug, Clone)]
pub struct VariableLenPoseidon2Hash<F, S, const OUTPUT_SIZE: usize>
where
    F: PrimeField + Unit,
    S: Permutation<U = F>,
{
    _field: PhantomData<F>,
    _sponge: PhantomData<S>,
}

impl<F, S, const OUT: usize> CRHF for VariableLenPoseidon2Hash<F, S, OUT>
where
    F: PrimeField + Unit,
    S: Permutation<U = F>,
{
    type Input = [F];
    type Output = [F; OUT];
    type Error = Poseidon2Error;

    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, Self::Error> {
        let mut padded = Vec::from(input.borrow());
        bit_padding(&mut padded, S::R);

        let mut sponge = DuplexSponge::<S>::default();
        sponge.absorb_unchecked(&padded);
        let mut output = [F::default(); OUT];
        sponge.squeeze_unchecked(&mut output);
        Ok(output)
    }
}

// pad `data` with zeros until the length is the next multiple of `multiple`
#[inline(always)]
fn zero_padding<F: Field>(data: &mut Vec<F>, multiple: usize) {
    data.resize(data.len().next_multiple_of(multiple), F::zero());
}

// pad `data` with "10..0" (always pad "1"), until the length is the next
// multiple of `multiple`
#[inline(always)]
fn bit_padding<F: Field>(data: &mut Vec<F>, multiple: usize) {
    data.push(F::one());
    zero_padding(data, multiple);
}
