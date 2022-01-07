//! Constants for curve specific parameters

use ark_ec::models::TEModelParameters;
use ark_ff::{FpParameters, PrimeField};

#[inline]
pub(crate) fn field_byte_len<F: PrimeField>() -> usize {
    ((F::Params::MODULUS_BITS + 7) / 8) as usize
}

#[inline]
pub(crate) fn field_bit_len<F: PrimeField>() -> usize {
    F::Params::MODULUS_BITS as usize
}

#[inline]
pub(crate) fn challenge_bit_len<F: PrimeField>() -> usize {
    // Our challenge is of size 248 bits
    // This is enough for a soundness error of 2^-128
    (field_byte_len::<F>() - 1) << 3
}

#[inline]
pub(crate) fn curve_cofactor<P: TEModelParameters>() -> u64 {
    P::COFACTOR[0]
}
