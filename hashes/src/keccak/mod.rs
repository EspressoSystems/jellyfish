//! This file implements Sponge wrappers for sha3::keccak256

use ark_ff::PrimeField;
use ark_sponge::{Absorb, CryptographicSponge, FieldElementSize};
use ark_std::marker::PhantomData;
use sha3::Digest;

#[derive(Debug, Clone)]
/// A keccak Sponge consists of
/// - an internal state
/// - a hasher type
pub struct KeccakSponge<H: Digest> {
    _state: [u8; 32],
    phantom: PhantomData<H>,
}

impl<H: Digest + Clone> CryptographicSponge for KeccakSponge<H> {
    /// Parameters used by the sponge.
    type Parameters = H;

    /// Initialize a new instance of the sponge.
    fn new(_params: &Self::Parameters) -> Self {
        todo!()
    }

    /// Absorb an input into the sponge.
    fn absorb(&mut self, _input: &impl Absorb) {
        todo!()
    }

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_bytes(&mut self, _num_bytes: usize) -> Vec<u8> {
        todo!()
    }

    /// Squeeze `num_bits` bits from the sponge.
    fn squeeze_bits(&mut self, _num_bits: usize) -> Vec<bool> {
        todo!()
    }

    /// Squeeze `sizes.len()` field elements from the sponge, where the `i`-th
    /// element of the output has size `sizes[i]`.
    ///
    /// If the implementation is field-based, to squeeze native field elements,
    /// call `self.squeeze_native_field_elements` instead.
    ///
    /// TODO: Support general Field.
    ///
    /// Note that when `FieldElementSize` is `FULL`, the output is not strictly
    /// uniform. Output space is uniform in \[0, 2^{F::MODULUS_BITS - 1}\]
    fn squeeze_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Vec<F> {
        todo!()
    }
}
