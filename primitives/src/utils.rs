// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use crate::{elgamal, signatures::schnorr};
use ark_ec::{models::TEModelParameters, ProjectiveCurve, TEModelParameters as Parameters};
use ark_ff::{FpParameters, PrimeField};
use ark_std::vec::Vec;
use jf_plonk::circuit::Variable;

impl<F, P> From<&schnorr::VerKey<P>> for (F, F)
where
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
{
    fn from(vk: &schnorr::VerKey<P>) -> Self {
        let point = vk.0.into_affine();
        (point.x, point.y)
    }
}

impl<P> From<&elgamal::EncKey<P>> for (P::BaseField, P::BaseField)
where
    P: Parameters + Clone,
{
    fn from(pk: &elgamal::EncKey<P>) -> Self {
        let point = pk.key.into_affine();
        (point.x, point.y)
    }
}

#[inline]
pub(crate) fn pad_with(vec: &mut Vec<Variable>, multiple: usize, var: Variable) {
    let len = vec.len();
    let new_len = if len % multiple == 0 {
        len
    } else {
        len + multiple - len % multiple
    };
    vec.resize(new_len, var);
}

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
