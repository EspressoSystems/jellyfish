// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements a pseudo random function that is derived from
//! the rescue hash function.

use ark_std::marker::PhantomData;

use crate::{
    errors::PrimitivesError,
    rescue::{sponge::RescueSpongePRF, RescueParameter, STATE_SIZE},
};
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::{borrow::ToOwned, format, string::ToString, vec::Vec};
use jf_utils::pad_with_zeros;
use zeroize::Zeroize;

#[allow(clippy::upper_case_acronyms)]
/// Pseudo-random function (PRF) instance for user defined input and output size
pub struct PRF<F: RescueParameter> {
    /// Length of the input.
    pub input_len: usize,
    /// Length of the output.
    pub output_len: usize,
    phantom_f: PhantomData<F>,
}

#[derive(
    Clone, Default, Debug, PartialEq, Eq, Hash, Zeroize, CanonicalSerialize, CanonicalDeserialize,
)]
/// Key data-type of Pseudo-random function consisting on a single scalar
/// element.
pub struct PrfKey<F: PrimeField>(pub(crate) F);

impl<F: PrimeField> Drop for PrfKey<F> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<F: PrimeField> From<F> for PrfKey<F> {
    fn from(key: F) -> Self {
        PrfKey(key)
    }
}

impl<F: PrimeField> PrfKey<F> {
    /// return the internal field value
    pub fn internal(&self) -> F {
        self.0
    }
}

impl<F: RescueParameter> PRF<F> {
    /// Pseudo-random function instance constructor
    /// `input_len`: number of input scalars for the function
    /// `output_len`: number of scalar outputs for the function
    pub fn new(input_len: usize, output_len: usize) -> PRF<F> {
        PRF {
            input_len,
            output_len,
            phantom_f: PhantomData,
        }
    }

    /// Key generation for Pseudo-random function
    pub fn key_gen<R: ark_std::rand::RngCore>(&self, rng: &mut R) -> PrfKey<F> {
        PrfKey::from(F::rand(rng))
    }

    /// Compute output of pseudo-random function for a given key and input
    /// Return Err(PrimitivesError::ParameterError) if input length does not
    /// match instance defined input length
    pub fn eval(&self, key: &PrfKey<F>, input: &[F]) -> Result<Vec<F>, PrimitivesError> {
        if input.len() != self.input_len {
            return Err(PrimitivesError::ParameterError(format!(
                "PRF Error: input length ({}) does not match instance ({})",
                input.len(),
                self.input_len
            )));
        }
        // Ok to pad with 0's since input length is fixed for the PRF instance
        let mut padded = input.to_owned();
        pad_with_zeros(&mut padded, STATE_SIZE);
        RescueSpongePRF::full_state_keyed_sponge_no_padding(&key.0, &padded, self.output_len)
            .map_err(|_| {
                PrimitivesError::InternalError("Bug in PRF: bad padding for input".to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::prf::PRF;
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::One;
    use ark_std::vec;
    macro_rules! test_prf {
        ($tr:tt) => {
            let mut prng = ark_std::test_rng();
            let prf = PRF::new(1, 15);
            let key = prf.key_gen(&mut prng);
            let input = vec![$tr::one()];
            let out = prf.eval(&key, &input);
            assert!(out.is_ok());

            let input = vec![];
            let out = prf.eval(&key, &input);
            assert!(out.is_err());

            let input = vec![$tr::one(); 2];
            let out = prf.eval(&key, &input);
            assert!(out.is_err());
        };
    }

    #[test]
    pub fn test_prf() {
        test_prf!(FqEd254);
        test_prf!(FqEd377);
        test_prf!(FqEd381);
        test_prf!(Fq377);
    }
}
