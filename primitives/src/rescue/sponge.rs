// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This file contains the APIs wrappers for ark-sponge

use ark_crypto_primitives::sponge::{
    Absorb, CryptographicSponge, FieldBasedCryptographicSponge, FieldElementSize, SpongeExt,
};
use ark_ff::PrimeField;
use ark_std::{string::ToString, vec, vec::Vec};
use jf_utils::pad_with_zeros;

use super::{
    errors::RescueError, Permutation, RescueParameter, RescueVector, CRHF_RATE, STATE_SIZE,
};

#[derive(Clone, Default, Debug)]
/// A rescue hash function consists of a permutation function and
/// an internal state.
struct RescueSponge<F: RescueParameter, const RATE: usize> {
    pub(crate) state: RescueVector<F>,
    pub(crate) permutation: Permutation<F>,
}

/// CRHF
#[derive(Debug, Clone)]
pub(crate) struct RescueCRHF<F: RescueParameter> {
    sponge: RescueSponge<F, CRHF_RATE>,
}

/// PRF
#[derive(Debug, Clone)]
pub(crate) struct RescuePRFCore<F: RescueParameter> {
    sponge: RescueSponge<F, STATE_SIZE>,
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
    pub(crate) fn sponge_with_bit_padding(input: &[F], num_outputs: usize) -> Vec<F> {
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
    pub(crate) fn sponge_with_zero_padding(input: &[F], num_outputs: usize) -> Vec<F> {
        let mut padded = input.to_vec();
        pad_with_zeros(&mut padded, CRHF_RATE);
        Self::sponge_no_padding(padded.as_slice(), num_outputs)
            .expect("Bug in JF Primitives : bad padding of input for FSKS construction")
    }

    /// Sponge hashing based on rescue permutation for RATE 3 and CAPACITY 1. It
    /// allows inputs with length that is a multiple of `CRHF_RATE` and
    /// returns a vector of `num_outputs` elements.
    pub(crate) fn sponge_no_padding(input: &[F], num_output: usize) -> Result<Vec<F>, RescueError> {
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

impl<F: RescueParameter, const RATE: usize> SpongeExt for RescueSponge<F, RATE> {
    type State = RescueVector<F>;

    fn from_state(state: Self::State, permutation: &Self::Config) -> Self {
        Self {
            state,
            permutation: permutation.clone(),
        }
    }

    fn into_state(self) -> Self::State {
        self.state
    }
}

impl<T: RescueParameter + PrimeField, const RATE: usize> CryptographicSponge
    for RescueSponge<T, RATE>
{
    /// Config used by the sponge.
    type Config = Permutation<T>;

    /// Initialize a new instance of the sponge.
    fn new(permutation: &Self::Config) -> Self {
        Self {
            state: RescueVector::default(),
            permutation: permutation.clone(),
        }
    }

    /// Absorb an input into the sponge.
    /// This function will absorb the entire input, in chunks of `RATE`,
    /// even if the input lenght is not a multiple of `RATE`.
    fn absorb(&mut self, input: &impl Absorb) {
        let input_field_elements = input.to_sponge_field_elements_as_vec();

        // Absorb input.
        input_field_elements.chunks(RATE).for_each(|chunk| {
            self.state.add_assign_elems(chunk);
            self.state = self.permutation.eval(&self.state)
        });
    }

    /// WARNING! This trait method is unimplemented and should not be used.
    /// Only use the `CryptographicSponge` for squeezing native field elements.
    fn squeeze_bytes(&mut self, _num_bytes: usize) -> Vec<u8> {
        unimplemented!("Currently we only support squeezing native field elements!")
    }

    /// WARNING! This trait method is unimplemented and should not be used.
    /// Only use the `CryptographicSponge` for squeezing native field elements.
    fn squeeze_bits(&mut self, _num_bits: usize) -> Vec<bool> {
        unimplemented!("Currently we only support squeezing native field elements!")
    }

    /// WARNING! This trait method is unimplemented and should not be used.
    /// Use `squeeze_native_field_elements` instead.
    fn squeeze_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        _sizes: &[FieldElementSize],
    ) -> Vec<F> {
        unimplemented!("Currently we only support squeezing native field elements!")
    }

    /// WARNING! This trait method is unimplemented and should not be used.
    /// Use `squeeze_native_field_elements` instead.
    fn squeeze_field_elements<F: PrimeField>(&mut self, _num_elements: usize) -> Vec<F> {
        unimplemented!("Currently we only support squeezing native field elements!")
    }

    /// Creates a new sponge with applied domain separation.
    fn fork(&self, domain: &[u8]) -> Self {
        let mut new_sponge = self.clone();

        let mut input = Absorb::to_sponge_bytes_as_vec(&domain.len());
        input.extend_from_slice(domain);
        new_sponge.absorb(&input);

        new_sponge
    }
}

/// The interface for field-based cryptographic sponge.
/// `T` is the native field used by the cryptographic sponge implementation.
impl<T: RescueParameter, const RATE: usize> FieldBasedCryptographicSponge<T>
    for RescueSponge<T, RATE>
{
    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<T> {
        // SQUEEZE PHASE
        let mut result = vec![];
        let mut remaining = num_elements;
        // extract current rate before calling PRP again
        loop {
            let extract = remaining.min(RATE);
            result.extend_from_slice(&self.state.vec[0..extract]);
            remaining -= extract;
            if remaining == 0 {
                break;
            }
            self.state = self.permutation.eval(&self.state)
        }
        result
    }

    /// WARNING! This trait method is unimplemented and should not be used.
    /// Use `squeeze_native_field_elements` instead.
    fn squeeze_native_field_elements_with_sizes(&mut self, _sizes: &[FieldElementSize]) -> Vec<T> {
        unimplemented!("Currently we only support squeezing native field elements!")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_crypto_primitives::{
        absorb, collect_sponge_bytes, collect_sponge_field_elements, sponge::AbsorbWithLength,
    };
    use ark_ff::{One, UniformRand};
    use jf_utils::test_rng;

    fn assert_different_encodings<F: RescueParameter, A: Absorb>(a: &A, b: &A) {
        let bytes1 = a.to_sponge_bytes_as_vec();
        let bytes2 = b.to_sponge_bytes_as_vec();
        assert_ne!(bytes1, bytes2);

        let sponge_param = Permutation::default();
        let mut sponge1 = RescueSponge::<F, 3>::new(&sponge_param);
        let mut sponge2 = RescueSponge::<F, 3>::new(&sponge_param);

        sponge1.absorb(&a);
        sponge2.absorb(&b);

        assert_ne!(
            sponge1.squeeze_native_field_elements(3),
            sponge2.squeeze_native_field_elements(3)
        );
    }

    #[test]
    fn single_field_element() {
        let mut rng = test_rng();
        let elem1 = Fr::rand(&mut rng);
        let elem2 = elem1 + Fr::one();

        assert_different_encodings::<Fr, _>(&elem1, &elem2)
    }

    #[test]
    fn list_with_constant_size_element() {
        let mut rng = test_rng();
        let lst1: Vec<_> = (0..1024 * 8).map(|_| Fr::rand(&mut rng)).collect();
        let mut lst2 = lst1.to_vec();
        lst2[3] += Fr::one();

        assert_different_encodings::<Fr, _>(&lst1, &lst2)
    }

    struct VariableSizeList(Vec<u8>);

    impl Absorb for VariableSizeList {
        fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
            self.0.to_sponge_bytes_with_length(dest)
        }

        fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
            self.0.to_sponge_field_elements_with_length(dest)
        }
    }

    #[test]
    fn list_with_nonconstant_size_element() {
        let lst1 = vec![
            VariableSizeList(vec![1u8, 2, 3, 4]),
            VariableSizeList(vec![5, 6]),
        ];
        let lst2 = vec![
            VariableSizeList(vec![1u8, 2]),
            VariableSizeList(vec![3, 4, 5, 6]),
        ];

        assert_different_encodings::<Fr, _>(&lst1, &lst2);
    }

    #[test]
    fn test_macros() {
        let sponge_param = Permutation::default();
        let mut sponge1 = RescueSponge::<Fr, 3>::new(&sponge_param);
        sponge1.absorb(&vec![1u8, 2, 3, 4, 5, 6]);
        sponge1.absorb(&Fr::from(114514u128));

        let mut sponge2 = RescueSponge::<Fr, 3>::new(&sponge_param);
        absorb!(&mut sponge2, vec![1u8, 2, 3, 4, 5, 6], Fr::from(114514u128));

        let expected = sponge1.squeeze_native_field_elements(3);
        let actual = sponge2.squeeze_native_field_elements(3);

        assert_eq!(actual, expected);

        let mut expected = Vec::new();
        vec![6u8, 5, 4, 3, 2, 1].to_sponge_bytes(&mut expected);
        Fr::from(42u8).to_sponge_bytes(&mut expected);

        let actual = collect_sponge_bytes!(vec![6u8, 5, 4, 3, 2, 1], Fr::from(42u8));

        assert_eq!(actual, expected);

        let mut expected: Vec<Fr> = Vec::new();
        vec![6u8, 5, 4, 3, 2, 1].to_sponge_field_elements(&mut expected);
        Fr::from(42u8).to_sponge_field_elements(&mut expected);

        let actual: Vec<Fr> =
            collect_sponge_field_elements!(vec![6u8, 5, 4, 3, 2, 1], Fr::from(42u8));

        assert_eq!(actual, expected);
    }
}
