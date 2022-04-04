//! This file contains the APIs wrappers for ark-sponge

use crate::{
    param::{RescueParameter, RATE},
    structs::RescueVector,
    Permutation, RescueHash,
};
use ark_ff::{BigInteger, PrimeField};
use ark_sponge::{Absorb, CryptographicSponge, FieldBasedCryptographicSponge, FieldElementSize};
use jf_utils::pad_with_zeros;
use num_bigint::BigUint;

impl<T: RescueParameter> CryptographicSponge for RescueHash<T> {
    /// Parameters used by the sponge.
    type Parameters = Permutation<T>;

    /// Initialize a new instance of the sponge.
    fn new(params: &Self::Parameters) -> Self {
        Self {
            state: RescueVector::default(),
            permutation: params.clone(),
        }
    }

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &impl Absorb) {
        let mut input_field_elements = input.to_sponge_field_elements_as_vec();
        // Pad input as follows: append a One, then pad with 0 until length is multiple
        // of RATE
        input_field_elements.push(T::one());
        pad_with_zeros(&mut input_field_elements, RATE);

        input_field_elements
            .chunks_exact(RATE)
            .into_iter()
            .for_each(|chunk| {
                let block = RescueVector::pad_smaller_chunk(chunk);
                self.state.add_assign(&block);
                self.state = self.permutation.eval(&self.state)
            });
    }

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        self.squeeze_bits(num_bytes)
            .chunks(8)
            .map(|x| bools_to_u8(x))
            .collect()
    }

    /// Squeeze `num_bits` bits from the sponge.
    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        // we extract k number of field elements;
        // each field elements will produce a maximum
        // ```
        // T::size_in_bits() - 129
        // ```
        // number of bits that is computational uniform.
        // For simplicity, we will extract 120 bits
        #[cfg(debug_assertions)]
        assert!(T::size_in_bits() > 248);

        let mut result = Vec::new();
        let mut remaining = num_bits;

        // we extract 3 elements with a hash call
        let extracted_bits_per_elem = T::size_in_bits() - 129;
        let mut elem_ctr = 0;
        // let extracted_bits_per_hash = 3*extracted_bits_per_elem;
        let mut extracted = self.state.vec;
        self.state = self.permutation.eval(&self.state);
        // modulus is 2^extracted_bits_per_elem
        let modulus: BigUint = T::from(2u64).pow(&[extracted_bits_per_elem as u64]).into();

        while remaining > extracted_bits_per_elem {
            let e_int: BigUint = extracted[elem_ctr].into();
            elem_ctr += 1;
            if elem_ctr == 3 {
                extracted = self.state.vec;
                self.state = self.permutation.eval(&self.state);
                elem_ctr = 0;
            }

            let extracted_bit = e_int % &modulus;
            result.extend_from_slice(
                &T::from(extracted_bit).into_repr().to_bits_le()[0..extracted_bits_per_elem],
            );
            remaining -= extracted_bits_per_elem;
        }

        let e_int: BigUint = extracted[elem_ctr].into();
        let extracted_bit = e_int % &modulus;
        result.extend_from_slice(&T::from(extracted_bit).into_repr().to_bits_le()[0..remaining]);

        result
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
        if T::size_in_bits() == F::size_in_bits() {
            let mut res_f = Vec::with_capacity(sizes.len());
            let res_t = RescueHash::<T>::squeeze_native_field_elements_with_sizes(self, sizes);
            batch_field_cast(&res_t, &mut res_f).unwrap();
            res_f
        } else {
            // currently we do not support hashing into a non-native field
            unimplemented!()
        }
    }

    /// Squeeze `num_elements` nonnative field elements from the sponge.
    ///
    /// Because of rust limitation, for field-based implementation, using this
    /// method to squeeze native field elements will have runtime casting
    /// cost. For better efficiency, use `squeeze_native_field_elements`.
    fn squeeze_field_elements<F: PrimeField>(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_field_elements_with_sizes::<F>(
            vec![FieldElementSize::Full; num_elements].as_slice(),
        )
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
/// `CF` is the native field used by the cryptographic sponge implementation.
impl<T: RescueParameter> FieldBasedCryptographicSponge<T> for RescueHash<T> {
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

    /// Squeeze `sizes.len()` field elements from the sponge, where the `i`-th
    /// element of the output has size `sizes[i]`.
    fn squeeze_native_field_elements_with_sizes(&mut self, sizes: &[FieldElementSize]) -> Vec<T> {
        let mut all_full_sizes = true;
        for size in sizes {
            if *size != FieldElementSize::Full {
                all_full_sizes = false;
                break;
            }
        }

        if all_full_sizes {
            self.squeeze_native_field_elements(sizes.len())
        } else {
            // we do not currently want to output field elements other than T.
            // This will be fixed once `squeeze_bytes` interfaces is fixed.
            unimplemented!()
        }
    }
}

#[inline]
fn bools_to_u8(input: &[bool]) -> u8 {
    let mut res = 0;
    for &e in input {
        res <<= 1;
        if e {
            res += 1
        }
    }
    res
}

/// If `F1` equals to `F2`, add all elements of `x` as `F2` to `dest` and
/// returns `dest` pointer.
///
/// This function will return None and no-op if `F1` is not equal to `F2`.
pub(crate) fn batch_field_cast<'a, F1: PrimeField, F2: PrimeField>(
    x: &[F1],
    dest: &'a mut Vec<F2>,
) -> Option<&'a mut Vec<F2>> {
    if F1::characteristic() != F2::characteristic() {
        // "Trying to absorb non-native field elements."
        None
    } else {
        x.iter().for_each(|item| {
            let mut buf = Vec::new();
            item.serialize(&mut buf).unwrap();
            dest.push(F2::from_le_bytes_mod_order(&buf))
        });
        Some(dest)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, UniformRand};
    use ark_sponge::{
        absorb, collect_sponge_bytes, collect_sponge_field_elements, AbsorbWithLength,
    };
    use ark_std::test_rng;

    fn assert_different_encodings<F: RescueParameter, A: Absorb>(a: &A, b: &A) {
        let bytes1 = a.to_sponge_bytes_as_vec();
        let bytes2 = b.to_sponge_bytes_as_vec();
        assert_ne!(bytes1, bytes2);

        let sponge_param = Permutation::default();
        let mut sponge1 = RescueHash::<F>::new(&sponge_param);
        let mut sponge2 = RescueHash::<F>::new(&sponge_param);

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
    fn test_squeeze_cast_native() {
        let mut rng = test_rng();
        let sponge_param = Permutation::default();
        let elem = Fr::rand(&mut rng);
        let mut sponge1 = RescueHash::<Fr>::new(&sponge_param);
        sponge1.absorb(&elem);
        let mut sponge2 = sponge1.clone();

        // those two should return same result
        let squeezed1 = sponge1.squeeze_native_field_elements(5);
        let squeezed2 = sponge2.squeeze_field_elements::<Fr>(5);

        assert_eq!(squeezed1, squeezed2);
    }

    #[test]
    fn test_macros() {
        let sponge_param = Permutation::default();
        let mut sponge1 = RescueHash::<Fr>::new(&sponge_param);
        sponge1.absorb(&vec![1u8, 2, 3, 4, 5, 6]);
        sponge1.absorb(&Fr::from(114514u128));

        let mut sponge2 = RescueHash::<Fr>::new(&sponge_param);
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
