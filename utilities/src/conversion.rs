// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use core::mem;

use ark_ec::CurveConfig;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::{cmp::min, format, string::String, vec::Vec};
use sha2::{Digest, Sha512};

/// Convert a scalar field element to a base field element.
/// Mod reduction is not performed since the conversion occurs
/// for fields on a same curve.
pub fn fr_to_fq<F, P>(scalar: &P::ScalarField) -> F
where
    F: PrimeField,
    P: CurveConfig<BaseField = F>,
{
    // sanity checks:
    // ensure | jubjub scalar field | <= | BLS Scalar field |
    // jubjub scalar field:
    // 6554484396890773809930967563523245729705921265872317281365359162392183254199
    // BLS12-381 scalar field:
    // 52435875175126190479447740508185965837690552500527637822603658699938581184513
    // jubjub377 scalar field:
    // 2111115437357092606062206234695386632838870926408408195193685246394721360383
    // BLS12-377 scalar field:
    // 8444461749428370424248824938781546531375899335154063827935233455917409239041
    F::from_le_bytes_mod_order(&scalar.into_bigint().to_bytes_le())
}

/// Convert a base field element to a scalar field element.
/// Perform a mod reduction if the base field element is greater than
/// the modulus of the scalar field.
pub fn fq_to_fr<F, P>(base: &F) -> P::ScalarField
where
    F: PrimeField,
    P: CurveConfig<BaseField = F>,
{
    P::ScalarField::from_le_bytes_mod_order(&base.into_bigint().to_bytes_le())
}

/// Convert a field element in F(rom) to a field element in T(o),
/// with |T| < |F|; truncating the element via masking the top
/// F::MODULUS_BIT_SIZE - T::MODULUS_BIT_SIZE with 0s
pub fn fq_to_fr_with_mask<F, T>(base: &F) -> T
where
    F: PrimeField,
    T: PrimeField,
{
    assert!(T::MODULUS_BIT_SIZE < F::MODULUS_BIT_SIZE);
    let length = (T::MODULUS_BIT_SIZE >> 3) as usize;
    // ensure that no mod reduction happened
    T::from_le_bytes_mod_order(&base.into_bigint().to_bytes_le()[0..length])
}

// convert a field element in F(rom)
// to a field element in T(o).
// return an error if a mod reduction occurs.
#[inline]
pub fn field_switching<F, T>(base: &F) -> T
where
    F: PrimeField,
    T: PrimeField,
{
    let bytes = base.into_bigint().to_bytes_le();
    let t = T::from_le_bytes_mod_order(&bytes);

    // check t == base
    // i.e., t did not overflow the target field
    let bytes_rec = t.into_bigint().to_bytes_le();
    let length = min(bytes.len(), bytes_rec.len());
    assert_eq!(bytes_rec[0..length], bytes[0..length],);
    t
}

/// Hash a sequence of bytes to into a field
/// element, whose order is less than 256 bits.
pub fn hash_to_field<B, F>(bytes: B) -> F
where
    B: AsRef<[u8]>,
    F: PrimeField,
{
    // we extract a random `rand_byte_len` bytes from the hash
    // the compute res = OS2IP(output) mod p
    // which is less than 2^-128 from uniform
    let rand_byte_len = (F::MODULUS_BIT_SIZE + 7) as usize / 8 + 128 / 8;
    let mut hasher = Sha512::default();
    hasher.update(bytes.as_ref());
    let output = &hasher.finalize()[0..rand_byte_len];

    F::from_le_bytes_mod_order(output)
}

/// Invertible, deterministic, infallible conversion from arbitrary bytes to
/// field elements.
pub fn bytes_to_field_elements<B, F>(bytes: B) -> Vec<F>
where
    B: AsRef<[u8]>,
    F: Field,
{
    // Need to ensure that F::characteristic is large enough to hold a u64.
    // This should be possible at compile time but I don't know how.
    // Example: could use <https://docs.rs/static_assertions> but then you hit
    // <https://users.rust-lang.org/t/error-e0401-cant-use-generic-parameters-from-outer-function/84512>
    assert!(F::BasePrimeField::MODULUS_BIT_SIZE > 64);

    // - partition bytes into chunks of length one fewer than the base prime field
    //   modulus byte length
    // - convert each chunk into PrimeField via from_le_bytes_mod_order
    // - modular reduction is guaranteed not to occur because chunk byte length is
    //   sufficiently small
    // - collect PrimeField elements into Field elements and append to result
    let primefield_chunk_len = ((F::BasePrimeField::MODULUS_BIT_SIZE - 1) / 8) as usize;
    let extension_degree = F::extension_degree() as usize;
    let field_chunk_len = primefield_chunk_len * extension_degree;
    let result_length = (bytes.as_ref().len() + field_chunk_len - 1) / field_chunk_len + 1;
    let mut result = Vec::with_capacity(result_length);

    // the first field element encodes the bytes length as u64
    result.push(F::from(bytes.as_ref().len() as u64));

    for field_chunk in bytes.as_ref().chunks(field_chunk_len) {
        let mut primefield_elems = Vec::with_capacity(extension_degree);
        for primefield_chunk in field_chunk.chunks(primefield_chunk_len) {
            primefield_elems.push(F::BasePrimeField::from_le_bytes_mod_order(primefield_chunk));
        }
        // not enough prime field elems? fill remaining elems with zero
        if primefield_elems.len() < extension_degree {
            for _ in 0..(extension_degree - primefield_elems.len()) {
                primefield_elems.push(F::BasePrimeField::ZERO);
            }
        }
        assert_eq!(primefield_elems.len(), extension_degree);
        result.push(F::from_base_prime_field_elems(&primefield_elems).unwrap());
    }
    assert_eq!(result.len(), result_length);
    result
}

/// Inverse of `bytes_to_field_elements`.
/// Preconditions:
/// - Each base prime field element must fit into one fewer byte than the
///   modulus.
/// - The first field element encodes the length of bytes to return as u64.
/// TODO String error?
pub fn bytes_from_field_elements<T, F>(elems: T) -> Result<Vec<u8>, String>
where
    T: AsRef<[F]>,
    F: Field,
{
    // Need to ensure that F::characteristic is large enough to hold a u64.
    // This should be possible at compile time but I don't know how.
    // Example: could use <https://docs.rs/static_assertions> but then you hit
    // <https://users.rust-lang.org/t/error-e0401-cant-use-generic-parameters-from-outer-function/84512>
    assert!(F::BasePrimeField::MODULUS_BIT_SIZE > 64);

    let (first_elem, elems) = elems.as_ref().split_first().ok_or("empty elems")?;

    // the first element encodes the number of bytes to return
    let first_elem = first_elem
        .to_base_prime_field_elements()
        .next()
        .ok_or("empty first elem")?;
    let first_elem_bytes = first_elem.into_bigint().to_bytes_le();
    let first_elem_bytes = first_elem_bytes
        .get(..mem::size_of::<u64>())
        .ok_or("can't read result len from field element: not enough bytes")?;
    let result_len = u64::from_le_bytes(first_elem_bytes.try_into().unwrap());
    let result_len =
        usize::try_from(result_len).map_err(|_| "can't convert result len u64 to usize")?;

    let primefield_chunk_len = ((F::BasePrimeField::MODULUS_BIT_SIZE - 1) / 8) as usize;
    let extension_degree = F::extension_degree() as usize;
    let field_chunk_len = primefield_chunk_len * extension_degree;
    let result_capacity = elems.len() * field_chunk_len;

    // the original bytes must end somewhere in the final field element
    // thus, result_len must be within elem_byte_len of result_capacity
    if result_len > result_capacity || result_len < result_capacity - field_chunk_len {
        return Err(format!(
            "result len {} out of bounds {}..{}",
            result_len,
            result_capacity - field_chunk_len,
            result_capacity
        ));
    }

    // for each base prime field element:
    // - convert to bytes
    // - drop the trailing byte, which must be zero
    // - append bytes to result
    let mut result = Vec::with_capacity(result_capacity);
    for elem in elems {
        for primefield_elem in elem.to_base_prime_field_elements() {
            let bytes = primefield_elem.into_bigint().to_bytes_le();
            assert_eq!(bytes.len(), primefield_chunk_len + 1);
            let (last_byte, bytes) = bytes
                .split_last()
                .ok_or("prime field elem bytes has 0 len")?;
            if *last_byte != 0 {
                return Err(format!(
                    "nonzero last byte {} in prime field elem",
                    *last_byte
                ));
            }
            result.extend_from_slice(bytes);
        }
    }
    assert_eq!(result.len(), result_capacity);

    // all bytes to truncate should be zero
    for byte in result.iter().skip(result_len) {
        if *byte != 0 {
            return Err("nonzero bytes beyond result len".into());
        }
    }
    result.truncate(result_len);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::test_rng;

    use super::*;
    use ark_ed_on_bls12_377::{EdwardsConfig as Param377, Fr as Fr377};
    use ark_ed_on_bls12_381::{EdwardsConfig as Param381, Fr as Fr381};
    use ark_ed_on_bn254::{EdwardsConfig as Param254, Fr as Fr254};
    use ark_std::{rand::RngCore, UniformRand};

    #[test]
    fn test_bn254_scalar_conversion() {
        let mut rng = test_rng();
        for _ in 0..6 {
            let jj = Fr254::rand(&mut rng);
            let jj_bls = fr_to_fq::<_, Param254>(&jj);
            assert!(jj.into_bigint() == jj_bls.into_bigint());
        }
    }

    #[test]
    fn test_jubjub_bls_scalar_conversion_377() {
        let mut rng = test_rng();
        for _ in 0..6 {
            let jj = Fr377::rand(&mut rng);
            let jj_bls = fr_to_fq::<_, Param377>(&jj);
            assert!(jj.into_bigint() == jj_bls.into_bigint());
        }
    }

    #[test]
    fn test_jubjub_bls_scalar_conversion_381() {
        let mut rng = test_rng();
        for _ in 0..6 {
            let jj = Fr381::rand(&mut rng);
            let jj_bls = fr_to_fq::<_, Param381>(&jj);
            assert!(jj.into_bigint() == jj_bls.into_bigint());
        }
    }

    fn bytes_field_elems<F: Field>() {
        let mut rng = test_rng();
        let lengths = [2, 16, 32, 48, 63, 64, 65, 100, 200];

        for len in lengths {
            let mut random_bytes = vec![0u8; len];
            rng.fill_bytes(&mut random_bytes);

            let elems: Vec<F> = bytes_to_field_elements(&random_bytes);
            let result = bytes_from_field_elements(elems).unwrap();
            assert_eq!(result, random_bytes);
        }

        // trailing zeros
        let bytes = [5, 4, 3, 2, 1, 0];
        let elems: Vec<F> = bytes_to_field_elements(&bytes);
        let result = bytes_from_field_elements(&elems).unwrap();
        assert_eq!(result, bytes);
    }

    #[test]
    fn test_bytes_field_elems() {
        bytes_field_elems::<Fr381>();
        bytes_field_elems::<Fr254>();
    }
}
