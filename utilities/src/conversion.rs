// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use ark_ec::CurveConfig;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::{
    borrow::Borrow,
    cmp::min,
    iter::{once, repeat},
    mem,
    vec::Vec,
};
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

/// Deterministic, infallible, invertible conversion from arbitrary bytes to
/// field elements.
///
/// # How it works
///
/// - The first [`Field`] element in the result encodes `bytes` length as a
///   `u64`.
/// - Partition `bytes` into chunks of length P, where P is the field
///   characteristic byte length minus 1.
/// - Convert each chunk into [`Field::BasePrimeField`] via
///   [`PrimeField::from_le_bytes_mod_order`]. Reduction modulo the field
///   characteristic is guaranteed not to occur because chunk byte length is
///   sufficiently small.
/// - Collect [`Field::BasePrimeField`] elements into [`Field`] elements and
///   append to result.
/// - If `bytes` is empty then result is empty.
///
/// # Panics
///
/// Panics only under conditions that should be checkable at compile time:
///
/// - The [`Field::BasePrimeField`] modulus bit length is too small to hold a
///   `u64`.
/// - The byte length of a single [`Field::BasePrimeField`] element fails to fit
///   inside a `usize`.
/// - The extension degree of the [`Field`] fails to fit inside a `usize`.
/// - The byte length of a [`Field`] element fails to fit inside a `usize`.
///
/// If any of the above conditions holds then this function *always* panics.
pub fn bytes_to_field_elements<B, F>(bytes: B) -> Vec<F>
where
    B: Borrow<[u8]>,
    F: Field,
{
    let bytes = bytes.borrow();
    let (primefield_bytes_len, extension_degree, field_bytes_len) = compile_time_checks::<F>();
    if bytes.is_empty() {
        return Vec::new();
    }

    // Result length is always less than `bytes` length for sufficiently large
    // `bytes`. Thus, the following should never panic.
    let result_len = (field_bytes_len
        .checked_add(bytes.len())
        .expect("result len should fit into usize")
        - 1)
        / field_bytes_len
        + 1;

    let result = once(F::from(bytes.len() as u64)) // the first field element encodes the bytes length as u64
        .chain(bytes.chunks(field_bytes_len).map(|field_elem_bytes| {
            F::from_base_prime_field_elems(
                &field_elem_bytes.chunks(primefield_bytes_len)
                .map(F::BasePrimeField::from_le_bytes_mod_order)
                // not enough prime field elems? fill remaining elems with zero
                .chain(repeat(F::BasePrimeField::ZERO).take(
                    extension_degree - (field_elem_bytes.len()-1) / primefield_bytes_len - 1)
                )
                .collect::<Vec<_>>(),
            )
            .expect("failed to construct field element")
        }))
        .collect::<Vec<_>>();

    // sanity check
    assert_eq!(
        result.len(),
        result_len,
        "invalid result len, expect {}, found {}",
        result_len,
        result.len()
    );
    result
}

/// Deterministic, infallible inverse of [`bytes_to_field_elements`].
///
/// This function is not invertible because [`bytes_to_field_elements`] is not
/// onto.
///
/// ## Panics
///
/// Panics under the conditions listed at [`bytes_to_field_elements`], or if the
/// length of the return `Vec<u8>` overflows `usize`.
pub fn bytes_from_field_elements<T, F>(elems: T) -> Vec<u8>
where
    T: Borrow<[F]>,
    F: Field,
{
    let elems = elems.borrow();
    let (primefield_bytes_len, _, field_bytes_len) = compile_time_checks::<F>();
    if elems.is_empty() {
        return Vec::new();
    }

    let (first_elem, elems) = elems.split_first().expect("elems should be non-empty");

    // the first element encodes the number of bytes to return
    let result_len = usize::try_from(u64::from_le_bytes(
        first_elem
            .to_base_prime_field_elements()
            .next()
            .expect("first base prime field elem should be non-empty")
            .into_bigint()
            .to_bytes_le()[..mem::size_of::<u64>()]
            .try_into()
            .expect("conversion from [u8] to u64 should succeed"),
    ))
    .expect("result len conversion from u64 to usize should succeed");

    let result_capacity = field_bytes_len
        .checked_mul(elems.len())
        .expect("result capacity should fit into usize");

    // If `elems` was produced by `bytes_to_field_elements`
    // then the original bytes MUST end before the final field element
    // so we expect `result_len <= result_capacity`.
    // But if `elems` is arbitrary then `result_len` could be large,
    // so we enforce `result_len <= result_capacity`.
    // Do not enforce a lower bound on `result_len` because the caller might
    // pad `elems`, for example with extra zeros from polynomial interpolation.
    let result_len = min(result_len, result_capacity);

    // for each base prime field element:
    // - convert to bytes
    // - drop the trailing byte
    // - append bytes to result
    let mut result = Vec::with_capacity(result_capacity);
    for elem in elems {
        for primefield_elem in elem.to_base_prime_field_elements() {
            let primefield_bytes = primefield_elem.into_bigint().to_bytes_le();
            let (_, primefield_bytes) = primefield_bytes
                .split_last() // ignore the final byte of primefield_elem
                .expect("prime field elem bytes should be non-empty");
            assert_eq!(
                primefield_bytes.len(),
                primefield_bytes_len,
                "invalid prime field elem bytes len, expect {}, found {}",
                primefield_bytes_len,
                primefield_bytes.len()
            );
            result.extend_from_slice(primefield_bytes);
        }
    }

    // sanity check
    assert_eq!(
        result.len(),
        result_capacity,
        "invalid result len, expect {}, found {}",
        result_capacity,
        result.len()
    );

    result.truncate(result_len);
    result
}

/// Compute various `usize` quantities as a function of the generic [`Field`]
/// parameter.
///
/// It should be possible to do all this at compile time but I don't know how.
/// Want to panic on overflow, so use checked arithetic and type conversion.
///
/// # Returns
///
/// Returns the following tuple:
/// 1. The byte length P of the [`BasePrimeField`] modulus minus 1.
/// 2. The extension degree of the [`Field`].
/// 3. The total byte length of a single [`Field`] element under the constraint
/// that   each [`BasePrimeField`] element fits into only P bytes.
///
/// # Panics
///
/// Panics under the conditions listed at [`bytes_to_field_elements`].
fn compile_time_checks<F: Field>() -> (usize, usize, usize) {
    assert!(
        F::BasePrimeField::MODULUS_BIT_SIZE > 64,
        "base prime field modulus bit len {} too small to hold a u64",
        F::BasePrimeField::MODULUS_BIT_SIZE
    );

    let primefield_bytes_len = usize::try_from((F::BasePrimeField::MODULUS_BIT_SIZE - 1) / 8)
        .expect("prime field modulus byte len should fit into usize");
    let extension_degree =
        usize::try_from(F::extension_degree()).expect("extension degree should fit into usize");
    let field_bytes_len = primefield_bytes_len
        .checked_mul(extension_degree)
        .expect("field element byte len should fit into usize");
    (primefield_bytes_len, extension_degree, field_bytes_len)
}

#[cfg(test)]
mod tests {
    use crate::test_rng;

    use super::*;
    use ark_bls12_377::Fq12 as Fq12_377;
    use ark_bls12_381::Fq12 as Fq12_381;
    use ark_bn254::Fq12 as Fq12_254;
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
        let lengths = [0, 1, 2, 16, 31, 32, 33, 48, 65, 100, 200];
        let trailing_zeros_lengths = [0, 1, 2, 5, 50];

        let max_len = *lengths.iter().max().unwrap();
        let max_trailing_zeros_len = *trailing_zeros_lengths.iter().max().unwrap();
        let mut bytes = Vec::with_capacity(max_len + max_trailing_zeros_len);
        let mut elems: Vec<F> = Vec::with_capacity(max_len);
        let mut rng = test_rng();

        for len in lengths {
            for trailing_zeros_len in trailing_zeros_lengths {
                // fill bytes with random bytes and trailing zeros
                bytes.resize(len + trailing_zeros_len, 0);
                rng.fill_bytes(&mut bytes[..len]);
                bytes[len..].fill(0);

                // round trip
                let encoded_bytes: Vec<F> = bytes_to_field_elements(bytes.as_ref());
                let result = bytes_from_field_elements(encoded_bytes);
                assert_eq!(result, bytes);
            }

            // test infallibility of bytes_from_field_elements
            // with random field elements
            elems.resize(len, F::zero());
            elems.iter_mut().for_each(|e| *e = F::rand(&mut rng));
            bytes_from_field_elements(elems.as_ref());
        }
    }

    #[test]
    fn test_bytes_field_elems() {
        bytes_field_elems::<Fr381>();
        bytes_field_elems::<Fr377>();
        bytes_field_elems::<Fr254>();
        bytes_field_elems::<Fq12_381>();
        bytes_field_elems::<Fq12_377>();
        bytes_field_elems::<Fq12_254>();
    }
}
