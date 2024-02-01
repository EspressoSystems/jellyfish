use ark_ff::{BigInteger, PrimeField};
use ark_std::{
    borrow::Borrow,
    iter::Take,
    marker::PhantomData,
    vec::{IntoIter, Vec},
};

/// Deterministic, infallible, invertible iterator adaptor to convert from
/// arbitrary bytes to field elements.
///
/// The final field element is padded with zero bytes as needed.
///
/// # Example
///
/// [doctest ignored because it's a private module.]
/// ```ignore
/// # use jf_primitives::vid::advz::{bytes_to_field};
/// # use ark_ed_on_bn254::Fr as Fr254;
/// let bytes = [1, 2, 3];
/// let mut elems_iter = bytes_to_field::<_, Fr254>(bytes);
/// assert_eq!(elems_iter.next(), Some(Fr254::from(197121u64)));
/// assert_eq!(elems_iter.next(), None);
/// ```
///
/// # Panics
///
/// Panics only under conditions that should be checkable at compile time:
///
/// - The [`PrimeField`] modulus bit length is too small to hold a `u64`.
/// - The [`PrimeField`] byte length is too large to fit inside a `usize`.
///
/// If any of the above conditions holds then this function *always* panics.
pub fn bytes_to_field<I, F>(bytes: I) -> impl Iterator<Item = F>
where
    F: PrimeField,
    I: IntoIterator,
    I::Item: Borrow<u8>,
{
    BytesToField::new(bytes.into_iter())
}

/// Deterministic, infallible inverse of [`bytes_to_field`].
///
/// The composition of [`field_to_bytes`] with [`bytes_to_field`] might contain
/// extra zero bytes.
///
/// # Example
///
/// [doctest ignored because it's a private module.]
/// ```ignore
/// # use jf_primitives::vid::advz::{bytes_to_field, field_to_bytes};
/// # use ark_ed_on_bn254::Fr as Fr254;
/// let bytes = [1, 2, 3];
/// let mut bytes_iter = field_to_bytes(bytes_to_field::<_, Fr254>(bytes));
/// assert_eq!(bytes_iter.next(), Some(1));
/// assert_eq!(bytes_iter.next(), Some(2));
/// assert_eq!(bytes_iter.next(), Some(3));
/// for _ in 0..28 {
///     assert_eq!(bytes_iter.next(), Some(0));
/// }
/// assert_eq!(bytes_iter.next(), None);
/// ```
///
/// ## Panics
///
/// Panics under the conditions listed at [`bytes_to_field`].
pub fn field_to_bytes<I, F>(elems: I) -> impl Iterator<Item = u8>
where
    F: PrimeField,
    I: IntoIterator,
    I::Item: Borrow<F>,
{
    FieldToBytes::new(elems.into_iter())
}

struct BytesToField<I, F> {
    bytes_iter: I,
    elem_byte_capacity: usize,
    _phantom: PhantomData<F>,
}

impl<I, F> BytesToField<I, F>
where
    F: PrimeField,
{
    fn new(bytes_iter: I) -> Self {
        Self {
            bytes_iter,
            elem_byte_capacity: elem_byte_capacity::<F>(),
            _phantom: PhantomData,
        }
    }
}

impl<I, F> Iterator for BytesToField<I, F>
where
    I: Iterator,
    I::Item: Borrow<u8>,
    F: PrimeField,
{
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        let mut elem_bytes = Vec::with_capacity(self.elem_byte_capacity);
        for _ in 0..elem_bytes.capacity() {
            if let Some(byte) = self.bytes_iter.next() {
                elem_bytes.push(*byte.borrow());
            } else {
                break;
            }
        }
        if elem_bytes.is_empty() {
            None
        } else {
            Some(F::from_le_bytes_mod_order(&elem_bytes))
        }
    }
}

struct FieldToBytes<I, F> {
    elems_iter: I,
    bytes_iter: Take<IntoIter<u8>>,
    elem_byte_capacity: usize,
    _phantom: PhantomData<F>,
}

impl<I, F> FieldToBytes<I, F>
where
    F: PrimeField,
{
    fn new(elems_iter: I) -> Self {
        Self {
            elems_iter,
            bytes_iter: Vec::new().into_iter().take(0),
            elem_byte_capacity: elem_byte_capacity::<F>(),
            _phantom: PhantomData,
        }
    }
}

impl<I, F> Iterator for FieldToBytes<I, F>
where
    I: Iterator,
    I::Item: Borrow<F>,
    F: PrimeField,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(byte) = self.bytes_iter.next() {
            return Some(byte);
        }
        if let Some(elem) = self.elems_iter.next() {
            self.bytes_iter = elem
                .borrow()
                .into_bigint()
                .to_bytes_le()
                .into_iter()
                .take(self.elem_byte_capacity);
            return self.bytes_iter.next();
        }
        None
    }
}

/// Return the number of bytes that can be encoded into a generic [`PrimeField`]
/// parameter.
///
/// Returns the byte length of the [`PrimeField`] modulus minus 1.
///
/// It should be possible to do all this at compile time but I don't know how.
/// Want to panic on overflow, so use checked arithetic and type conversion.
pub fn elem_byte_capacity<F: PrimeField>() -> usize {
    usize::try_from((F::MODULUS_BIT_SIZE - 1) / 8)
        .expect("prime field modulus byte len should fit into usize")
}

#[cfg(test)]
mod tests {
    use super::{bytes_to_field, field_to_bytes, PrimeField, Vec};
    use ark_ed_on_bls12_377::Fr as Fr377;
    use ark_ed_on_bls12_381::Fr as Fr381;
    use ark_ed_on_bn254::Fr as Fr254;
    use ark_std::rand::RngCore;

    fn bytes_to_field_iter<F: PrimeField>() {
        let byte_lens = [0, 1, 2, 16, 31, 32, 33, 48, 65, 100, 200, 5000];

        let max_len = *byte_lens.iter().max().unwrap();
        let mut bytes = Vec::with_capacity(max_len);
        // TODO pre-allocate space for elems, owned, borrowed
        let mut rng = jf_utils::test_rng();

        for len in byte_lens {
            // fill bytes with random bytes and trailing zeros
            bytes.resize(len, 0);
            rng.fill_bytes(&mut bytes);

            // round trip, owned:
            // bytes as Iterator<Item = u8>, elems as Iterator<Item = F>
            let owned: Vec<_> = field_to_bytes(bytes_to_field::<_, F>(bytes.clone()))
                .take(bytes.len())
                .collect();
            assert_eq!(owned, bytes);

            // round trip, borrowed:
            // bytes as Iterator<Item = &u8>, elems as Iterator<Item = &F>
            let elems: Vec<_> = bytes_to_field::<_, F>(bytes.iter()).collect();
            let borrowed: Vec<_> = field_to_bytes::<_, F>(elems.iter())
                .take(bytes.len())
                .collect();
            assert_eq!(borrowed, bytes);
        }

        // empty input -> empty output
        let bytes = Vec::new();
        assert!(bytes.first().is_none());
        let mut elems_iter = bytes_to_field::<_, F>(bytes.iter());
        assert!(elems_iter.next().is_none());

        // 1-item input -> 1-item output
        let bytes = [42u8; 1];
        let mut elems_iter = bytes_to_field::<_, F>(bytes.iter());
        assert_eq!(elems_iter.next().unwrap(), F::from(42u64));
        assert!(elems_iter.next().is_none());
    }

    #[test]
    fn test_bytes_field_elems_iter() {
        bytes_to_field_iter::<Fr254>();
        bytes_to_field_iter::<Fr377>();
        bytes_to_field_iter::<Fr381>();
    }
}
