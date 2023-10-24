//! paylod module doc

// use ark_ff::PrimeField;
use ark_std::{
    // borrow::Borrow,
    slice::Iter,
    vec::{IntoIter, Vec},
};

/// payload
#[derive(Debug, PartialEq)]
pub struct Payload {
    // TODO store as Vec<F> instead?
    payload: Vec<u8>,
}

impl Payload {
    /// from_iter
    // pub fn from_iter<I>(payload: I) -> Self
    // where
    //     I: IntoIterator,
    //     I::Item: Borrow<u8>,
    // {
    //     Self {
    //         payload: payload.into_iter().map(|b| *b.borrow()).collect(),
    //     }
    // }

    /// from_vec
    pub fn from_vec(payload: Vec<u8>) -> Self {
        Self { payload }
    }

    /// as_slice
    pub fn as_slice(&self) -> &[u8] {
        &self.payload
    }

    /// iter
    pub fn iter(&self) -> Iter<'_, u8> {
        self.payload.iter()
    }

    // fn field_iter<F>(&self) -> impl Iterator<Item = F>
    // where
    //     F: PrimeField,
    // {
    //     todo!()
    // }
}

// delegation boilerplate
impl<'a> IntoIterator for &'a Payload {
    type Item = &'a u8;
    type IntoIter = Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// delegation boilerplate
impl IntoIterator for Payload {
    type Item = u8;
    type IntoIter = IntoIter<u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.payload.into_iter()
    }
}
