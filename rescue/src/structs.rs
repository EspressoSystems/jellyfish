//! This module defines vector and matrix structs for rescue hash function.

use crate::param::{RescueParameter, STATE_SIZE};
use ark_ff::PrimeField;

#[derive(Clone, Debug, PartialEq, Copy, Default)]
/// Data type for rescue prp inputs, keys and internal data
pub struct RescueVector<F> {
    pub(crate) vec: [F; STATE_SIZE],
}

// Public functions
impl<F: PrimeField> RescueVector<F> {
    /// zero vector
    pub fn zero() -> RescueVector<F> {
        RescueVector {
            vec: [F::zero(); STATE_SIZE],
        }
    }

    /// Return vector of the field elements
    /// WARNING: may expose the internal state.
    pub fn elems(&self) -> Vec<F> {
        self.vec.to_vec()
    }

    /// Perform a linear transform of the vector.
    /// Function needs to be public for circuits generation..
    pub fn linear(&mut self, matrix: &RescueMatrix<F>, vector: &RescueVector<F>) {
        let mut aux = matrix.mul_vec(self);
        aux.add_assign(vector);
        *self = aux
    }
}

// Private functions
impl<F: PrimeField> RescueVector<F> {
    pub(crate) fn from_elems_le_bytes(
        e0: &[u8],
        e1: &[u8],
        e2: &[u8],
        e3: &[u8],
    ) -> RescueVector<F> {
        RescueVector {
            vec: [
                F::from_le_bytes_mod_order(e0),
                F::from_le_bytes_mod_order(e1),
                F::from_le_bytes_mod_order(e2),
                F::from_le_bytes_mod_order(e3),
            ],
        }
    }

    pub(crate) fn pad_smaller_chunk(input: &[F]) -> RescueVector<F> {
        assert!(input.len() < 4);
        let mut vec = Self::zero().vec;
        for (i, elem) in input.iter().enumerate() {
            vec[i] = *elem;
        }
        RescueVector { vec }
    }

    pub(crate) fn pow(&mut self, exp: &[u64]) {
        self.vec.iter_mut().for_each(|elem| {
            *elem = elem.pow(exp);
        });
    }

    pub(crate) fn add_assign(&mut self, vector: &RescueVector<F>) {
        for (a, b) in self.vec.iter_mut().zip(vector.vec.iter()) {
            a.add_assign(b);
        }
    }

    pub(crate) fn add(&self, vector: &RescueVector<F>) -> RescueVector<F> {
        let mut aux = *self;
        aux.add_assign(vector);
        aux
    }

    pub(crate) fn add_assign_elems(&mut self, elems: &[F]) {
        assert_eq!(elems.len(), STATE_SIZE);
        self.vec
            .iter_mut()
            .zip(elems.iter())
            .for_each(|(a, b)| a.add_assign(b));
    }

    fn dot_product(&self, vector: &RescueVector<F>) -> F {
        let mut r = F::zero();
        for (a, b) in self.vec.iter().zip(vector.vec.iter()) {
            r.add_assign(&a.mul(b));
        }
        r
    }
}

impl<F: RescueParameter> RescueVector<F> {
    /// Helper function to compute f(M,x,c) = Mx^a + c.
    /// Function needs to be public for circuits generation..
    pub fn non_linear(&mut self, matrix: &RescueMatrix<F>, vector: &RescueVector<F>) {
        let mut self_aux = *self;
        self_aux.pow(&[F::A]);
        let mut aux = matrix.mul_vec(&self_aux);
        aux.add_assign(vector);
        *self = aux;
    }
}

impl<F: Copy> From<&[F]> for RescueVector<F> {
    fn from(field_elems: &[F]) -> RescueVector<F> {
        assert_eq!(field_elems.len(), STATE_SIZE);
        RescueVector {
            vec: [
                field_elems[0],
                field_elems[1],
                field_elems[2],
                field_elems[3],
            ],
        }
    }
}

impl<F: Copy> From<&[F; STATE_SIZE]> for RescueVector<F> {
    fn from(field_elems: &[F; STATE_SIZE]) -> RescueVector<F> {
        RescueVector { vec: *field_elems }
    }
}

/// A matrix that consists of `STATE_SIZE` number of rescue vectors.
#[derive(Clone)]
pub struct RescueMatrix<F> {
    matrix: [RescueVector<F>; STATE_SIZE],
}

impl<F: PrimeField> From<&[RescueVector<F>; STATE_SIZE]> for RescueMatrix<F> {
    fn from(vectors: &[RescueVector<F>; STATE_SIZE]) -> Self {
        Self { matrix: *vectors }
    }
}

impl<F: PrimeField> RescueMatrix<F> {
    fn mul_vec(&self, vector: &RescueVector<F>) -> RescueVector<F> {
        let mut result = [F::zero(); STATE_SIZE];
        self.matrix
            .iter()
            .enumerate()
            .for_each(|(i, row)| result[i] = row.dot_product(vector));
        RescueVector { vec: result }
    }

    /// Accessing the i-th vector of the matrix.    
    /// Function needs to be public for circuits generation..
    /// WARNING: may expose the internal state.
    pub fn vec(&self, i: usize) -> RescueVector<F> {
        self.matrix[i]
    }

    /// Check if the matrix is empty.
    pub fn is_empty(&self) -> bool {
        self.matrix.is_empty()
    }

    /// Return the number of columns of the matrix.
    pub fn len(&self) -> usize {
        self.matrix.len()
    }
}
