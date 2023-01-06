use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_std::vec::Vec;
use rayon::prelude::*;

pub trait VecPolynomial {
    fn remove_leading_zeros(&mut self, min_len: usize) -> &mut Self;

    fn add_mut(&mut self, other: &[Fr]) -> &mut Self;

    fn add_scaled_mut(&mut self, other: &[Fr], elem: Fr) -> &mut Self;

    fn add_mut_offset(&mut self, other: &[Fr], offset: usize) -> &mut Self;

    fn add_scaled_mut_offset(&mut self, other: &[Fr], elem: Fr, offset: usize) -> &mut Self;

    fn scale_mut(&mut self, elem: Fr) -> &mut Self;

    fn mul_by_vanishing_poly(&self, n: usize) -> Self;
}

impl VecPolynomial for Vec<Fr> {
    fn remove_leading_zeros(&mut self, min_len: usize) -> &mut Self {
        let mut i = self.len();
        while i > min_len && self[i - 1].is_zero() {
            i -= 1;
        }

        self.truncate(i);
        self.shrink_to_fit();

        self
    }

    fn add_mut(&mut self, other: &[Fr]) -> &mut Self {
        if self.len() < other.len() {
            self.resize(other.len(), Fr::zero());
        }
        self.par_iter_mut().zip(other).for_each(|(a, b)| {
            *a += b;
        });
        self.remove_leading_zeros(0)
    }

    fn add_scaled_mut(&mut self, other: &[Fr], elem: Fr) -> &mut Self {
        if self.len() < other.len() {
            self.resize(other.len(), Fr::zero());
        }
        self.par_iter_mut().zip(other).for_each(|(a, b)| {
            *a += elem * b;
        });
        self.remove_leading_zeros(0)
    }

    fn add_mut_offset(&mut self, other: &[Fr], offset: usize) -> &mut Self {
        if self.len() < offset + other.len() {
            self.resize(offset + other.len(), Fr::zero());
        }
        self[offset..].par_iter_mut().zip(other).for_each(|(a, b)| {
            *a += b;
        });
        self.remove_leading_zeros(0)
    }

    fn add_scaled_mut_offset(&mut self, other: &[Fr], elem: Fr, offset: usize) -> &mut Self {
        if self.len() < offset + other.len() {
            self.resize(offset + other.len(), Fr::zero());
        }
        self[offset..].par_iter_mut().zip(other).for_each(|(a, b)| {
            *a += elem * b;
        });
        self.remove_leading_zeros(0)
    }

    fn scale_mut(&mut self, elem: Fr) -> &mut Self {
        self.par_iter_mut().for_each(|e| {
            *e *= elem;
        });
        self
    }

    fn mul_by_vanishing_poly(&self, n: usize) -> Self {
        let mut shifted = vec![Fr::zero(); n];
        shifted.extend_from_slice(self);
        shifted.par_iter_mut().zip(self.par_iter()).for_each(|(s, c)| *s -= c);
        shifted.remove_leading_zeros(0);
        shifted
    }
}
