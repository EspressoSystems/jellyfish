use std::ops::Range;

use ark_bls12_381::Fr;
use ark_ff::Zero;
use ark_std::vec::Vec;
use fn_timer::fn_timer;
use rayon::prelude::*;

fn add_within(v: &mut [Fr], to: Range<usize>, from: Range<usize>) {
    // SAFEFY:
    // We use `unsafe` here because a vector cannot have a mutable reference and an immutable reference at the same time.
    // This is actually safe because `to` and `from` are assumed to be disjoint.
    v[to].par_iter().zip(&v[from]).for_each(|(a, b)| unsafe {
        *(a as *const _ as *mut Fr) += b;
    });
}

pub trait VecPolynomial {
    fn remove_leading_zeros(&mut self, min_len: usize) -> &mut Self;

    fn add_mut(&mut self, other: &[Fr]) -> &mut Self;

    fn add_scaled_mut(&mut self, other: &[Fr], elem: Fr) -> &mut Self;

    fn add_scaled_mut_offset(&mut self, other: &[Fr], elem: Fr, offset: usize) -> &mut Self;

    fn scale_mut(&mut self, elem: Fr) -> &mut Self;

    fn mul_by_vanishing_poly(&mut self, n: usize) -> &mut Self;

    /// Divide a polynomial by the vanishing polynomial.
    /// The algorithm is in place, and the actual result is u[n..].
    /// The first n elements are not removed, so we can avoid a memory copy.
    fn div_by_vanishing_poly(&mut self, n: usize) -> &mut Self;
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
        self.par_iter_mut().zip(other).for_each(|(a, b)| *a += b);
        self.remove_leading_zeros(0)
    }

    fn add_scaled_mut(&mut self, other: &[Fr], elem: Fr) -> &mut Self {
        if self.len() < other.len() {
            self.resize(other.len(), Fr::zero());
        }
        self.par_iter_mut().zip(other).for_each(|(a, b)| *a += elem * b);
        self.remove_leading_zeros(0)
    }

    fn add_scaled_mut_offset(&mut self, other: &[Fr], elem: Fr, offset: usize) -> &mut Self {
        if self.len() < offset + other.len() {
            self.resize(offset + other.len(), Fr::zero());
        }
        self[offset..].par_iter_mut().zip(other).for_each(|(a, b)| *a += elem * b);
        self.remove_leading_zeros(0)
    }

    fn scale_mut(&mut self, elem: Fr) -> &mut Self {
        self.par_iter_mut().for_each(|e| *e *= elem);
        self
    }

    fn mul_by_vanishing_poly(&mut self, n: usize) -> &mut Self {
        let l = self.len();

        self.resize(n, Default::default());
        self.extend_from_within(..l);
        self[..l].par_iter_mut().for_each(|i| *i = -*i);
        self.remove_leading_zeros(0)
    }

    #[fn_timer]
    fn div_by_vanishing_poly(&mut self, n: usize) -> &mut Self {
        for i in (n..self.len()).step_by(n).rev() {
            add_within(self, i - n..i, i..i + n);
        }
        // Trick: add the remainder to the quotient.
        // Although at this point u is not divisible by the vanishing polynomial,
        // the numerator of the final quotient polynomial t will be.
        // One can check this by running the following code:
        // ```
        // let rng = &mut thread_rng();
        // let l = 1 << (rng.gen_range(1..20));
        // let domain = Radix2EvaluationDomain::<Fr>::new(l).unwrap();
        // let q = DensePolynomial::rand(l - 1, rng);
        // let a = DensePolynomial::rand(2 * l - 1, rng);
        // let b = &q.mul_by_vanishing_poly(domain) - &a;
        // let (q_1, r_1) = a.divide_by_vanishing_poly(domain).unwrap();
        // let (q_2, r_2) = b.divide_by_vanishing_poly(domain).unwrap();
        // assert_eq!(&q_1 + &q_2 + r_1 + r_2, q);
        // ```
        add_within(self, n..2 * n, 0..n);

        self.remove_leading_zeros(n)
    }
}
