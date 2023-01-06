use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{Field, One};

use super::{PlonkImplInner, Selectors};
use crate::polynomial::VecPolynomial;

impl PlonkImplInner {
    pub fn finalize_t_part1(
        &self,
        t: &mut Vec<Fr>,
        zeta: Fr,
        w_of_zeta: Fr,
        v: Fr,
        s1: Fr,
        s2: Fr,
    ) {
        let x = -(zeta.pow(&[self.n as u64]) - Fr::one())
            * zeta.pow(&[((self.n + 2) * (4 - self.me)) as u64]);
        match &self.q {
            Selectors::Type1 { a, h } | Selectors::Type2 { a, h, .. } => {
                t.scale_mut(x)
                    .add_scaled_mut(&a.load().unwrap(), w_of_zeta)
                    .add_scaled_mut(&h.load().unwrap(), w_of_zeta * w_of_zeta.square().square())
                    .add_scaled_mut(&self.w.load().unwrap(), v.pow(&[self.me as u64 + 1]))
                    .add_scaled_mut(&self.sigma.load().unwrap(), v.pow(&[self.me as u64 + 6]));
            }
            Selectors::Type3 { o, c, .. } => {
                t.scale_mut(x)
                    .add_mut(&c.load().unwrap())
                    .add_scaled_mut(&o.load().unwrap(), -w_of_zeta)
                    .add_scaled_mut(&self.w.load().unwrap(), v.pow(&[self.me as u64 + 1]))
                    .add_scaled_mut(&self.z, s1)
                    .add_scaled_mut(&self.sigma.load().unwrap(), s2);
            }
        };
    }

    pub fn finalize_t_part2(&self, t: &mut Vec<Fr>, w_of_zeta: Fr) {
        match &self.q {
            Selectors::Type2 { m, .. } => {
                t.add_scaled_mut(&m.load().unwrap(), w_of_zeta);
            }
            _ => unreachable!(),
        }
    }

    pub fn finalize_t_part3(&self, t: &mut Vec<Fr>, w_of_zeta: Fr) {
        match &self.q {
            Selectors::Type3 { e, .. } => {
                t.add_scaled_mut(&e.load().unwrap(), w_of_zeta);
            }
            _ => unreachable!(),
        }
    }

    pub fn compute_opening_proof(&self, t: &mut Vec<Fr>, zeta: &Fr) -> G1Projective {
        let mut x = t.pop().unwrap();
        for i in (0..t.len()).rev() {
            (t[i], x) = (x, t[i] + x * zeta);
        }
        self.commit_polynomial(&t)
    }

    pub fn compute_shifted_opening_proof(&self, zeta: &Fr) -> G1Projective {
        let this = unsafe { &mut *(self as *const _ as *mut Self) };
        let mut x = this.z.pop().unwrap();
        for i in (0..this.z.len()).rev() {
            (this.z[i], x) = (x, this.z[i] + x * self.domain1.generator() * zeta);
        }
        let r = self.commit_polynomial(&this.z);
        this.z = Default::default();
        r
    }
}
