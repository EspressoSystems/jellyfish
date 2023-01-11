use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{Field, One};

use super::{PlonkImplInner, Selectors};
use crate::polynomial::VecPolynomial;

impl PlonkImplInner {
    pub fn finalize_t_part1(
        &self,
        t: &mut Vec<Fr>,
        z: &[Fr],
        w_of_zeta: Fr,
        v: Fr,
        s1: Fr,
        s2: Fr,
    ) {
        let x = -(self.zeta.pow([self.n as u64]) - Fr::one())
            * self.zeta.pow([((self.n + 2) * (4 - self.me)) as u64]);

        match &self.q {
            Selectors::Type1 { a, h } | Selectors::Type2 { a, h, .. } => {
                t.scale_mut(x)
                    .add_scaled_mut(&a.mmap().unwrap(), w_of_zeta)
                    .add_scaled_mut(&h.mmap().unwrap(), w_of_zeta * w_of_zeta.square().square())
                    .add_scaled_mut(&self.w.mmap().unwrap(), v.pow([self.me as u64 + 1]))
                    .add_scaled_mut(&self.sigma.mmap().unwrap(), v.pow([self.me as u64 + 6]));
            }
            Selectors::Type3 { o, c, .. } => {
                t.scale_mut(x)
                    .add_mut(&c.mmap().unwrap())
                    .add_scaled_mut(&o.mmap().unwrap(), -w_of_zeta)
                    .add_scaled_mut(&self.w.mmap().unwrap(), v.pow([self.me as u64 + 1]))
                    .add_scaled_mut(z, s1)
                    .add_scaled_mut(&self.sigma.mmap().unwrap(), s2);
            }
        };
    }

    pub fn finalize_t_part2(&self, t: &mut Vec<Fr>, w_of_zeta: Fr) {
        match &self.q {
            Selectors::Type2 { m, .. } => {
                t.add_scaled_mut(&m.mmap().unwrap(), w_of_zeta);
            }
            _ => unreachable!(),
        }
    }

    pub fn finalize_t_part3(&self, t: &mut Vec<Fr>, w_of_zeta: Fr) {
        match &self.q {
            Selectors::Type3 { e, .. } => {
                t.add_scaled_mut(&e.mmap().unwrap(), w_of_zeta);
            }
            _ => unreachable!(),
        }
    }

    pub fn compute_opening_proof(&self, t: &mut Vec<Fr>) -> G1Projective {
        let mut x = t.pop().unwrap();
        for i in (0..t.len()).rev() {
            (t[i], x) = (x, t[i] + x * self.zeta);
        }
        self.commit_polynomial(t)
    }

    pub fn compute_shifted_opening_proof(&self, z: &mut Vec<Fr>) -> G1Projective {
        let mut x = z.pop().unwrap();
        for i in (0..z.len()).rev() {
            (z[i], x) = (x, z[i] + x * self.domain1.generator() * self.zeta);
        }
        let r = self.commit_polynomial(z);
        *z = Default::default();
        r
    }
}
