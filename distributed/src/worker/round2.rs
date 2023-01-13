use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{batch_inversion, One, UniformRand};
use fn_timer::fn_timer;
use rand::thread_rng;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use super::PlonkImplInner;
use crate::{gpu::FFTDomain, polynomial::VecPolynomial};

impl PlonkImplInner {
    #[fn_timer]
    pub fn compute_z_evals(&self, beta: Fr, gamma: Fr) -> Vec<Fr> {
        let k = self.k[self.me];

        let mut w_evals = self.w_evals.load().unwrap();

        let mut denominators = w_evals
            .par_iter()
            .zip_eq(self.sigma_evals.mmap().unwrap().par_iter())
            .take(self.n - 1)
            .map(|(w, sigma)| gamma + beta * sigma + w)
            .collect::<Vec<_>>();

        batch_inversion(&mut denominators);

        w_evals
            .par_iter_mut()
            .enumerate()
            .take(self.n - 1)
            .for_each(|(i, w)| *w += gamma + beta * k * self.domain1.element(i));

        w_evals.pop();

        let mut numerators = w_evals;

        numerators.par_iter_mut().zip_eq(denominators).for_each(|(n, d)| {
            *n *= d;
        });

        let mut z = numerators;

        let mut t = Fr::one();
        (0..(self.n - 1)).for_each(|i| {
            (z[i], t) = (t, t * z[i]);
        });
        z.push(t);

        z
    }

    pub fn update_z_evals(&self, z_self: &mut Vec<Fr>, z_other: &[Fr]) {
        z_self.par_iter_mut().zip(z_other).for_each(|(z_self, z_other)| {
            *z_self *= z_other;
        });
    }

    pub fn compute_and_commit_z(&self, z: &mut Vec<Fr>) -> G1Projective {
        let mut r = {
            let rng = &mut thread_rng();
            vec![Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)]
        };

        self.domain1.ifft_ii(z);
        z.add_mut(r.mul_by_vanishing_poly(self.n));
        assert_eq!(z.len(), self.n + 3);

        self.commit_polynomial(z)
    }
}
