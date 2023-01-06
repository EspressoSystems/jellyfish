use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{One, UniformRand};
use fn_timer::fn_timer;
use rand::Rng;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

use super::{PlonkImplInner, Utils};
use crate::polynomial::VecPolynomial;

impl PlonkImplInner {
    #[fn_timer]
    pub fn compute_z_evals(&self, beta: Fr, gamma: Fr) -> Vec<Fr> {
        let k = self.k[self.me];

        let mut product_vec = self
            .w_evals
            .load()
            .unwrap()
            .par_iter()
            .zip_eq(self.sigma_evals.load().unwrap().par_iter())
            .zip_eq(self.domain1_elements.load().unwrap().par_iter())
            .take(self.n - 1)
            .map(|((w, sigma), g)| (gamma + beta * k * g + w) / (gamma + beta * sigma + w))
            .collect::<Vec<_>>();

        let mut t = Fr::one();
        for i in 0..(self.n - 1) {
            (product_vec[i], t) = (t, t * product_vec[i]);
        }
        product_vec.push(t);

        product_vec
    }

    pub fn update_z_evals(&self, z_self: &mut Vec<Fr>, z_other: &[Fr]) {
        z_self.par_iter_mut().zip(z_other).for_each(|(z_self, z_other)| {
            *z_self *= z_other;
        });
    }

    pub fn compute_and_commit_z<R: Rng>(&self, rng: &mut R, z: &mut Vec<Fr>) -> G1Projective {
        Utils::ifft(&self.domain1, z);
        z.add_mut(&vec![Fr::one(), Fr::one(), Fr::one()].mul_by_vanishing_poly(self.n));
        // z.add_mut(&vec![Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)].mul_by_vanishing_poly(self.n));
        let z_comm = self.commit_polynomial(z);
        z_comm
    }
}
