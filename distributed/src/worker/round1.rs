

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{UniformRand, One};
use fn_timer::fn_timer;
use rand::Rng;

use crate::polynomial::{VecPolynomial};

use super::{PlonkImplInner, Utils};


impl PlonkImplInner {
    #[fn_timer]
    pub fn init_and_commit_w<R: Rng>(
        &self,
        rng: &mut R,
    ) -> G1Projective {
        let mut w = self.w_evals.load().unwrap().to_vec();

        Utils::ifft(&self.domain1, &mut w);

        w.add_mut(&vec![Fr::one(), Fr::one()].mul_by_vanishing_poly(self.n));
        // w.add_mut(&vec![Fr::rand(rng), Fr::rand(rng)].mul_by_vanishing_poly(self.n));

        assert_eq!(w.len(), self.n + 2);
        let w_comm = self.commit_polynomial(&w);
        self.w.store(&w).unwrap();
        w_comm
    }
}
