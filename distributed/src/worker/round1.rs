use ark_bls12_381::{Fr, G1Projective};
use ark_ff::UniformRand;
use fn_timer::fn_timer;
use rand::thread_rng;

use super::PlonkImplInner;
use crate::{gpu::FFTDomain, polynomial::VecPolynomial};

impl PlonkImplInner {
    #[fn_timer]
    pub fn init_and_commit_w(&self) -> G1Projective {
        let mut r = {
            let mut rng = thread_rng();
            vec![Fr::rand(&mut rng), Fr::rand(&mut rng)]
        };
        let mut w = self.w_evals.load().unwrap();

        self.domain1.ifft_ii(&mut w);

        w.add_mut(r.mul_by_vanishing_poly(self.n));

        assert_eq!(w.len(), self.n + 2);
        self.w.store(&w).unwrap();
        self.commit_polynomial(&w)
    }
}
