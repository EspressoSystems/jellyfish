use std::{
    collections::HashSet,
};

use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{Field, One, UniformRand};
use fn_timer::fn_timer;
use jf_plonk::{
    circuit::{Variable},
    constants::GATE_WIDTH,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

use super::PlonkImplInner;
use crate::{
    gpu::Domain,
    timer,
    worker::{Selectors, Utils}, circuit2::Gate,
};

impl PlonkImplInner {
    #[fn_timer]
    pub fn init_domains(&self, domain_elements: &[Fr]) {
        // We abuse `unsafe` here and there to make `self` mutable without declaring a `FnMut` closure,
        // so we can avoid setting the type of `PlonkImpl`'s `inner` field to `Arc<Mutex<...>>`,
        // and in turn reduce the ugly (personal opinion) `self.inner.lock().unwrap()` calls.
        // This is safe because we only call this function once, and the mutated fields are guaranteed
        // to be used only after this function is called.
        let mut this = unsafe { &mut *(self as *const _ as *mut Self) };
        this.n = domain_elements.len();
        this.domain1 = timer!(
            format!("Initialize domain with size {}", self.n),
            Domain::from_group_elems(domain_elements)
        );
        this.domain4 =
            timer!(format!("Initialize domain with size {}", self.n * 4), Domain::new(self.n * 4));
        this.domain8 =
            timer!(format!("Initialize domain with size {}", self.n * 8), Domain::new(self.n * 8));
    }

    #[fn_timer]
    pub fn init_k(&self, num_wire_types: usize) {
        let mut this = unsafe { &mut *(self as *const _ as *mut Self) };

        let mut k_vec = vec![Fr::one()];
        let mut pow_k_n_set = HashSet::new();
        pow_k_n_set.insert(Fr::one());
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        for _ in 1..num_wire_types {
            loop {
                let next = Fr::rand(&mut rng);
                let pow_next_n = next.pow([self.n as u64]);
                if !pow_k_n_set.contains(&pow_next_n) {
                    k_vec.push(next);
                    pow_k_n_set.insert(pow_next_n);
                    break;
                }
            }
        }
        this.k = k_vec;
    }

    #[fn_timer]
    pub fn store_public_inputs(&self, public_inputs: Vec<Fr>) {
        let x = timer!("Compute public input polynomial", {
            let mut x = public_inputs;
            Utils::ifft(&self.domain1, &mut x);
            x
        });
        self.x.store(&x).unwrap();
    }

    #[fn_timer]
    pub fn store_w_evals(&self, wire_variables: &[usize], witnesses: Vec<Fr>) {
        let w_evals = wire_variables.par_iter().map(|&var| witnesses[var]).collect::<Vec<_>>();
        self.w_evals.store(&w_evals).unwrap();
    }

    #[fn_timer]
    pub fn init_and_commit_selectors(&self, gates: Vec<Gate>) -> Vec<G1Projective> {
        let me = self.me;
        match &self.q {
            Selectors::Type1 { a, h } => {
                let mut q_a = gates.iter().map(|i| i.q_lc()[me]).collect::<Vec<_>>();
                let mut q_h = gates.iter().map(|i| i.q_hash()[me]).collect::<Vec<_>>();
                Utils::ifft(&self.domain1, &mut q_a);
                Utils::ifft(&self.domain1, &mut q_h);
                let c_q_a = self.commit_polynomial(&q_a);
                let c_q_h = self.commit_polynomial(&q_h);
                a.store(&q_a).unwrap();
                h.store(&q_h).unwrap();
                vec![c_q_a, c_q_h]
            }
            Selectors::Type2 { a, h, m } => {
                let mut q_a = gates.iter().map(|i| i.q_lc()[me]).collect::<Vec<_>>();
                let mut q_h = gates.iter().map(|i| i.q_hash()[me]).collect::<Vec<_>>();
                let mut q_m = gates.iter().map(|i| i.q_mul()[me >> 1]).collect::<Vec<_>>();
                Utils::ifft(&self.domain1, &mut q_a);
                Utils::ifft(&self.domain1, &mut q_h);
                Utils::ifft(&self.domain1, &mut q_m);
                let c_q_a = self.commit_polynomial(&q_a);
                let c_q_h = self.commit_polynomial(&q_h);
                let c_q_m = self.commit_polynomial(&q_m);
                a.store(&q_a).unwrap();
                h.store(&q_h).unwrap();
                m.store(&q_m).unwrap();
                vec![c_q_a, c_q_h, c_q_m]
            }
            Selectors::Type3 { o, c, e } => {
                let mut q_o = gates.iter().map(|i| i.q_o()).collect::<Vec<_>>();
                let mut q_c = gates.iter().map(|i| i.q_c()).collect::<Vec<_>>();
                let mut q_e = gates.iter().map(|i| i.q_ecc()).collect::<Vec<_>>();
                Utils::ifft(&self.domain1, &mut q_o);
                Utils::ifft(&self.domain1, &mut q_c);
                Utils::ifft(&self.domain1, &mut q_e);
                let c_q_o = self.commit_polynomial(&q_o);
                let c_q_c = self.commit_polynomial(&q_c);
                let c_q_e = self.commit_polynomial(&q_e);
                o.store(&q_o).unwrap();
                c.store(&q_c).unwrap();
                e.store(&q_e).unwrap();
                vec![c_q_o, c_q_c, c_q_e]
            }
        }
    }

    #[fn_timer(format!("Worker {}: init_sigma_and_commit", self.me))]
    pub fn init_and_commit_sigma(
        &self,
        wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
        num_vars: usize,
        domain_elements: Vec<Fr>,
    ) -> G1Projective {
        let me = self.me;
        let n = self.n;
        let logn = n.trailing_zeros();
        let mut sigma = vec![Default::default(); n];
        let mut variable_wire_map: Vec<Option<usize>> = vec![None; num_vars];
        let mut variable_wire_first = vec![0usize; num_vars];
        for (wire_id, variables) in wire_variables.iter().enumerate() {
            for (gate_id, &var) in variables.iter().enumerate() {
                match variable_wire_map[var] {
                    Some(prev) => {
                        let prev_wire_id = prev >> logn;
                        let prev_gate_id = prev & (n - 1);
                        if prev_wire_id == me {
                            sigma[prev_gate_id] = self.k[wire_id] * domain_elements[gate_id];
                        }
                    }
                    None => {
                        variable_wire_first[var] = (wire_id << logn) + gate_id;
                    }
                }
                variable_wire_map[var] = Some((wire_id << logn) + gate_id);
            }
        }
        drop(wire_variables);
        for i in 0..num_vars {
            match variable_wire_map[i] {
                Some(prev) => {
                    let prev_wire_id = prev >> logn;
                    let prev_gate_id = prev & (n - 1);
                    if prev_wire_id == me {
                        sigma[prev_gate_id] = self.k[variable_wire_first[i] >> logn]
                            * domain_elements[variable_wire_first[i] & (n - 1)];
                    }
                }
                None => {}
            }
        }
        self.sigma_evals.store(&sigma).unwrap();
        self.domain1_elements.store(&domain_elements).unwrap();
        drop(domain_elements);

        Utils::ifft(&self.domain1, &mut sigma);
        self.sigma.store(&sigma).unwrap();

        self.commit_polynomial(&sigma)
    }
}
