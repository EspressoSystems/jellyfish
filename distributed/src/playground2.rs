use std::collections::HashSet;

use ark_bls12_381::{g1, g2, Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{
    short_weierstrass_jacobian::GroupAffine, AffineCurve, PairingEngine, ProjectiveCurve,
    SWModelParameters as SWParam,
};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain, UVPolynomial,
};
use ark_poly_commit::kzg10::{Commitment, UniversalParams, VerifierKey};
use ark_std::{
    ops::Mul,
    println,
    rand::{CryptoRng, RngCore, SeedableRng},
    time::Instant,
    vec,
    vec::Vec,
};
use jf_plonk::{
    circuit::{Arithmetization},
    constants::GATE_WIDTH,
    errors::SnarkError,
    prelude::{PlonkError, Proof, ProofEvaluations, ProvingKey, VerifyingKey},
};
use jf_utils::to_bytes;
use merlin::Transcript;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

use crate::circuit::FakePlonkCircuit;

/// A wrapper of `merlin::Transcript`.
struct StandardTranscript(Transcript);

impl StandardTranscript {
    /// create a new plonk transcript
    pub fn new(label: &'static [u8]) -> Self {
        Self(Transcript::new(label))
    }

    /// Append the verification key and the public input to the transcript.
    pub fn append_vk_and_pub_input<F, E, P>(
        &mut self,
        vk: &VerifyingKey<E>,
        pub_input: &[E::Fr],
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
    {
        self.0.append_message(b"field size in bits", E::Fr::size_in_bits().to_le_bytes().as_ref());
        self.0.append_message(b"domain size", vk.domain_size.to_le_bytes().as_ref());
        self.0.append_message(b"input size", vk.num_inputs.to_le_bytes().as_ref());

        for ki in vk.k.iter() {
            self.0.append_message(b"wire subsets separators", &to_bytes!(ki)?);
        }
        for selector_com in vk.selector_comms.iter() {
            self.0.append_message(b"selector commitments", &to_bytes!(selector_com)?);
        }

        for sigma_comms in vk.sigma_comms.iter() {
            self.0.append_message(b"sigma commitments", &to_bytes!(sigma_comms)?);
        }

        for input in pub_input.iter() {
            self.0.append_message(b"public input", &to_bytes!(input)?);
        }

        Ok(())
    }

    /// Append a slice of commitments to the transcript.
    pub fn append_commitments<F, E, P>(
        &mut self,
        label: &'static [u8],
        comms: &[Commitment<E>],
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
    {
        for comm in comms.iter() {
            self.0.append_message(label, &to_bytes!(comm)?);
        }
        Ok(())
    }

    /// Append a single commitment to the transcript.
    pub fn append_commitment<F, E, P>(
        &mut self,
        label: &'static [u8],
        comm: &Commitment<E>,
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        P: SWParam<BaseField = F> + Clone,
    {
        self.0.append_message(label, &to_bytes!(comm)?);
        Ok(())
    }

    /// Append a proof evaluation to the transcript.
    pub fn append_proof_evaluations<E: PairingEngine>(
        &mut self,
        wires_evals: &[E::Fr],
        wire_sigma_evals: &[E::Fr],
        perm_next_eval: &E::Fr,
    ) -> Result<(), PlonkError> {
        for w_eval in wires_evals {
            self.0.append_message(b"wire_evals", &to_bytes!(w_eval)?);
        }
        for sigma_eval in wire_sigma_evals {
            self.0.append_message(b"wire_sigma_evals", &to_bytes!(sigma_eval)?);
        }
        self.0.append_message(b"perm_next_eval", &to_bytes!(perm_next_eval)?);
        Ok(())
    }

    // generate the challenge for the current transcript
    // and append it to the transcript
    pub fn get_and_append_challenge<E>(&mut self, label: &'static [u8]) -> Result<E::Fr, PlonkError>
    where
        E: PairingEngine,
    {
        let mut buf = [0u8; 64];
        self.0.challenge_bytes(label, &mut buf);
        let challenge = E::Fr::from_le_bytes_mod_order(&buf);
        self.0.append_message(label, &to_bytes!(&challenge)?);
        Ok(challenge)
    }
}

pub struct TrustedParty;

impl TrustedParty {
    pub fn universal_setup<R: RngCore>(
        max_degree: usize,
        rng: &mut R,
    ) -> UniversalParams<Bls12_381> {
        let beta = Fr::rand(rng);
        let g = g1::G1Projective::rand(rng);
        let h = g2::G2Projective::rand(rng);

        let now = Instant::now();
        let mut powers_of_beta = vec![Fr::one()];
        let mut cur = beta;
        for _ in 0..max_degree {
            powers_of_beta.push(cur);
            cur *= &beta;
        }
        println!("powers_of_beta: {:?}", now.elapsed());

        let now = Instant::now();
        let powers_of_g = Utils::fixed_msm(g, &powers_of_beta);
        println!("powers_of_g: {:?}", now.elapsed());

        let h = h.into_affine();
        let beta_h = h.mul(beta).into_affine();

        UniversalParams {
            powers_of_g,
            powers_of_gamma_g: Default::default(),
            h,
            beta_h,
            neg_powers_of_h: Default::default(),
            prepared_h: h.into(),
            prepared_beta_h: beta_h.into(),
        }
    }
}

pub struct Indexer;

impl Indexer {
    pub fn coset_representatives(num_wire_types: usize, coset_size: usize) -> Vec<Fr> {
        let mut k_vec = vec![Fr::one()];
        let mut pow_k_n_set = HashSet::new();
        pow_k_n_set.insert(Fr::one());
        let mut rng = rand_chacha::ChaChaRng::from_seed([0u8; 32]);

        for _ in 1..num_wire_types {
            loop {
                let next = Fr::rand(&mut rng);
                let pow_next_n = next.pow([coset_size as u64]);
                if !pow_k_n_set.contains(&pow_next_n) {
                    k_vec.push(next);
                    pow_k_n_set.insert(pow_next_n);
                    break;
                }
            }
        }
        k_vec
    }

    pub fn pk_gen<C: Arithmetization<Fr>>(
        circuit: &mut C,
    ) -> (Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>) {
        let circuit = unsafe { &mut *(circuit as *mut _ as *mut FakePlonkCircuit<Fr>) };
        let domain = circuit.eval_domain;
        let n = domain.size();
        let logn = domain.log_size_of_group;

        let now = Instant::now();
        let mut selector_evals = vec![vec![Fr::zero(); n]; 13];
        for (i, gate) in circuit.gates.iter().enumerate() {
            let lc = gate.q_lc();
            selector_evals[0][i] = lc[0];
            selector_evals[1][i] = lc[1];
            selector_evals[2][i] = lc[2];
            selector_evals[3][i] = lc[3];
            let mul = gate.q_mul();
            selector_evals[4][i] = mul[0];
            selector_evals[5][i] = mul[1];
            let hash = gate.q_hash();
            selector_evals[6][i] = hash[0];
            selector_evals[7][i] = hash[1];
            selector_evals[8][i] = hash[2];
            selector_evals[9][i] = hash[3];
            selector_evals[10][i] = gate.q_o();
            selector_evals[11][i] = gate.q_c();
            selector_evals[12][i] = gate.q_ecc();
        }
        circuit.gates.clear();
        circuit.gates.shrink_to_fit();
        println!("selector_evals: {:?}", now.elapsed());

        let now = Instant::now();
        let selector_polys = selector_evals
            .into_par_iter()
            .map(|mut v| {
                domain.ifft_in_place(&mut v);
                DensePolynomial::from_coefficients_vec(v)
            })
            .collect();
        println!("selector_polys: {:?}", now.elapsed());

        let now = Instant::now();
        let k = Self::coset_representatives(circuit.num_wire_types, n);
        let group_elems = domain.elements().collect::<Vec<_>>();
        let mut variable_wire_map: Vec<Option<usize>> = vec![None; circuit.num_vars];
        let mut sigma_evals = vec![vec![Fr::zero(); n]; circuit.num_wire_types];
        for (wire_id, variables) in
            circuit.wire_variables.iter().take(circuit.num_wire_types).enumerate()
        {
            for (gate_id, &var) in variables.iter().enumerate() {
                match variable_wire_map[var] {
                    Some(prev) => {
                        let prev_wire_id = prev >> logn;
                        let prev_gate_id = prev & (n - 1);
                        sigma_evals[wire_id][gate_id] = sigma_evals[prev_wire_id][prev_gate_id];
                        sigma_evals[prev_wire_id][prev_gate_id] = k[wire_id] * group_elems[gate_id];
                    }
                    None => {
                        sigma_evals[wire_id][gate_id] = k[wire_id] * group_elems[gate_id];
                    }
                }
                variable_wire_map[var] = Some((wire_id << logn) + gate_id);
            }
        }
        println!("sigma_evals: {:?}", now.elapsed());

        let now = Instant::now();
        let sigma_polys = sigma_evals
            .into_par_iter()
            .map(|mut v| {
                domain.ifft_in_place(&mut v);
                DensePolynomial::from_coefficients_vec(v)
            })
            .collect();
        println!("sigma_polys: {:?}", now.elapsed());

        (selector_polys, sigma_polys)
    }

    pub fn vk_gen<C: Arithmetization<Fr>>(
        srs: &UniversalParams<Bls12_381>,
        circuit: &C,
        selector_polys: &[DensePolynomial<Fr>],
        sigma_polys: &[DensePolynomial<Fr>],
    ) -> VerifyingKey<Bls12_381> {
        let circuit = unsafe { &*(circuit as *const _ as *const FakePlonkCircuit<Fr>) };
        let n = circuit.eval_domain.size();

        let now = Instant::now();
        let selector_comms = selector_polys
            .par_iter()
            .map(|poly| Utils::commit_polynomial(&srs.powers_of_g, poly))
            .collect();
        println!("selector_comms: {:?}", now.elapsed());

        let now = Instant::now();
        let sigma_comms = sigma_polys
            .par_iter()
            .map(|poly| Utils::commit_polynomial(&srs.powers_of_g, poly))
            .collect();
        println!("sigma_comms: {:?}", now.elapsed());

        VerifyingKey {
            domain_size: n,
            num_inputs: circuit.pub_input_gate_ids.len(),
            selector_comms,
            sigma_comms,
            k: Self::coset_representatives(circuit.num_wire_types, n),
            open_key: VerifierKey {
                g: srs.powers_of_g[0],
                gamma_g: Default::default(),
                h: srs.h,
                beta_h: srs.beta_h,
                prepared_h: srs.prepared_h.clone(),
                prepared_beta_h: srs.prepared_beta_h.clone(),
            },
        }
    }
}

pub struct Prover {}

impl Prover {
    pub fn prove<C, R>(
        _prng: &mut R,
        srs: &UniversalParams<Bls12_381>,
        circuit: &C,
        prove_key: &ProvingKey<Bls12_381>,
    ) -> Result<Proof<Bls12_381>, PlonkError>
    where
        C: Arithmetization<Fr>,
        R: CryptoRng + RngCore,
    {
        // Dirty hack: extract private fields from `circuit`
        let circuit = unsafe { &*(circuit as *const _ as *mut FakePlonkCircuit<Fr>) };

        let domain = circuit.eval_domain;
        let n = domain.size();
        let logn = domain.log_size_of_group;
        let num_wires = circuit.num_wire_types;
        let num_vars = circuit.num_vars;
        let witness = &circuit.witness;
        let wire_variables = &circuit.wire_variables;
        let pub_input_gate_ids = &circuit.pub_input_gate_ids;

        let ck = &srs.powers_of_g;

        // Initialize transcript
        let mut transcript = StandardTranscript::new(b"PlonkProof");
        let mut pub_input = DensePolynomial::from_coefficients_vec(
            pub_input_gate_ids
                .iter()
                .map(|&gate_id| witness[wire_variables[num_wires - 1][gate_id]])
                .collect(),
        );

        transcript.append_vk_and_pub_input(&prove_key.vk, &pub_input)?;

        domain.ifft_in_place(&mut pub_input.coeffs);
        // Self::ifft(&kernel, &domain, &mut pub_input);

        // Round 1
        let now = Instant::now();
        let wire_polys = wire_variables
            .par_iter()
            .take(num_wires)
            .map(|wire_vars| {
                let mut coeffs = wire_vars.iter().map(|&var| witness[var]).collect();
                domain.ifft_in_place(&mut coeffs);
                // Self::ifft(&kernel, &domain, &mut coeffs);
                /* DensePolynomial::rand(1, &mut thread_rng()) */
                DensePolynomial::from_coefficients_vec(vec![Fr::one(), Fr::one()])
                    .mul_by_vanishing_poly(domain)
                    + DensePolynomial::from_coefficients_vec(coeffs)
            })
            .collect::<Vec<_>>();
        let wires_poly_comms = wire_polys
            .par_iter()
            .map(|poly| {
                Utils::commit_polynomial(/* context, */ &ck, poly)
            })
            .collect::<Vec<_>>();
        println!("wires_poly_comms:");
        for i in &wires_poly_comms {
            println!("{}", i.0);
        }
        transcript.append_commitments(b"witness_poly_comms", &wires_poly_comms)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 2
        let now = Instant::now();
        let beta = transcript.get_and_append_challenge::<Bls12_381>(b"beta")?;
        let gamma = transcript.get_and_append_challenge::<Bls12_381>(b"gamma")?;
        let mut group_elems = domain.elements().collect::<Vec<_>>();
        group_elems.push(group_elems[n - 1] * domain.group_gen);
        group_elems.push(group_elems[n] * domain.group_gen);
        group_elems.push(group_elems[n + 1] * domain.group_gen);
        let permutation_poly = {
            let mut variable_wire_map: Vec<Option<usize>> = vec![None; num_vars];
            let mut wire_permutation = vec![vec![0; n]; num_wires];
            for (wire_id, variables) in wire_variables.iter().take(num_wires).enumerate() {
                for (gate_id, &var) in variables.iter().enumerate() {
                    match variable_wire_map[var] {
                        Some(prev) => {
                            let prev_wire_id = prev >> logn;
                            let prev_gate_id = prev & (n - 1);
                            wire_permutation[wire_id][gate_id] =
                                wire_permutation[prev_wire_id][prev_gate_id];
                            wire_permutation[prev_wire_id][prev_gate_id] =
                                (wire_id << logn) + gate_id;
                        }
                        None => {
                            wire_permutation[wire_id][gate_id] = (wire_id << logn) + gate_id;
                        }
                    }
                    variable_wire_map[var] = Some((wire_id << logn) + gate_id);
                }
            }

            let mut product_vec = (0..(n - 1))
                .into_par_iter()
                .map(|j| {
                    let a = (0..num_wires)
                        .into_par_iter()
                        .map(|i| {
                            witness[wire_variables[i][j]]
                                + gamma
                                + beta * prove_key.vk.k[i] * group_elems[j]
                        })
                        .reduce(|| Fr::one(), Fr::mul);
                    let b = (0..num_wires)
                        .into_par_iter()
                        .map(|i| {
                            let perm = wire_permutation[i][j];
                            witness[wire_variables[i][j]]
                                + gamma
                                + beta * prove_key.vk.k[perm >> logn] * group_elems[perm & (n - 1)]
                        })
                        .reduce(|| Fr::one(), Fr::mul);
                    a / b
                })
                .collect::<Vec<_>>();
            let mut t = Fr::one();
            for i in 0..(n - 1) {
                (product_vec[i], t) = (t, t * product_vec[i]);
            }
            product_vec.push(t);
            domain.ifft_in_place(&mut product_vec);
            /* DensePolynomial::rand(2, prng) */
            DensePolynomial::from_coefficients_vec(vec![Fr::one(), Fr::one(), Fr::one()])
                .mul_by_vanishing_poly(domain)
                + DensePolynomial::from_coefficients_vec(product_vec)
        };
        let prod_perm_poly_comm = Utils::commit_polynomial(/*ctx, */ ck, &permutation_poly);
        println!("prod_perm_poly_comm:");
        println!("{}", prod_perm_poly_comm.0);
        transcript.append_commitment(b"perm_poly_comms", &prod_perm_poly_comm)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 3
        let now = Instant::now();
        let alpha = transcript.get_and_append_challenge::<Bls12_381>(b"alpha")?;
        let alpha_square_div_n = alpha.square() / Fr::from(n as u64);
        let quotient_poly = {
            let tmp_domain = Radix2EvaluationDomain::<Fr>::new((n + 2) * 5).unwrap();

            let ab = wire_polys[0].mul(&wire_polys[1]);
            let cd = wire_polys[2].mul(&wire_polys[3]);

            let mut f = DensePolynomial::zero();
            for i in 0..4 {
                let t = prove_key.selectors[i].mul(&wire_polys[i])
                    + prove_key.selectors[i + 6].mul(&{
                        let mut evals = tmp_domain.fft(&wire_polys[i]);
                        evals.par_iter_mut().for_each(|x| *x *= x.square().square());
                        tmp_domain.ifft_in_place(&mut evals);
                        DensePolynomial::from_coefficients_vec(evals)
                    });
                println!("{}", Utils::commit_polynomial(&ck, &t).0);
                f += &t;
            }

            {
                let t = prove_key.selectors[4].mul(&ab);
                println!("{}", Utils::commit_polynomial(&ck, &t).0);
                f += &t;
            }

            {
                let t = prove_key.selectors[5].mul(&cd);
                println!("{}", Utils::commit_polynomial(&ck, &t).0);
                f += &t;
            }

            {
                let t = &pub_input
                    + &prove_key.selectors[11]
                    + -prove_key.selectors[10].mul(&wire_polys[4]);
                println!("{}", Utils::commit_polynomial(&ck, &t).0);
                f += &t;
            }

            {
                let t = prove_key.selectors[12].mul(&ab).mul(&cd).mul(&wire_polys[4]);
                println!("{}", Utils::commit_polynomial(&ck, &t).0);
                f += &t;
            }

            let g1 = (&wire_polys[0]
                + &DensePolynomial { coeffs: vec![gamma, beta * prove_key.vk.k[0]] })
                .mul(
                    &(&wire_polys[1]
                        + &DensePolynomial { coeffs: vec![gamma, beta * prove_key.vk.k[1]] }),
                );
            println!("{}", Utils::commit_polynomial(&ck, &g1).0);
            let g2 = (&wire_polys[2]
                + &DensePolynomial { coeffs: vec![gamma, beta * prove_key.vk.k[2]] })
                .mul(
                    &(&wire_polys[3]
                        + &DensePolynomial { coeffs: vec![gamma, beta * prove_key.vk.k[3]] }),
                );
            println!("{}", Utils::commit_polynomial(&ck, &g2).0);
            let g3 = &wire_polys[4]
                + &DensePolynomial { coeffs: vec![gamma, beta * prove_key.vk.k[4]] };
            println!("{}", Utils::commit_polynomial(&ck, &g3).0);
            let g4 = permutation_poly.mul(alpha);
            println!("{}", Utils::commit_polynomial(&ck, &g4).0);
            let g = g1.mul(&g2).mul(&g3).mul(&g4);
            println!("{}", Utils::commit_polynomial(&ck, &g).0);
            f = f + g;

            let h1 = (&wire_polys[0]
                + &prove_key.sigmas[0].mul(beta)
                + DensePolynomial { coeffs: vec![gamma] }).mul(&(&wire_polys[1]
                    + &prove_key.sigmas[1].mul(beta)
                    + DensePolynomial { coeffs: vec![gamma] }));
            println!("{}", Utils::commit_polynomial(&ck, &h1).0);
            let h2 = (&wire_polys[2]
                + &prove_key.sigmas[2].mul(beta)
                + DensePolynomial { coeffs: vec![gamma] }).mul(&(&wire_polys[3]
                    + &prove_key.sigmas[3].mul(beta)
                    + DensePolynomial { coeffs: vec![gamma] }));
            println!("{}", Utils::commit_polynomial(&ck, &h2).0);
            let h3 = &wire_polys[4]
                + &prove_key.sigmas[4].mul(beta)
                + DensePolynomial { coeffs: vec![gamma] };
            println!("{}", Utils::commit_polynomial(&ck, &h3).0);
            let mut h4 = permutation_poly.mul(-alpha);
            {
                let mut t = Fr::one();
                for i in 0..h4.len() {
                    h4[i] *= t;
                    t *= domain.group_gen;
                }
            }
            println!("{}", Utils::commit_polynomial(&ck, &h4).0);
            let h = h1.mul(&h2).mul(&h3).mul(&h4);
            println!("{}", Utils::commit_polynomial(&ck, &h).0);
            f = f + h;

            ({
                let mut remainder = f;
                let mut quotient = vec![Fr::zero(); remainder.degree()];

                while !remainder.is_zero() && remainder.degree() >= n {
                    let cur_q_coeff = *remainder.coeffs.last().unwrap();
                    let cur_q_degree = remainder.degree() - n;
                    quotient[cur_q_degree] = cur_q_coeff;

                    remainder[cur_q_degree] += &cur_q_coeff;
                    remainder[cur_q_degree + n] -= &cur_q_coeff;
                    while let Some(true) = remainder.coeffs.last().map(|c| c.is_zero()) {
                        remainder.coeffs.pop();
                    }
                }
                DensePolynomial::from_coefficients_vec(quotient)
            } + {
                let mut r = permutation_poly.mul(alpha_square_div_n);
                r[0] -= alpha_square_div_n;
                let mut t = r.coeffs.pop().unwrap();
                for i in (0..r.len()).rev() {
                    (r[i], t) = (t, r[i] + t);
                }
                r
            })
        };
        let split_quot_polys = {
            let expected_degree = num_wires * (n + 1) + 2;
            if quotient_poly.degree() != expected_degree {
                return Err(SnarkError::WrongQuotientPolyDegree(
                    quotient_poly.degree(),
                    expected_degree,
                )
                .into());
            }
            quotient_poly
                .coeffs
                .chunks(n + 2)
                .map(DensePolynomial::from_coefficients_slice)
                .collect::<Vec<_>>()
        };
        let split_quot_poly_comms = split_quot_polys
            .par_iter()
            .map(|poly| {
                Utils::commit_polynomial(/* context, */ &ck, poly)
            })
            .collect::<Vec<_>>();
        println!("split_quot_poly_comms:");
        for i in &split_quot_poly_comms {
            println!("{}", i.0);
        }
        transcript.append_commitments(b"quot_poly_comms", &split_quot_poly_comms)?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 4
        let now = Instant::now();
        let zeta = transcript.get_and_append_challenge::<Bls12_381>(b"zeta")?;
        let wires_evals =
            wire_polys.par_iter().map(|poly| poly.evaluate(&zeta)).collect::<Vec<_>>();
        let wire_sigma_evals = prove_key
            .sigmas
            .par_iter()
            .take(num_wires - 1)
            .map(|poly| poly.evaluate(&zeta))
            .collect::<Vec<_>>();
        let perm_next_eval = permutation_poly.evaluate(&(zeta * domain.group_gen));
        println!("wires_evals:");
        for i in &wires_evals {
            println!("{}", i);
        }
        println!("wire_sigma_evals:");
        for i in &wire_sigma_evals {
            println!("{}", i);
        }
        println!("perm_next_eval:");
        println!("{}", perm_next_eval);
        transcript.append_proof_evaluations::<Bls12_381>(
            &wires_evals,
            &wire_sigma_evals,
            &perm_next_eval,
        )?;
        println!("Elapsed: {:.2?}", now.elapsed());

        // Round 5
        let now = Instant::now();
        let vanish_eval = zeta.pow(&[n as u64]) - Fr::one();
        let lin_poly = {
            // The selectors order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
            // TODO: (binyi) get the order from a function.
            let q_lc = &prove_key.selectors[..GATE_WIDTH];
            let q_mul = &prove_key.selectors[GATE_WIDTH..GATE_WIDTH + 2];
            let q_hash = &prove_key.selectors[GATE_WIDTH + 2..2 * GATE_WIDTH + 2];
            let q_o = &prove_key.selectors[2 * GATE_WIDTH + 2];
            let q_c = &prove_key.selectors[2 * GATE_WIDTH + 3];
            let q_ecc = &prove_key.selectors[2 * GATE_WIDTH + 4];

            // TODO(binyi): add polynomials in parallel.
            // Note we don't need to compute the constant term of the polynomial.
            let a = wires_evals[0];
            let b = wires_evals[1];
            let c = wires_evals[2];
            let d = wires_evals[3];
            let e = wires_evals[4];
            let ab = a * b;
            let cd = c * d;
            q_lc[0].mul(a)
                + q_lc[1].mul(b)
                + q_lc[2].mul(c)
                + q_lc[3].mul(d)
                + q_mul[0].mul(ab)
                + q_mul[1].mul(cd)
                + q_hash[0].mul(a.square().square() * a)
                + q_hash[1].mul(b.square().square() * b)
                + q_hash[2].mul(c.square().square() * c)
                + q_hash[3].mul(d.square().square() * d)
                + q_ecc.mul(ab * cd * e)
                + q_o.mul(-e)
                + q_c.clone()
        } + {
            let lagrange_1_eval = vanish_eval / (Fr::from(n as u32) * (zeta - Fr::one()));

            // Compute the coefficient of z(X)
            let coeff =
                wires_evals.iter().zip(&prove_key.vk.k).fold(alpha, |acc, (&wire_eval, &k)| {
                    acc * (wire_eval + beta * k * zeta + gamma)
                }) + alpha.square() * lagrange_1_eval;
            permutation_poly.mul(coeff)
        } + {
            // Compute the coefficient of the last sigma wire permutation polynomial
            let coeff = -wires_evals
                .iter()
                .take(num_wires - 1)
                .zip(&wire_sigma_evals)
                .fold(alpha * beta * perm_next_eval, |acc, (&wire_eval, &sigma_eval)| {
                    acc * (wire_eval + beta * sigma_eval + gamma)
                });
            prove_key.sigmas[num_wires - 1].mul(coeff)
        } + {
            let zeta_to_n_plus_2 = (vanish_eval + Fr::one()) * zeta.square();
            let mut r_quot = split_quot_polys[0].clone();
            let mut coeff = Fr::one();
            for poly in &split_quot_polys[1..] {
                coeff *= zeta_to_n_plus_2;
                r_quot = r_quot + poly.mul(coeff);
            }
            r_quot.mul(-vanish_eval)
        };
        println!("lin_poly:");
        println!("{}", Utils::commit_polynomial(&ck, &lin_poly).0);
        let v = transcript.get_and_append_challenge::<Bls12_381>(b"v")?;

        let opening_proof = {
            // List the polynomials to be opened at point `zeta`.
            let mut polys_ref = vec![&lin_poly];
            for poly in wire_polys.iter() {
                polys_ref.push(poly);
            }
            // Note we do not add the last wire sigma polynomial.
            for poly in prove_key.sigmas.iter().take(prove_key.sigmas.len() - 1) {
                polys_ref.push(poly);
            }
            let (batch_poly, _) = polys_ref
                .iter()
                .fold((DensePolynomial::zero(), Fr::one()), |(acc, coeff), &poly| {
                    (acc + poly.mul(coeff), coeff * v)
                });

            Utils::commit_polynomial(
                // context,
                &ck,
                &{
                    let mut opening_poly = batch_poly;
                    let mut t = opening_poly.coeffs.pop().unwrap();
                    for i in (0..opening_poly.len()).rev() {
                        (opening_poly[i], t) = (t, opening_poly[i] + t * zeta);
                    }
                    opening_poly
                },
            )
        };

        let shifted_opening_proof = {
            Utils::commit_polynomial(
                // context,
                &ck,
                &{
                    let mut opening_poly = permutation_poly;
                    let mut t = opening_poly.coeffs.pop().unwrap();
                    for i in (0..opening_poly.len()).rev() {
                        (opening_poly[i], t) = (t, opening_poly[i] + t * domain.group_gen * zeta);
                    }
                    opening_poly
                },
            )
        };
        println!("opening_proof:");
        println!("{}", opening_proof.0);
        println!("shifted_opening_proof:");
        println!("{}", shifted_opening_proof.0);
        println!("Elapsed: {:.2?}", now.elapsed());

        // unsafe {
        //     mult_pippenger_free(context);
        // }

        Ok(Proof {
            wires_poly_comms,
            prod_perm_poly_comm,
            split_quot_poly_comms,
            opening_proof,
            shifted_opening_proof,
            poly_evals: ProofEvaluations { wires_evals, wire_sigma_evals, perm_next_eval },
        })
    }
}

struct Utils;

impl Utils {
    // #[inline]
    // fn ifft(
    //     kernel: &SingleMultiexpKernel,
    //     domain: &Radix2EvaluationDomain<Fr>,
    //     coeffs: &mut Vec<Fr>,
    // ) {
    //     coeffs.resize(domain.size(), Fr::zero());
    //     kernel
    //         .radix_fft(coeffs, &domain.group_gen_inv, domain.log_size_of_group)
    //         .unwrap();
    //     coeffs.iter_mut().for_each(|val| *val *= domain.size_inv);
    // }

    // #[inline]
    // fn coset_fft(
    //     kernel: &SingleMultiexpKernel,
    //     domain: &Radix2EvaluationDomain<Fr>,
    //     coeffs: &mut Vec<Fr>,
    // ) {
    //     Radix2EvaluationDomain::distribute_powers(
    //         coeffs,
    //         Fr::multiplicative_generator(),
    //     );
    //     coeffs.resize(domain.size(), Fr::zero());
    //     kernel
    //         .radix_fft(coeffs, &domain.group_gen, domain.log_size_of_group)
    //         .unwrap();
    // }

    // #[inline]
    // fn coset_ifft(
    //     kernel: &SingleMultiexpKernel,
    //     domain: &Radix2EvaluationDomain<Fr>,
    //     coeffs: &mut Vec<Fr>,
    // ) {
    //     coeffs.resize(domain.size(), Fr::zero());
    //     kernel
    //         .radix_fft(coeffs, &domain.group_gen_inv, domain.log_size_of_group)
    //         .unwrap();
    //     coeffs.iter_mut().for_each(|val| *val *= domain.size_inv);
    //     Radix2EvaluationDomain::distribute_powers(
    //         coeffs,
    //         Fr::multiplicative_generator().inverse().unwrap(),
    //     );
    // }

    #[inline]
    fn commit_polynomial(ck: &[G1Affine], poly: &[Fr]) -> Commitment<Bls12_381> {
        Commitment(Self::var_msm(&ck, &poly).into())
    }

    fn fixed_msm(g: G1Projective, v: &[Fr]) -> Vec<G1Affine> {
        let num_scalars = v.len();
        let window =
            if num_scalars < 32 { 3 } else { (ark_std::log2(num_scalars) * 69 / 100) as usize + 2 };
        let scalar_size = Fr::size_in_bits();
        let outerc = (scalar_size + window - 1) / window;
        let table = {
            let in_window = 1 << window;
            let last_in_window = 1 << (scalar_size - (outerc - 1) * window);

            let mut multiples_of_g = vec![vec![G1Projective::zero(); in_window]; outerc];

            let mut g_outer = g;
            let mut g_outers = Vec::with_capacity(outerc);
            for _ in 0..outerc {
                g_outers.push(g_outer);
                for _ in 0..window {
                    g_outer.double_in_place();
                }
            }
            multiples_of_g.par_iter_mut().enumerate().take(outerc).zip(g_outers).for_each(
                |((outer, multiples_of_g), g_outer)| {
                    let cur_in_window =
                        if outer == outerc - 1 { last_in_window } else { in_window };

                    let mut g_inner = G1Projective::zero();
                    for inner in multiples_of_g.iter_mut().take(cur_in_window) {
                        *inner = g_inner;
                        g_inner += &g_outer;
                    }
                },
            );
            multiples_of_g
                .par_iter()
                .map(|s| G1Projective::batch_normalization_into_affine(&s))
                .collect::<Vec<_>>()
        };

        v.par_iter()
            .map(|e| {
                let scalar_val = e.into_repr().to_bits_le();

                let mut res = table[0][0].into_projective();
                for outer in 0..outerc {
                    let mut inner = 0usize;
                    for i in 0..window {
                        if outer * window + i < scalar_size && scalar_val[outer * window + i] {
                            inner |= 1 << i;
                        }
                    }
                    res.add_assign_mixed(&table[outer][inner]);
                }
                res.into_affine()
            })
            .collect()
    }

    fn var_msm(bases: &[G1Affine], scalars: &[Fr]) -> G1Projective {
        let size = ark_std::cmp::min(bases.len(), scalars.len());
        let scalars = &scalars[..size];
        let bases = &bases[..size];
        let scalars_and_bases_iter = scalars.iter().zip(bases).filter(|(s, _)| !s.is_zero());

        let c = if size < 32 { 3 } else { (ark_std::log2(size) * 69 / 100) as usize + 2 };

        let num_bits = Fr::size_in_bits();
        let fr_one = Fr::one();

        let zero = G1Projective::zero();
        let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

        // Each window is of size `c`.
        // We divide up the bits 0..num_bits into windows of size `c`, and
        // in parallel process each such window.
        let window_sums: Vec<_> = window_starts
            .into_par_iter()
            .map(|w_start| {
                let mut res = zero;
                // We don't need the "zero" bucket, so we only have 2^c - 1 buckets.
                let mut buckets = vec![zero; (1 << c) - 1];
                // This clone is cheap, because the iterator contains just a
                // pointer and an index into the original vectors.
                scalars_and_bases_iter.clone().for_each(|(&scalar, base)| {
                    if scalar == fr_one {
                        // We only process unit scalars once in the first window.
                        if w_start == 0 {
                            res.add_assign_mixed(base);
                        }
                    } else {
                        let mut scalar = scalar.into_repr();

                        // We right-shift by w_start, thus getting rid of the
                        // lower bits.
                        scalar.divn(w_start as u32);

                        // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
                        let scalar = scalar.as_ref()[0] % (1 << c);

                        // If the scalar is non-zero, we update the corresponding
                        // bucket.
                        // (Recall that `buckets` doesn't have a zero bucket.)
                        if scalar != 0 {
                            buckets[(scalar - 1) as usize].add_assign_mixed(base);
                        }
                    }
                });

                // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
                // This is computed below for b buckets, using 2b curve additions.
                //
                // We could first normalize `buckets` and then use mixed-addition
                // here, but that's slower for the kinds of groups we care about
                // (Short Weierstrass curves and Twisted Edwards curves).
                // In the case of Short Weierstrass curves,
                // mixed addition saves ~4 field multiplications per addition.
                // However normalization (with the inversion batched) takes ~6
                // field multiplications per element,
                // hence batch normalization is a slowdown.

                // `running_sum` = sum_{j in i..num_buckets} bucket[j],
                // where we iterate backward from i = num_buckets to 0.
                let mut running_sum = G1Projective::zero();
                buckets.into_iter().rev().for_each(|b| {
                    running_sum += &b;
                    res += &running_sum;
                });
                res
            })
            .collect();

        // We're traversing windows from high to low.
        window_sums[0]
            + &window_sums[1..].iter().rev().fold(zero, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
    }
}

#[cfg(test)]
mod tests {
    

    
    use jf_plonk::{
        prelude::{Circuit},
        proof_system::{PlonkKzgSnark, Snark},
    };
    
    
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::{
        circuit::{generate_circuit},
    };

    #[test]
    fn test() {
        let seed = [0; 32];
        // thread_rng().fill_bytes(&mut seed);

        let rng = &mut ChaChaRng::from_seed(seed);

        let mut circuit = generate_circuit(rng).unwrap();
        let srs = TrustedParty::universal_setup(circuit.srs_size().unwrap(), rng);

        let (selector_polys, sigma_polys) = Indexer::pk_gen(&mut circuit);
        let vk = Indexer::vk_gen(&srs, &circuit, &selector_polys, &sigma_polys);
        for i in &vk.selector_comms {
            println!("{}", i.0);
        }
        for i in &vk.sigma_comms {
            println!("{}", i.0);
        }

        let pk = ProvingKey {
            selectors: selector_polys,
            sigmas: sigma_polys,
            commit_key: Default::default(),
            vk: vk.clone(),
        };
        let proof = Prover::prove(rng, &srs, &circuit, &pk).unwrap();
        let public_inputs = circuit.public_input().unwrap();
        assert!(PlonkKzgSnark::<Bls12_381>::verify::<jf_plonk::transcript::StandardTranscript>(
            &vk,
            &public_inputs,
            &proof
        )
        .is_ok())
    }
}
