pub mod gpu;

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ff::{FftField, Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain, UVPolynomial,
};
use ark_std::{
    ops::Mul,
    println,
    rand::{thread_rng, CryptoRng, RngCore},
    time::Instant,
    vec,
    vec::Vec,
};
use jf_plonk::{
    circuit::{gates::Gate, Arithmetization, GateId, Variable, WireId},
    constants::GATE_WIDTH,
    errors::SnarkError,
    prelude::{PlonkError, Proof, ProofEvaluations, ProvingKey, VerifyingKey},
};
use rayon::prelude::*;

use ark_ec::{
    short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters as SWParam,
};
use ark_poly_commit::kzg10::Commitment;
use gpu::{threadpool::Worker, MultiKernel};
use jf_utils::to_bytes;
use merlin::Transcript;

struct Context {
    kernel: MultiKernel,
    pool: Worker,
}

/// A wrapper of `merlin::Transcript`.
struct FakeStandardTranscript(Transcript);

impl FakeStandardTranscript {
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
        self.0.append_message(
            b"field size in bits",
            E::Fr::size_in_bits().to_le_bytes().as_ref(),
        );
        self.0
            .append_message(b"domain size", vk.domain_size.to_le_bytes().as_ref());
        self.0
            .append_message(b"input size", vk.num_inputs.to_le_bytes().as_ref());

        for ki in vk.k.iter() {
            self.0
                .append_message(b"wire subsets separators", &to_bytes!(ki)?);
        }
        for selector_com in vk.selector_comms.iter() {
            self.0
                .append_message(b"selector commitments", &to_bytes!(selector_com)?);
        }

        for sigma_comms in vk.sigma_comms.iter() {
            self.0
                .append_message(b"sigma commitments", &to_bytes!(sigma_comms)?);
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
            self.0
                .append_message(b"wire_sigma_evals", &to_bytes!(sigma_eval)?);
        }
        self.0
            .append_message(b"perm_next_eval", &to_bytes!(perm_next_eval)?);
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

/// A specific Plonk circuit instantiation.
#[derive(Debug, Clone)]
struct FakePlonkCircuit<F>
where
    F: FftField,
{
    _num_vars: usize,
    gates: Vec<Box<dyn Gate<F>>>,
    wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
    pub_input_gate_ids: Vec<GateId>,
    witness: Vec<F>,
    wire_permutation: Vec<(WireId, GateId)>,
    extended_id_permutation: Vec<F>,
    num_wire_types: usize,
    eval_domain: Radix2EvaluationDomain<F>,
}

pub struct Prover {}

impl Prover {
    pub fn prove<C, R>(
        prng: &mut R,
        circuit: &C,
        prove_key: &ProvingKey<Bls12_381>,
    ) -> Result<Proof<Bls12_381>, PlonkError>
    where
        C: Arithmetization<Fr>,
        R: CryptoRng + RngCore,
    {
        // Dirty hack: extract private fields from `circuit`
        let circuit = unsafe { &mut *(circuit as *const _ as *mut FakePlonkCircuit<Fr>) };

        let ctx = &mut Context {
            kernel: MultiKernel::create(include_bytes!("./gpu/cl/lib.fatbin")),
            pool: Worker::new()
        };

        let domain = circuit.eval_domain;
        let n = domain.size();
        let num_wire_types = circuit.num_wire_types;

        let mut ck = prove_key.commit_key.powers_of_g.to_vec();
        ck.resize(((ck.len() + 31) >> 5) << 5, G1Affine::zero());

        circuit.gates.clear();

        // Initialize transcript
        let mut transcript = FakeStandardTranscript::new(b"PlonkProof");
        let mut pub_input = DensePolynomial::from_coefficients_vec(
            circuit
                .pub_input_gate_ids
                .iter()
                .map(|&gate_id| {
                    circuit.witness[circuit.wire_variables[num_wire_types - 1][gate_id]]
                })
                .collect(),
        );

        transcript.append_vk_and_pub_input(&prove_key.vk, &pub_input)?;

        Self::ifft(ctx, &domain, &mut pub_input.coeffs);

        // Round 1
        let now = Instant::now();
        let witness = &circuit.witness;
        let wire_polys = circuit
            .wire_variables
            .iter()
            .take(num_wire_types)
            .map(|wire_vars| {
                let mut coeffs = wire_vars.iter().map(|&var| witness[var]).collect();
                Self::ifft(ctx, &domain, &mut coeffs);
                DensePolynomial::rand(1, &mut thread_rng()).mul_by_vanishing_poly(domain)
                    + DensePolynomial::from_coefficients_vec(coeffs)
            })
            .collect::<Vec<_>>();
        let wires_poly_comms = wire_polys
            .iter()
            .map(|poly| {
                Self::commit_polynomial(ctx, &ck, poly)
            })
            .collect::<Vec<_>>();
        transcript.append_commitments(b"witness_poly_comms", &wires_poly_comms)?;
        println!("Round 1: {:.2?}", now.elapsed());

        // Round 2
        let now = Instant::now();
        let beta = transcript.get_and_append_challenge::<Bls12_381>(b"beta")?;
        let gamma = transcript.get_and_append_challenge::<Bls12_381>(b"gamma")?;
        let permutation_poly = {
            let mut product_vec = vec![Fr::one()];
            for j in 0..(n - 1) {
                // Nominator
                let mut a = Fr::one();
                // Denominator
                let mut b = Fr::one();
                for i in 0..num_wire_types {
                    let wire_value = circuit.witness[circuit.wire_variables[i][j]];
                    let tmp = wire_value + gamma;
                    a *= tmp + beta * circuit.extended_id_permutation[i * n + j];
                    let (perm_i, perm_j) = circuit.wire_permutation[i * n + j];
                    b *= tmp + beta * circuit.extended_id_permutation[perm_i * n + perm_j];
                }
                product_vec.push(product_vec[j] * a / b);
            }
            Self::ifft(ctx, &domain, &mut product_vec);
            DensePolynomial::rand(2, prng).mul_by_vanishing_poly(domain)
                + DensePolynomial::from_coefficients_vec(product_vec)
        };
        let prod_perm_poly_comm = Self::commit_polynomial(
            ctx,
            &ck,
            &permutation_poly,
        );
        transcript.append_commitment(b"perm_poly_comms", &prod_perm_poly_comm)?;
        println!("Round 2: {:.2?}", now.elapsed());

        // Round 3
        let now = Instant::now();
        let alpha = transcript.get_and_append_challenge::<Bls12_381>(b"alpha")?;
        let alpha_square_div_n = alpha.square() / Fr::from(n as u64);
        let quotient_poly = {
            let tmp_domain = Radix2EvaluationDomain::<Fr>::new((n + 2) * 5).unwrap();

            let ab = wire_polys[0].mul(&wire_polys[1]);
            let cd = wire_polys[2].mul(&wire_polys[3]);

            let mut f = &pub_input
                + &prove_key.selectors[11]
                + prove_key.selectors[0].mul(&wire_polys[0])
                + prove_key.selectors[1].mul(&wire_polys[1])
                + prove_key.selectors[2].mul(&wire_polys[2])
                + prove_key.selectors[3].mul(&wire_polys[3])
                + prove_key.selectors[4].mul(&ab)
                + prove_key.selectors[5].mul(&cd)
                + prove_key.selectors[6].mul(&{
                    let mut evals = wire_polys[0].coeffs.clone();
                    Self::fft(ctx, &tmp_domain, &mut evals);
                    evals.par_iter_mut().for_each(|x| *x *= x.square().square());
                    Self::ifft(ctx, &tmp_domain, &mut evals);
                    DensePolynomial::from_coefficients_vec(evals)
                })
                + prove_key.selectors[7].mul(&{
                    let mut evals = wire_polys[1].coeffs.clone();
                    Self::fft(ctx, &tmp_domain, &mut evals);
                    evals.par_iter_mut().for_each(|x| *x *= x.square().square());
                    Self::ifft(ctx, &tmp_domain, &mut evals);
                    DensePolynomial::from_coefficients_vec(evals)
                })
                + prove_key.selectors[8].mul(&{
                    let mut evals = wire_polys[2].coeffs.clone();
                    Self::fft(ctx, &tmp_domain, &mut evals);
                    evals.par_iter_mut().for_each(|x| *x *= x.square().square());
                    Self::ifft(ctx, &tmp_domain, &mut evals);
                    DensePolynomial::from_coefficients_vec(evals)
                })
                + prove_key.selectors[9].mul(&{
                    let mut evals = wire_polys[3].coeffs.clone();
                    Self::fft(ctx, &tmp_domain, &mut evals);
                    evals.par_iter_mut().for_each(|x| *x *= x.square().square());
                    Self::ifft(ctx, &tmp_domain, &mut evals);
                    DensePolynomial::from_coefficients_vec(evals)
                })
                + -prove_key.selectors[10].mul(&wire_polys[4])
                + prove_key.selectors[12]
                    .mul(&ab)
                    .mul(&cd)
                    .mul(&wire_polys[4]);

            let mut g = permutation_poly.mul(alpha);
            for i in 0..num_wire_types {
                g = g.mul(
                    &(&wire_polys[i]
                        + &DensePolynomial {
                            coeffs: vec![gamma, beta * prove_key.vk.k[i]],
                        }),
                );
            }
            f = f + g;

            let mut h = permutation_poly.mul(-alpha);
            {
                let mut t = Fr::one();
                for i in 0..h.len() {
                    h[i] *= t;
                    t *= domain.group_gen;
                }
            }
            for i in 0..num_wire_types {
                h = h.mul(
                    &(&wire_polys[i]
                        + &prove_key.sigmas[i].mul(beta)
                        + DensePolynomial {
                            coeffs: vec![gamma],
                        }),
                );
            }
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
            let expected_degree = num_wire_types * (n + 1) + 2;
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
            .iter()
            .map(|poly| {
                Self::commit_polynomial(ctx, &ck, poly)
            })
            .collect::<Vec<_>>();
        transcript.append_commitments(b"quot_poly_comms", &split_quot_poly_comms)?;
        println!("Round 3: {:.2?}", now.elapsed());

        // Round 4
        let now = Instant::now();
        let zeta = transcript.get_and_append_challenge::<Bls12_381>(b"zeta")?;
        let wires_evals = wire_polys
            .par_iter()
            .map(|poly| poly.evaluate(&zeta))
            .collect::<Vec<_>>();
        let wire_sigma_evals = prove_key
            .sigmas
            .par_iter()
            .take(num_wire_types - 1)
            .map(|poly| poly.evaluate(&zeta))
            .collect::<Vec<_>>();
        let perm_next_eval = permutation_poly.evaluate(&(zeta * domain.group_gen));
        transcript.append_proof_evaluations::<Bls12_381>(
            &wires_evals,
            &wire_sigma_evals,
            &perm_next_eval,
        )?;
        println!("Round 4: {:.2?}", now.elapsed());

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
            let coeff = wires_evals
                .iter()
                .zip(&prove_key.vk.k)
                .fold(alpha, |acc, (&wire_eval, &k)| {
                    acc * (wire_eval + beta * k * zeta + gamma)
                })
                + alpha.square() * lagrange_1_eval;
            permutation_poly.mul(coeff)
        } + {
            // Compute the coefficient of the last sigma wire permutation polynomial
            let coeff = -wires_evals
                .iter()
                .take(num_wire_types - 1)
                .zip(&wire_sigma_evals)
                .fold(
                    alpha * beta * perm_next_eval,
                    |acc, (&wire_eval, &sigma_eval)| acc * (wire_eval + beta * sigma_eval + gamma),
                );
            prove_key.sigmas[num_wire_types - 1].mul(coeff)
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
            let (batch_poly, _) = polys_ref.iter().fold(
                (DensePolynomial::zero(), Fr::one()),
                |(acc, coeff), &poly| (acc + poly.mul(coeff), coeff * v),
            );

            Self::commit_polynomial(
                ctx,
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
            Self::commit_polynomial(
                ctx,
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
        println!("Round 5: {:.2?}", now.elapsed());

        Ok(Proof {
            wires_poly_comms,
            prod_perm_poly_comm,
            split_quot_poly_comms,
            opening_proof,
            shifted_opening_proof,
            poly_evals: ProofEvaluations {
                wires_evals,
                wire_sigma_evals,
                perm_next_eval,
            },
        })
    }
}

/// Private helper methods
impl Prover {
    #[inline]
    fn fft(ctx: &mut Context, domain: &Radix2EvaluationDomain<Fr>, coeffs: &mut Vec<Fr>) {
        coeffs.resize(domain.size(), Fr::zero());
        ctx.kernel
            .radix_fft(coeffs, &domain.group_gen, domain.log_size_of_group);
    }

    #[inline]
    fn ifft(ctx: &mut Context, domain: &Radix2EvaluationDomain<Fr>, coeffs: &mut Vec<Fr>) {
        coeffs.resize(domain.size(), Fr::zero());
        ctx.kernel
            .radix_fft(coeffs, &domain.group_gen_inv, domain.log_size_of_group);
        coeffs.iter_mut().for_each(|val| *val *= domain.size_inv);
    }

    #[inline]
    fn commit_polynomial(ctx: &mut Context, ck: &[G1Affine], poly: &[Fr]) -> Commitment<Bls12_381> {
        let mut plain_coeffs = poly.iter().map(|s| s.into_repr()).collect::<Vec<_>>();

        plain_coeffs.resize(ck.len(), Fr::zero().into_repr());

        Commitment(Self::msm(ctx, ck, &plain_coeffs).into())
    }

    #[inline]
    fn msm(
        ctx: &mut Context,
        bases: &[G1Affine],
        exps: &[<Fr as PrimeField>::BigInt],
    ) -> G1Projective {
        ctx.kernel.multiexp(&ctx.pool, bases, exps, 0)
    }
}
