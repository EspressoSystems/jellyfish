// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::structs::{Challenges, Oracles, ProofEvaluations, ProvingKey};
use crate::{
    circuit::Arithmetization,
    constants::{domain_size_ratio, GATE_WIDTH},
    errors::{PlonkError, SnarkError::*},
    proof_system::structs::CommitKey,
};
use ark_ec::PairingEngine;
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
    Radix2EvaluationDomain, UVPolynomial,
};
use ark_poly_commit::{
    kzg10::{Commitment, Randomness, KZG10},
    PCRandomness,
};
use ark_std::{
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use core::ops::Neg;
use rayon::prelude::*;

type CommitmentsAndPolys<E> = (
    Vec<Commitment<E>>,
    Vec<DensePolynomial<<E as PairingEngine>::Fr>>,
);

/// A Plonk IOP prover.
pub(crate) struct Prover<E: PairingEngine> {
    domain: Radix2EvaluationDomain<E::Fr>,
    quot_domain: GeneralEvaluationDomain<E::Fr>,
}

impl<E: PairingEngine> Prover<E> {
    /// Construct a Plonk prover that uses a domain with size `domain_size` and
    /// quotient polynomial domain with a size that is larger than the degree of
    /// the quotient polynomial.
    /// * `num_wire_types` - number of wire types in the corresponding
    ///   constraint system.
    pub(crate) fn new(domain_size: usize, num_wire_types: usize) -> Result<Self, PlonkError> {
        let domain = Radix2EvaluationDomain::<E::Fr>::new(domain_size)
            .ok_or(PlonkError::DomainCreationError)?;
        let quot_domain = GeneralEvaluationDomain::<E::Fr>::new(
            domain_size * domain_size_ratio(domain_size, num_wire_types),
        )
        .ok_or(PlonkError::DomainCreationError)?;
        Ok(Self {
            domain,
            quot_domain,
        })
    }

    /// Round 1:
    /// 1. Compute and commit wire witness polynomials.
    /// 2. Compute public input polynomial.
    /// Return the wire witness polynomials and their commitments,
    /// also return the public input polynomial.
    pub(crate) fn run_1st_round<C: Arithmetization<E::Fr>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        cs: &C,
    ) -> Result<(CommitmentsAndPolys<E>, DensePolynomial<E::Fr>), PlonkError> {
        let wire_polys: Vec<DensePolynomial<E::Fr>> = cs
            .compute_wire_polynomials()?
            .into_iter()
            .map(|poly| self.mask_polynomial(prng, poly, 1))
            .collect();
        let wires_poly_comms = Self::commit_polynomials(ck, &wire_polys)?;
        let pub_input_poly = cs.compute_pub_input_polynomial()?;
        Ok(((wires_poly_comms, wire_polys), pub_input_poly))
    }

    /// Round 2: Compute and commit the permutation grand product polynomial.
    /// Return the grand product polynomial and its commitment.
    pub(crate) fn run_2nd_round<C: Arithmetization<E::Fr>, R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        ck: &CommitKey<E>,
        cs: &C,
        challenges: &Challenges<E::Fr>,
    ) -> Result<(Commitment<E>, DensePolynomial<E::Fr>), PlonkError> {
        let prod_perm_poly = self.mask_polynomial(
            prng,
            cs.compute_prod_permutation_polynomial(&challenges.beta, &challenges.gamma)?,
            2,
        );
        let prod_perm_comm = Self::commit_polynomial(ck, &prod_perm_poly)?;
        Ok((prod_perm_comm, prod_perm_poly))
    }

    /// Round 3: Return the splitted quotient polynomials and their commitments.
    /// Note that the first `num_wire_types`-1 splitted quotient polynomials
    /// have degree `domain_size`+1.
    pub(crate) fn run_3rd_round(
        &self,
        ck: &CommitKey<E>,
        pks: &[&ProvingKey<E>],
        challenges: &Challenges<E::Fr>,
        online_oracles: &[Oracles<E::Fr>],
        num_wire_types: usize,
    ) -> Result<CommitmentsAndPolys<E>, PlonkError> {
        let quot_poly =
            self.compute_quotient_polynomial(challenges, pks, online_oracles, num_wire_types)?;
        let split_quot_polys = self.split_quotient_polynomial(&quot_poly, num_wire_types)?;
        let split_quot_poly_comms = Self::commit_polynomials(ck, &split_quot_polys)?;

        Ok((split_quot_poly_comms, split_quot_polys))
    }

    /// Round 4: Compute linearization polynomial and evaluate polynomials to be
    /// opened.
    ///
    /// Compute the polynomial evaluations for TurboPlonk.
    /// Return evaluations of the Plonk proof.
    pub(crate) fn compute_evaluations(
        &self,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        online_oracles: &Oracles<E::Fr>,
        num_wire_types: usize,
    ) -> ProofEvaluations<E::Fr> {
        let wires_evals: Vec<E::Fr> = online_oracles
            .wire_polys
            .par_iter()
            .map(|poly| poly.evaluate(&challenges.zeta))
            .collect();
        let wire_sigma_evals: Vec<E::Fr> = pk
            .sigmas
            .par_iter()
            .take(num_wire_types - 1)
            .map(|poly| poly.evaluate(&challenges.zeta))
            .collect();
        let perm_next_eval = online_oracles
            .prod_perm_poly
            .evaluate(&(challenges.zeta * self.domain.group_gen));

        ProofEvaluations {
            wires_evals,
            wire_sigma_evals,
            perm_next_eval,
        }
    }

    /// Compute linearization polynomial (excluding the quotient part)
    pub(crate) fn compute_non_quotient_component_for_lin_poly(
        &self,
        alpha_base: E::Fr,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        online_oracles: &Oracles<E::Fr>,
        poly_evals: &ProofEvaluations<E::Fr>,
    ) -> Result<DensePolynomial<E::Fr>, PlonkError> {
        let r_circ = Self::compute_lin_poly_circuit_contribution(pk, &poly_evals.wires_evals);
        let r_perm = Self::compute_lin_poly_copy_constraint_contribution(
            pk,
            challenges,
            poly_evals,
            &online_oracles.prod_perm_poly,
        );
        let mut lin_poly = r_circ + r_perm;

        lin_poly = Self::mul_poly(&lin_poly, &alpha_base);
        Ok(lin_poly)
    }

    // Compute the Quotient part of the linearization polynomial:
    //
    // -Z_H(x) * [t1(X) + x^{n+2} * t2(X) + ... + x^{(num_wire_types-1)*(n+2)} *
    // t_{num_wire_types}(X)]
    pub(crate) fn compute_quotient_component_for_lin_poly(
        domain_size: usize,
        zeta: E::Fr,
        quot_polys: &[DensePolynomial<E::Fr>],
    ) -> Result<DensePolynomial<E::Fr>, PlonkError> {
        let vanish_eval = zeta.pow(&[domain_size as u64]) - E::Fr::one();
        let zeta_to_n_plus_2 = (vanish_eval + E::Fr::one()) * zeta * zeta;
        let mut r_quot = quot_polys.first().ok_or(PlonkError::IndexError)?.clone();
        let mut coeff = E::Fr::one();
        for poly in quot_polys.iter().skip(1) {
            coeff *= zeta_to_n_plus_2;
            r_quot = r_quot + Self::mul_poly(poly, &coeff);
        }
        r_quot = Self::mul_poly(&r_quot, &vanish_eval.neg());
        Ok(r_quot)
    }

    /// Compute (aggregated) polynomial opening proofs at point `zeta` and
    /// `zeta * domain_generator`. TODO: Parallelize the computation.
    pub(crate) fn compute_opening_proofs(
        &self,
        ck: &CommitKey<E>,
        pks: &[&ProvingKey<E>],
        zeta: &E::Fr,
        v: &E::Fr,
        online_oracles: &[Oracles<E::Fr>],
        lin_poly: &DensePolynomial<E::Fr>,
    ) -> Result<(Commitment<E>, Commitment<E>), PlonkError> {
        if pks.is_empty() || pks.len() != online_oracles.len() {
            return Err(ParameterError(
                "inconsistent pks/online oracles when computing opening proofs".to_string(),
            )
            .into());
        }
        // List the polynomials to be opened at point `zeta`.
        let mut polys_ref = vec![lin_poly];
        for (pk, oracles) in pks.iter().zip(online_oracles.iter()) {
            for poly in oracles.wire_polys.iter() {
                polys_ref.push(poly);
            }
            // Note we do not add the last wire sigma polynomial.
            for poly in pk.sigmas.iter().take(pk.sigmas.len() - 1) {
                polys_ref.push(poly);
            }
        }

        let opening_proof =
            Self::compute_batched_witness_polynomial_commitment(ck, &polys_ref, v, zeta)?;

        // List the polynomials to be opened at point `zeta * w`.
        let mut polys_ref = vec![];
        for oracles in online_oracles.iter() {
            polys_ref.push(&oracles.prod_perm_poly);
        }

        let shifted_opening_proof = Self::compute_batched_witness_polynomial_commitment(
            ck,
            &polys_ref,
            v,
            &(self.domain.group_gen * zeta),
        )?;

        Ok((opening_proof, shifted_opening_proof))
    }
}

/// Private helper methods
impl<E: PairingEngine> Prover<E> {
    /// Mask the polynomial so that it remains hidden after revealing
    /// `hiding_bound` evaluations.
    fn mask_polynomial<R: CryptoRng + RngCore>(
        &self,
        prng: &mut R,
        poly: DensePolynomial<E::Fr>,
        hiding_bound: usize,
    ) -> DensePolynomial<E::Fr> {
        let mask_poly =
            DensePolynomial::rand(hiding_bound, prng).mul_by_vanishing_poly(self.domain);
        mask_poly + poly
    }

    /// Compute polynomial commitments.
    fn commit_polynomials(
        ck: &CommitKey<E>,
        polys: &[DensePolynomial<E::Fr>],
    ) -> Result<Vec<Commitment<E>>, PlonkError> {
        let poly_comms = polys
            .par_iter()
            .map(|poly| Self::commit_polynomial(ck, poly))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(poly_comms)
    }

    /// Commit a polynomial.
    #[inline]
    fn commit_polynomial(
        ck: &CommitKey<E>,
        poly: &DensePolynomial<E::Fr>,
    ) -> Result<Commitment<E>, PlonkError> {
        let (poly_comm, _) = KZG10::commit(ck, poly, None, None).map_err(PlonkError::PcsError)?;
        Ok(poly_comm)
    }

    /// Return a batched opening proof given a list of polynomials `polys_ref`,
    /// evaluation point `eval_point`, and randomized combiner `r`.
    fn compute_batched_witness_polynomial_commitment(
        ck: &CommitKey<E>,
        polys_ref: &[&DensePolynomial<E::Fr>],
        r: &E::Fr,
        eval_point: &E::Fr,
    ) -> Result<Commitment<E>, PlonkError> {
        // Compute the aggregated polynomial
        let (batch_poly, _) = polys_ref.iter().fold(
            (DensePolynomial::zero(), E::Fr::one()),
            |(acc, coeff), &poly| (acc + Self::mul_poly(poly, &coeff), coeff * r),
        );

        // Compute opening witness polynomial and its commitment
        let empty_rand = Randomness::<E::Fr, DensePolynomial<E::Fr>>::empty();
        let (witness_poly, _) = KZG10::<E, DensePolynomial<E::Fr>>::compute_witness_polynomial(
            &batch_poly,
            *eval_point,
            &empty_rand,
        )?;

        Self::commit_polynomial(ck, &witness_poly)
    }

    /// Compute the quotient polynomial via (i)FFTs.
    fn compute_quotient_polynomial(
        &self,
        challenges: &Challenges<E::Fr>,
        pks: &[&ProvingKey<E>],
        online_oracles: &[Oracles<E::Fr>],
        num_wire_types: usize,
    ) -> Result<DensePolynomial<E::Fr>, PlonkError> {
        if pks.is_empty() || pks.len() != online_oracles.len() {
            return Err(ParameterError(
                "inconsistent pks/online oracles when computing quotient polys".to_string(),
            )
            .into());
        }

        let n = self.domain.size();
        let m = self.quot_domain.size();
        let domain_size_ratio = m / n;
        // Compute 1/Z_H(w^i).
        let z_h_inv: Vec<E::Fr> = (0..domain_size_ratio)
            .map(|i| {
                ((E::Fr::multiplicative_generator() * self.quot_domain.element(i)).pow([n as u64])
                    - E::Fr::one())
                .inverse()
                .unwrap()
            })
            .collect();

        // Compute coset evaluations of the quotient polynomial.
        let mut quot_poly_coset_evals_sum = vec![E::Fr::zero(); m];
        let mut alpha_base = E::Fr::one();
        let alpha_3 = challenges.alpha.square() * challenges.alpha;
        // enumerate proving instances
        for (oracles, pk) in online_oracles.iter().zip(pks.iter()) {
            // Compute coset evaluations.
            let selectors_coset_fft: Vec<Vec<E::Fr>> = pk
                .selectors
                .par_iter()
                .map(|poly| self.quot_domain.coset_fft(poly.coeffs()))
                .collect();
            let sigmas_coset_fft: Vec<Vec<E::Fr>> = pk
                .sigmas
                .par_iter()
                .map(|poly| self.quot_domain.coset_fft(poly.coeffs()))
                .collect();

            let wire_polys_coset_fft: Vec<Vec<E::Fr>> = oracles
                .wire_polys
                .par_iter()
                .map(|poly| self.quot_domain.coset_fft(poly.coeffs()))
                .collect();
            // TODO: (binyi) we can also compute below in parallel with
            // `wire_polys_coset_fft`.
            let prod_perm_poly_coset_fft =
                self.quot_domain.coset_fft(oracles.prod_perm_poly.coeffs());
            let pub_input_poly_coset_fft =
                self.quot_domain.coset_fft(oracles.pub_inp_poly.coeffs());

            // Compute coset evaluations of the quotient polynomial.
            let quot_poly_coset_evals: Vec<E::Fr> = (0..m)
                .into_par_iter()
                .map(|i| {
                    let w: Vec<E::Fr> = (0..num_wire_types)
                        .map(|j| wire_polys_coset_fft[j][i])
                        .collect();

                    let t_circ = Self::compute_quotient_circuit_contribution(
                        i,
                        &w,
                        &pub_input_poly_coset_fft[i],
                        &selectors_coset_fft,
                    );
                    let (t_perm_1, t_perm_2) = Self::compute_quotient_copy_constraint_contribution(
                        i,
                        self.quot_domain.element(i) * E::Fr::multiplicative_generator(),
                        pk,
                        &w,
                        &prod_perm_poly_coset_fft[i],
                        &prod_perm_poly_coset_fft[(i + domain_size_ratio) % m],
                        challenges,
                        &sigmas_coset_fft,
                    );
                    let t1 = t_circ + t_perm_1;
                    let t2 = t_perm_2;

                    t1 * z_h_inv[i % domain_size_ratio] + t2
                })
                .collect();
            for (a, b) in quot_poly_coset_evals_sum
                .iter_mut()
                .zip(quot_poly_coset_evals.iter())
            {
                *a += alpha_base * b;
            }

            alpha_base *= alpha_3;
        }
        // Compute the coefficient form of the quotient polynomial
        Ok(DensePolynomial::from_coefficients_vec(
            self.quot_domain.coset_ifft(&quot_poly_coset_evals_sum),
        ))
    }

    // Compute the i-th coset evaluation of the circuit part of the quotient
    // polynomial.
    fn compute_quotient_circuit_contribution(
        i: usize,
        w: &[E::Fr],
        pi: &E::Fr,
        selectors_coset_fft: &[Vec<E::Fr>],
    ) -> E::Fr {
        // Selectors
        // The order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
        // TODO: (binyi) get the order from a function.
        let q_lc: Vec<E::Fr> = (0..GATE_WIDTH).map(|j| selectors_coset_fft[j][i]).collect();
        let q_mul: Vec<E::Fr> = (GATE_WIDTH..GATE_WIDTH + 2)
            .map(|j| selectors_coset_fft[j][i])
            .collect();
        let q_hash: Vec<E::Fr> = (GATE_WIDTH + 2..2 * GATE_WIDTH + 2)
            .map(|j| selectors_coset_fft[j][i])
            .collect();
        let q_o = selectors_coset_fft[2 * GATE_WIDTH + 2][i];
        let q_c = selectors_coset_fft[2 * GATE_WIDTH + 3][i];
        let q_ecc = selectors_coset_fft[2 * GATE_WIDTH + 4][i];

        q_c + pi
            + q_lc[0] * w[0]
            + q_lc[1] * w[1]
            + q_lc[2] * w[2]
            + q_lc[3] * w[3]
            + q_mul[0] * w[0] * w[1]
            + q_mul[1] * w[2] * w[3]
            + q_ecc * w[0] * w[1] * w[2] * w[3] * w[4]
            + q_hash[0] * w[0].pow(&[5])
            + q_hash[1] * w[1].pow(&[5])
            + q_hash[2] * w[2].pow(&[5])
            + q_hash[3] * w[3].pow(&[5])
            - q_o * w[4]
    }

    /// Compute the i-th coset evaluation of the copy constraint part of the
    /// quotient polynomial.
    /// `eval_point` - the evaluation point.
    /// `w` - the wire polynomial coset evaluations at `eval_point`.
    /// `z_x` - the permutation product polynomial evaluation at `eval_point`.
    /// `z_xw`-  the permutation product polynomial evaluation at `eval_point *
    /// g`, where `g` is the root of unity of the original domain.
    #[allow(clippy::too_many_arguments)]
    fn compute_quotient_copy_constraint_contribution(
        i: usize,
        eval_point: E::Fr,
        pk: &ProvingKey<E>,
        w: &[E::Fr],
        z_x: &E::Fr,
        z_xw: &E::Fr,
        challenges: &Challenges<E::Fr>,
        sigmas_coset_fft: &[Vec<E::Fr>],
    ) -> (E::Fr, E::Fr) {
        let num_wire_types = w.len();
        let n = pk.domain_size();

        // The check that:
        //   \prod_i [w_i(X) + beta * k_i * X + gamma] * z(X)
        // - \prod_i [w_i(X) + beta * sigma_i(X) + gamma] * z(wX) = 0
        // on the vanishing set.
        // Delay the division of Z_H(X).
        //
        // Extended permutation values
        let sigmas: Vec<E::Fr> = (0..num_wire_types)
            .map(|j| sigmas_coset_fft[j][i])
            .collect();

        // Compute the 1st term.
        let mut result_1 = challenges.alpha
            * w.iter().enumerate().fold(*z_x, |acc, (j, &w)| {
                acc * (w + pk.k()[j] * eval_point * challenges.beta + challenges.gamma)
            });
        // Minus the 2nd term.
        result_1 -= challenges.alpha
            * w.iter()
                .zip(sigmas.iter())
                .fold(*z_xw, |acc, (&w, &sigma)| {
                    acc * (w + sigma * challenges.beta + challenges.gamma)
                });

        // The check that z(x) = 1 at point 1.
        // (z(x)-1) * L1(x) * alpha^2 / Z_H(x) = (z(x)-1) * alpha^2 / (n * (x - 1))
        let result_2 = challenges.alpha.square() * (*z_x - E::Fr::one())
            / (E::Fr::from(n as u64) * (eval_point - E::Fr::one()));

        (result_1, result_2)
    }

    /// Split the quotient polynomial into `num_wire_types` polynomials.
    /// The first `num_wire_types`-1 polynomials have degree `domain_size`+1.
    fn split_quotient_polynomial(
        &self,
        quot_poly: &DensePolynomial<E::Fr>,
        num_wire_types: usize,
    ) -> Result<Vec<DensePolynomial<E::Fr>>, PlonkError> {
        let expected_degree = quotient_polynomial_degree(self.domain.size(), num_wire_types);
        if quot_poly.degree() != expected_degree {
            return Err(WrongQuotientPolyDegree(quot_poly.degree(), expected_degree).into());
        }
        let n = self.domain.size();
        let split_quot_polys = (0..num_wire_types)
            .into_par_iter()
            .map(|i| {
                let end = if i < num_wire_types - 1 {
                    (i + 1) * (n + 2)
                } else {
                    quot_poly.degree() + 1
                };
                // Degree-(n+1) polynomial has n + 2 coefficients.
                DensePolynomial::<E::Fr>::from_coefficients_slice(
                    &quot_poly.coeffs[i * (n + 2)..end],
                )
            })
            .collect();
        Ok(split_quot_polys)
    }

    // Compute the circuit part of the linearization polynomial
    fn compute_lin_poly_circuit_contribution(
        pk: &ProvingKey<E>,
        w_evals: &[E::Fr],
    ) -> DensePolynomial<E::Fr> {
        // The selectors order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
        // TODO: (binyi) get the order from a function.
        let q_lc = &pk.selectors[..GATE_WIDTH];
        let q_mul = &pk.selectors[GATE_WIDTH..GATE_WIDTH + 2];
        let q_hash = &pk.selectors[GATE_WIDTH + 2..2 * GATE_WIDTH + 2];
        let q_o = &pk.selectors[2 * GATE_WIDTH + 2];
        let q_c = &pk.selectors[2 * GATE_WIDTH + 3];
        let q_ecc = &pk.selectors[2 * GATE_WIDTH + 4];

        // TODO(binyi): add polynomials in parallel.
        // Note we don't need to compute the constant term of the polynomial.
        Self::mul_poly(&q_lc[0], &w_evals[0])
            + Self::mul_poly(&q_lc[1], &w_evals[1])
            + Self::mul_poly(&q_lc[2], &w_evals[2])
            + Self::mul_poly(&q_lc[3], &w_evals[3])
            + Self::mul_poly(&q_mul[0], &(w_evals[0] * w_evals[1]))
            + Self::mul_poly(&q_mul[1], &(w_evals[2] * w_evals[3]))
            + Self::mul_poly(&q_hash[0], &w_evals[0].pow(&[5]))
            + Self::mul_poly(&q_hash[1], &w_evals[1].pow(&[5]))
            + Self::mul_poly(&q_hash[2], &w_evals[2].pow(&[5]))
            + Self::mul_poly(&q_hash[3], &w_evals[3].pow(&[5]))
            + Self::mul_poly(
                q_ecc,
                &(w_evals[0] * w_evals[1] * w_evals[2] * w_evals[3] * w_evals[4]),
            )
            + Self::mul_poly(q_o, &(-w_evals[4]))
            + q_c.clone()
    }

    // Compute the wire permutation part of the linearization polynomial
    fn compute_lin_poly_copy_constraint_contribution(
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
        poly_evals: &ProofEvaluations<E::Fr>,
        prod_perm_poly: &DensePolynomial<E::Fr>,
    ) -> DensePolynomial<E::Fr> {
        let dividend = challenges.zeta.pow(&[pk.domain_size() as u64]) - E::Fr::one();
        let divisor = E::Fr::from(pk.domain_size() as u32) * (challenges.zeta - E::Fr::one());
        let lagrange_1_eval = dividend / divisor;

        // Compute the coefficient of z(X)
        let coeff = poly_evals.wires_evals.iter().enumerate().fold(
            challenges.alpha,
            |acc, (j, &wire_eval)| {
                acc * (wire_eval
                    + challenges.beta * pk.vk.k[j] * challenges.zeta
                    + challenges.gamma)
            },
        ) + challenges.alpha.square() * lagrange_1_eval;
        let mut r_perm = Self::mul_poly(prod_perm_poly, &coeff);

        // Compute the coefficient of the last sigma wire permutation polynomial
        let num_wire_types = poly_evals.wires_evals.len();
        let coeff = -poly_evals
            .wires_evals
            .iter()
            .take(num_wire_types - 1)
            .zip(poly_evals.wire_sigma_evals.iter())
            .fold(
                challenges.alpha * challenges.beta * poly_evals.perm_next_eval,
                |acc, (&wire_eval, &sigma_eval)| {
                    acc * (wire_eval + challenges.beta * sigma_eval + challenges.gamma)
                },
            );
        r_perm = r_perm + Self::mul_poly(&pk.sigmas[num_wire_types - 1], &coeff);
        r_perm
    }

    #[inline]
    fn mul_poly(poly: &DensePolynomial<E::Fr>, coeff: &E::Fr) -> DensePolynomial<E::Fr> {
        DensePolynomial::<E::Fr>::from_coefficients_vec(
            poly.coeffs.par_iter().map(|c| *coeff * c).collect(),
        )
    }
}

#[inline]
fn quotient_polynomial_degree(domain_size: usize, num_wire_types: usize) -> usize {
    num_wire_types * (domain_size + 1) + 2
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;
    use ark_bw6_761::BW6_761;
    use ark_std::test_rng;

    #[test]
    fn test_split_quotient_polynomial_wrong_degree() -> Result<(), PlonkError> {
        test_split_quotient_polynomial_wrong_degree_helper::<Bn254>()?;
        test_split_quotient_polynomial_wrong_degree_helper::<Bls12_377>()?;
        test_split_quotient_polynomial_wrong_degree_helper::<Bls12_381>()?;
        test_split_quotient_polynomial_wrong_degree_helper::<BW6_761>()
    }

    fn test_split_quotient_polynomial_wrong_degree_helper<E: PairingEngine>(
    ) -> Result<(), PlonkError> {
        let prover = Prover::<E>::new(4, GATE_WIDTH + 1)?;
        let rng = &mut test_rng();
        let bad_quot_poly = DensePolynomial::<E::Fr>::rand(25, rng);
        assert!(prover
            .split_quotient_polynomial(&bad_quot_poly, GATE_WIDTH + 1)
            .is_err());
        Ok(())
    }
}
