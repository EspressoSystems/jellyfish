// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::structs::{BatchProof, Challenges, ProofEvaluations, ScalarsAndBases, VerifyingKey};
use crate::{
    circuit::customized::ecc::SWToTEConParam,
    constants::*,
    errors::{PlonkError, SnarkError::ParameterError},
    proof_system::structs::OpenKey,
    transcript::*,
};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters};
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_poly_commit::kzg10::Commitment;
use ark_std::{format, vec, vec::Vec};
use core::ops::Neg;
use jf_rescue::RescueParameter;
use jf_utils::multi_pairing;

/// (Aggregated) polynomial commitment evaluation info.
/// * `u` - a random combiner that was used to combine evaluations at point
///   `eval_point` and `next_eval_point`.
/// * `eval_point` - the point to be evaluated at.
/// * `next_eval_point` - the shifted point to be evaluated at.
/// * `eval` - the (aggregated) polynomial evaluation value.
/// * `comm_scalars_and_bases` - the scalars-and-bases form of the (aggregated)
///   polynomial commitment.
/// * `opening_proof` - (aggregated) proof of evaluations at point `eval_point`.
/// * `shifted_opening_proof` - (aggregated) proof of evaluations at point
///   `next_eval_point`.
#[derive(Debug)]
pub(crate) struct PcsInfo<E: PairingEngine> {
    pub(crate) u: E::Fr,
    pub(crate) eval_point: E::Fr,
    pub(crate) next_eval_point: E::Fr,
    pub(crate) eval: E::Fr,
    pub(crate) comm_scalars_and_bases: ScalarsAndBases<E>,
    pub(crate) opening_proof: Commitment<E>,
    pub(crate) shifted_opening_proof: Commitment<E>,
}

pub(crate) struct Verifier<E: PairingEngine> {
    pub(crate) domain: Radix2EvaluationDomain<E::Fr>,
}

impl<E, F, P> Verifier<E>
where
    E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWModelParameters<BaseField = F> + Clone,
{
    /// Construct a Plonk verifier that uses a domain with size `domain_size`.
    pub(crate) fn new(domain_size: usize) -> Result<Self, PlonkError> {
        let domain = Radix2EvaluationDomain::<E::Fr>::new(domain_size)
            .ok_or(PlonkError::DomainCreationError)?;
        Ok(Self { domain })
    }

    /// Prepare the (aggregated) polynomial commitment evaluation information.
    pub(crate) fn prepare_pcs_info<T>(
        &self,
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        batch_proof: &BatchProof<E>,
    ) -> Result<PcsInfo<E>, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        if verify_keys.len() != batch_proof.len()
            || verify_keys.len() != public_inputs.len()
            || verify_keys.is_empty()
        {
            return Err(ParameterError(format!(
                "the number of verification keys = {}; the number of instances = {}; the number of public inputs = {}",
                verify_keys.len(),
                batch_proof.len(),
                public_inputs.len(),
            ))
            .into());
        }
        for (i, (&pub_input, &vk)) in public_inputs.iter().zip(verify_keys.iter()).enumerate() {
            if pub_input.len() != vk.num_inputs {
                return Err(ParameterError(
                    format!("the circuit public input length {} != the {}-th verification key public input length {}", pub_input.len(), i, vk.num_inputs)
                )
                .into());
            }
            if vk.domain_size != self.domain.size() {
                return Err(ParameterError(format!(
                    "the domain size {} of the {}-th verification key is different from {}",
                    vk.domain_size,
                    i,
                    self.domain.size(),
                ))
                .into());
            }
        }

        // compute challenges and evaluations
        let challenges = Self::compute_challenges::<T>(verify_keys, public_inputs, batch_proof)?;

        // pre-compute alpha related values
        let alpha_2 = challenges.alpha.square();
        let alpha_3 = alpha_2 * challenges.alpha;
        let alpha_4 = alpha_2 * alpha_2;
        let alpha_5 = alpha_2 * alpha_3;
        let alpha_6 = alpha_4 * alpha_2;
        let alpha_powers = vec![alpha_2, alpha_3, alpha_4, alpha_5, alpha_6];
        let mut alpha_bases = vec![E::Fr::one()];

        let mut tmp = alpha_3;
        if verify_keys.len() > 1 {
            for _ in 0..verify_keys.len() - 1 {
                alpha_bases.push(tmp);
                tmp *= alpha_bases[1];
            }
        }

        let vanish_eval = self.evaluate_vanishing_poly(&challenges.zeta);
        let lagrange_1_eval = self.evaluate_lagrange(&challenges.zeta, &vanish_eval);

        // compute the constant term of the linearization polynomial
        let lin_poly_constant = self.compute_lin_poly_constant_term(
            &challenges,
            verify_keys,
            public_inputs,
            batch_proof,
            &vanish_eval,
            &lagrange_1_eval,
            &alpha_powers,
            &alpha_bases,
        )?;

        // build the (aggregated) polynomial commitment/evaluation instance
        let (comm_scalars_and_bases, buffer_v_and_uv_basis) = self.aggregate_poly_commitments(
            verify_keys,
            &challenges,
            &vanish_eval,
            &lagrange_1_eval,
            batch_proof,
            &alpha_powers,
            &alpha_bases,
        )?;
        let eval = Self::aggregate_evaluations(
            &lin_poly_constant,
            &batch_proof.poly_evals_vec,
            &buffer_v_and_uv_basis,
        )?;

        Ok(PcsInfo {
            u: challenges.u,
            eval_point: challenges.zeta,
            next_eval_point: challenges.zeta * self.domain.group_gen,
            comm_scalars_and_bases,
            eval,
            opening_proof: batch_proof.opening_proof,
            shifted_opening_proof: batch_proof.shifted_opening_proof,
        })
    }

    /// Batchly verify multiple (aggregated) PCS opening proofs.
    ///
    /// We need to verify that
    /// - `e(Ai, [x]2) = e(Bi, [1]2) for i \in {0, .., m-1}`, where
    /// - `Ai = [open_proof_i] + u_i * [shifted_open_proof_i]` and
    /// - `Bi = eval_point_i * [open_proof_i] + u_i * next_eval_point_i *
    ///   [shifted_open_proof_i] + comm_i - eval_i * [1]1`.
    /// By Schwartz-Zippel lemma, it's equivalent to check that for a random r:
    /// - `e(A0 + ... + r^{m-1} * Am, [x]2) = e(B0 + ... + r^{m-1} * Bm, [1]2)`.
    pub(crate) fn batch_verify_opening_proofs<T>(
        open_key: &OpenKey<E>,
        pcs_infos: &[PcsInfo<E>],
    ) -> Result<bool, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        // Compute a pseudorandom challenge from the instances
        let r = if pcs_infos.len() == 1 {
            // No need to use `r` when there is only a single proof.
            E::Fr::one()
        } else {
            let mut transcript = T::new(b"batch verify");
            // r := hash(u1||u2||...||u_m), where u_i is the hash output of the i-th Plonk
            // protocol transcript. This approach is more secure as `r` depends not only
            // on the proofs, but also the list of public inputs and verifying keys.
            for pcs_info in pcs_infos {
                transcript.append_challenge::<E>(b"u", &pcs_info.u)?;
            }
            transcript.get_and_append_challenge::<E>(b"r")?
        };

        // Compute A := A0 + r * A1 + ... + r^{m-1} * Am
        let mut inners = ScalarsAndBases::<E>::new();
        let mut r_base = E::Fr::one();
        for pcs_info in pcs_infos.iter() {
            inners.push(r_base, pcs_info.opening_proof.0);
            inners.push(r_base * pcs_info.u, pcs_info.shifted_opening_proof.0);
            r_base *= r;
        }
        let inner = inners.multi_scalar_mul();
        // Add (A, [x]2) to the product pairing list
        let mut g1_elems: Vec<<E as PairingEngine>::G1Affine> = vec![inner.into()];
        let mut g2_elems = vec![open_key.beta_h];

        // Compute B := B0 + r * B1 + ... + r^{m-1} * Bm
        let mut inners = ScalarsAndBases::new();
        let mut r_base = E::Fr::one();
        let mut sum_evals = E::Fr::zero();
        for pcs_info in pcs_infos.iter() {
            inners.merge(r_base, &pcs_info.comm_scalars_and_bases);
            inners.push(r_base * pcs_info.eval_point, pcs_info.opening_proof.0);
            inners.push(
                r_base * pcs_info.u * pcs_info.next_eval_point,
                pcs_info.shifted_opening_proof.0,
            );
            sum_evals += r_base * pcs_info.eval;
            r_base *= r;
        }
        inners.push(-sum_evals, open_key.g);
        let inner = inners.multi_scalar_mul();
        // Add (-B, [1]2) to the product pairing list
        g1_elems.push(-inner.into());
        g2_elems.push(open_key.h);
        // Check e(A, [x]2) ?= e(B, [1]2)
        Ok(multi_pairing::<E>(&g1_elems, &g2_elems) == E::Fqk::one())
    }

    /// Compute verifier challenges `beta`, `gamma`, `alpha`, `zeta`,
    /// 'v', 'u'.
    #[inline]
    pub(crate) fn compute_challenges<T>(
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        batch_proof: &BatchProof<E>,
    ) -> Result<Challenges<E::Fr>, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        if verify_keys.len() != batch_proof.len() || verify_keys.len() != public_inputs.len() {
            return Err(ParameterError(format!(
                "the number of verification keys = {}; the number of instances = {}; the number of public inputs = {}",
                verify_keys.len(),
                batch_proof.len(),
                public_inputs.len(),
            ))
            .into());
        }
        let mut transcript = T::new(b"PlonkProof");
        for (&vk, &pi) in verify_keys.iter().zip(public_inputs.iter()) {
            transcript.append_vk_and_pub_input(vk, pi)?;
        }
        for wires_poly_comms in batch_proof.wires_poly_comms_vec.iter() {
            transcript.append_commitments(b"witness_poly_comms", wires_poly_comms)?;
        }

        let beta = transcript.get_and_append_challenge::<E>(b"beta")?;
        let gamma = transcript.get_and_append_challenge::<E>(b"gamma")?;
        for prod_perm_poly_comm in batch_proof.prod_perm_poly_comms_vec.iter() {
            transcript.append_commitment(b"perm_poly_comms", prod_perm_poly_comm)?;
        }

        let alpha = transcript.get_and_append_challenge::<E>(b"alpha")?;
        transcript.append_commitments(b"quot_poly_comms", &batch_proof.split_quot_poly_comms)?;
        let zeta = transcript.get_and_append_challenge::<E>(b"zeta")?;
        for poly_evals in batch_proof.poly_evals_vec.iter() {
            transcript.append_proof_evaluations::<E>(poly_evals)?;
        }

        let v = transcript.get_and_append_challenge::<E>(b"v")?;
        transcript.append_commitment(b"open_proof", &batch_proof.opening_proof)?;
        transcript.append_commitment(b"shifted_open_proof", &batch_proof.shifted_opening_proof)?;
        let u = transcript.get_and_append_challenge::<E>(b"u")?;
        Ok(Challenges {
            alpha,
            beta,
            gamma,
            zeta,
            v,
            u,
        })
    }

    /// Compute the constant term of the linearization polynomial:
    /// For each instance j:
    ///
    /// r_plonk_j = PI - L1(x) * alpha^2 -
    ///             alpha * \prod_i=1..m-1 (w_{j,i} + beta * sigma_{j,i} +
    /// gamma) * (w_{j,m} + gamma) * z_j(xw)
    ///
    /// r_lookup_j = alpha^3 * Ln(x) * (h1_x_j - h2_wx_j) -
    ///              alpha^4 * L1(x) * alpha -
    ///              alpha^5 * Ln(x) -
    ///              alpha^6 * (x - g^{n-1}) * prod_poly_wx_j * [gamma(1+beta) +
    /// h1_x_j + beta * h1_wx_j] * [gamma(1+beta) + beta * h2_wx_j]
    ///
    /// r_0 = \sum_{j=1..m} alpha^{k_j} * (r_plonk_j + (r_lookup_j))
    /// where m is the number of instances, and k_j is the number of alpha power
    /// terms added to the first j-1 instances.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_lin_poly_constant_term(
        &self,
        challenges: &Challenges<E::Fr>,
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        batch_proof: &BatchProof<E>,
        vanish_eval: &E::Fr,
        lagrange_1_eval: &E::Fr,
        alpha_powers: &[E::Fr],
        alpha_bases: &[E::Fr],
    ) -> Result<E::Fr, PlonkError> {
        if verify_keys.len() != batch_proof.len()
            || verify_keys.len() != public_inputs.len()
            || verify_keys.len() != alpha_bases.len()
        {
            return Err(ParameterError(format!(
                "the number of verification keys = {}; the number of instances = {}; the number of public inputs = {}; the number of alpha bases = {}",
                verify_keys.len(),
                batch_proof.len(),
                public_inputs.len(),
                alpha_bases.len()
            ))
            .into());
        }

        let mut result = E::Fr::zero();
        for (poly_evals, (&pi, (&_vk, &current_alpha_bases))) in
            batch_proof.poly_evals_vec.iter().zip(
                public_inputs
                    .iter()
                    .zip(verify_keys.iter().zip(alpha_bases.iter())),
            )
        {
            let mut tmp = self.evaluate_pi_poly(pi, &challenges.zeta, vanish_eval)?
                - alpha_powers[0] * lagrange_1_eval;
            let num_wire_types = GATE_WIDTH + 1;
            let first_w_evals = &poly_evals.wires_evals[..num_wire_types - 1];
            let last_w_eval = &poly_evals.wires_evals[num_wire_types - 1];
            let sigma_evals = &poly_evals.wire_sigma_evals[..];
            tmp -= first_w_evals.iter().zip(sigma_evals.iter()).fold(
                challenges.alpha * poly_evals.perm_next_eval * (challenges.gamma + last_w_eval),
                |acc, (w_eval, sigma_eval)| {
                    acc * (challenges.gamma + w_eval + challenges.beta * sigma_eval)
                },
            );

            result += current_alpha_bases * tmp;
        }
        Ok(result)
    }

    /// Aggregate polynomial commitments into a single commitment (in the
    /// ScalarsAndBases form). Useful in batch opening.
    /// The verification key type is guaranteed to match the Plonk proof type.
    /// The returned commitment is a generalization of `[F]1` described in Sec 8.4, step 10 of https://eprint.iacr.org/2019/953.pdf
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn aggregate_poly_commitments(
        &self,
        vks: &[&VerifyingKey<E>],
        challenges: &Challenges<E::Fr>,
        vanish_eval: &E::Fr,
        lagrange_1_eval: &E::Fr,
        batch_proof: &BatchProof<E>,
        alpha_powers: &[E::Fr],
        alpha_bases: &[E::Fr],
    ) -> Result<(ScalarsAndBases<E>, Vec<E::Fr>), PlonkError> {
        if vks.len() != batch_proof.len() {
            return Err(ParameterError(format!(
                "the number of verification keys {} != the number of instances {}",
                vks.len(),
                batch_proof.len()
            ))
            .into());
        }

        // Compute the first part of the batched polynomial commitment `[D]1` described in Sec 8.4, step 9 of https://eprint.iacr.org/2019/953.pdf
        let mut scalars_and_bases = self.linearization_scalars_and_bases(
            vks,
            challenges,
            vanish_eval,
            lagrange_1_eval,
            batch_proof,
            alpha_powers,
            alpha_bases,
        )?;

        // the random combiner term for the polynomials evaluated at point `zeta`
        let mut v_base = challenges.v;
        // the random combiner term for the polynomials evaluated at point `zeta * g`
        let mut uv_base = challenges.u;

        // return buffer for aggregate_evaluations computation
        let mut buffer_v_and_uv_basis = vec![];

        for (i, vk) in vks.iter().enumerate() {
            // Add poly commitments to be evaluated at point `zeta`.
            // Add wire witness polynomial commitments.
            for &poly_comm in batch_proof.wires_poly_comms_vec[i].iter() {
                buffer_v_and_uv_basis.push(v_base);
                Self::add_poly_comm(
                    &mut scalars_and_bases,
                    &mut v_base,
                    poly_comm.0,
                    challenges.v,
                );
            }
            // Add wire sigma polynomial commitments. The last sigma commitment is excluded.
            let num_wire_types = batch_proof.wires_poly_comms_vec[i].len();
            for &poly_comm in vk.sigma_comms.iter().take(num_wire_types - 1) {
                buffer_v_and_uv_basis.push(v_base);
                Self::add_poly_comm(
                    &mut scalars_and_bases,
                    &mut v_base,
                    poly_comm.0,
                    challenges.v,
                );
            }

            // Add poly commitments to be evaluated at point `zeta * g`.
            buffer_v_and_uv_basis.push(uv_base);
            Self::add_poly_comm(
                &mut scalars_and_bases,
                &mut uv_base,
                batch_proof.prod_perm_poly_comms_vec[i].0,
                challenges.v,
            );
        }

        Ok((scalars_and_bases, buffer_v_and_uv_basis))
    }

    /// Compute the bases and scalars in the batched polynomial commitment,
    /// which is a generalization of `[D]1` specified in Sec 8.3, Verifier
    /// algorithm step 9 of https://eprint.iacr.org/2019/953.pdf.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn linearization_scalars_and_bases(
        &self,
        vks: &[&VerifyingKey<E>],
        challenges: &Challenges<E::Fr>,
        vanish_eval: &E::Fr,
        lagrange_1_eval: &E::Fr,
        batch_proof: &BatchProof<E>,
        alpha_powers: &[E::Fr],
        alpha_bases: &[E::Fr],
    ) -> Result<ScalarsAndBases<E>, PlonkError> {
        if vks.len() != batch_proof.len() || alpha_bases.len() != vks.len() {
            return Err(ParameterError(format!(
                "the number of verification keys {} != the number of instances {} or alpha bases {}",
                vks.len(),
                batch_proof.len(),
                alpha_bases.len()
            ))
            .into());
        }

        let mut scalars_and_bases = ScalarsAndBases::new();
        for (i, (vk, &current_alpha_bases)) in vks.iter().zip(alpha_bases).enumerate() {
            // Compute coefficient for the permutation product polynomial commitment.
            // coeff = L1(zeta) * alpha^2
            //       + alpha
            //       * (beta * zeta      + a_bar + gamma)
            //       * (beta * k1 * zeta + b_bar + gamma)
            //       * (beta * k2 * zeta + c_bar + gamma)
            // where a_bar, b_bar and c_bar are in w_evals
            let mut coeff = alpha_powers[0] * lagrange_1_eval;
            let w_evals = &batch_proof.poly_evals_vec[i].wires_evals;
            coeff += w_evals
                .iter()
                .zip(vk.k.iter())
                .fold(challenges.alpha, |acc, (w_eval, k)| {
                    acc * (challenges.beta * k * challenges.zeta + challenges.gamma + w_eval)
                });
            coeff *= current_alpha_bases;
            // Add permutation product polynomial commitment.
            scalars_and_bases.push(coeff, batch_proof.prod_perm_poly_comms_vec[i].0);

            // Compute coefficient for the last wire sigma polynomial commitment.
            let num_wire_types = batch_proof.wires_poly_comms_vec[i].len();
            let sigma_evals = &batch_proof.poly_evals_vec[i].wire_sigma_evals;
            let coeff = w_evals
                .iter()
                .take(num_wire_types - 1)
                .zip(sigma_evals.iter())
                .fold(
                    challenges.alpha
                        * challenges.beta
                        * batch_proof.poly_evals_vec[i].perm_next_eval,
                    |acc, (w_eval, sigma_eval)| {
                        acc * (challenges.beta * sigma_eval + challenges.gamma + w_eval)
                    },
                )
                * current_alpha_bases;
            // Add output wire sigma polynomial commitment.
            scalars_and_bases.push(
                -coeff,
                vk.sigma_comms.last().ok_or(PlonkError::IndexError)?.0,
            );

            // Add selector polynomial commitments.
            // Compute coefficients for selector polynomial commitments.
            // The order: q_lc, q_mul, q_hash, q_o, q_c, q_ecc
            // TODO(binyi): get the order from a function.
            let mut q_scalars = vec![E::Fr::zero(); 2 * GATE_WIDTH + 5];
            q_scalars[0] = w_evals[0];
            q_scalars[1] = w_evals[1];
            q_scalars[2] = w_evals[2];
            q_scalars[3] = w_evals[3];
            q_scalars[4] = w_evals[0] * w_evals[1];
            q_scalars[5] = w_evals[2] * w_evals[3];
            q_scalars[6] = w_evals[0].pow([5]);
            q_scalars[7] = w_evals[1].pow([5]);
            q_scalars[8] = w_evals[2].pow([5]);
            q_scalars[9] = w_evals[3].pow([5]);
            q_scalars[10] = -w_evals[4];
            q_scalars[11] = E::Fr::one();
            q_scalars[12] = w_evals[0] * w_evals[1] * w_evals[2] * w_evals[3] * w_evals[4];
            for (&s, poly) in q_scalars.iter().zip(vk.selector_comms.iter()) {
                scalars_and_bases.push(s * current_alpha_bases, poly.0);
            }
        }

        // Add splitted quotient commitments
        let zeta_to_n_plus_2 = (E::Fr::one() + vanish_eval) * challenges.zeta * challenges.zeta;
        let mut coeff = vanish_eval.neg();
        scalars_and_bases.push(
            coeff,
            batch_proof
                .split_quot_poly_comms
                .first()
                .ok_or(PlonkError::IndexError)?
                .0,
        );
        for poly in batch_proof.split_quot_poly_comms.iter().skip(1) {
            coeff *= zeta_to_n_plus_2;
            scalars_and_bases.push(coeff, poly.0);
        }

        Ok(scalars_and_bases)
    }

    /// Combine the polynomial evaluations into a single evaluation. Useful in
    /// batch opening.
    /// The returned value is the scalar in `[E]1` described in Sec 8.4, step 11 of https://eprint.iacr.org/2019/953.pdf
    pub(crate) fn aggregate_evaluations(
        lin_poly_constant: &E::Fr,
        poly_evals_vec: &[ProofEvaluations<E::Fr>],
        // plookup_proofs_vec: &[Option<PlookupProof<E>>],
        buffer_v_and_uv_basis: &[E::Fr],
    ) -> Result<E::Fr, PlonkError> {
        let mut result: E::Fr = lin_poly_constant.neg();
        let mut v_and_uv_basis = buffer_v_and_uv_basis.iter();

        for poly_evals in poly_evals_vec.iter() {
            // evaluations at point `zeta`
            for &wire_eval in poly_evals.wires_evals.iter() {
                Self::add_pcs_eval(
                    &mut result,
                    v_and_uv_basis
                        .next()
                        .ok_or(PlonkError::IteratorOutOfRange)?,
                    wire_eval,
                );
            }
            for &sigma_eval in poly_evals.wire_sigma_evals.iter() {
                Self::add_pcs_eval(
                    &mut result,
                    v_and_uv_basis
                        .next()
                        .ok_or(PlonkError::IteratorOutOfRange)?,
                    sigma_eval,
                );
            }
            // evaluations at point `zeta * g`
            Self::add_pcs_eval(
                &mut result,
                v_and_uv_basis
                    .next()
                    .ok_or(PlonkError::IteratorOutOfRange)?,
                poly_evals.perm_next_eval,
            );
        }
        // ensure all the buffer has been consumed
        if v_and_uv_basis.next().is_some() {
            return Err(PlonkError::IteratorOutOfRange);
        }
        Ok(result)
    }
}

/// Private helper methods
impl<E, F, P> Verifier<E>
where
    E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWModelParameters<BaseField = F> + Clone,
{
    /// Merge a polynomial commitment into the aggregated polynomial commitment
    /// (in the ScalarAndBases form), update the random combiner afterward.
    #[inline]
    fn add_poly_comm(
        scalar_and_bases: &mut ScalarsAndBases<E>,
        random_combiner: &mut E::Fr,
        comm: E::G1Affine,
        r: E::Fr,
    ) {
        scalar_and_bases.push(*random_combiner, comm);
        *random_combiner *= r;
    }

    /// Add a polynomial commitment evaluation value to the aggregated
    /// polynomial evaluation, update the random combiner afterward.
    #[inline]
    fn add_pcs_eval(result: &mut E::Fr, random_combiner: &E::Fr, eval: E::Fr) {
        *result += eval * (*random_combiner);
    }

    /// Evaluate vanishing polynomial at point `zeta`
    #[inline]
    fn evaluate_vanishing_poly(&self, zeta: &E::Fr) -> E::Fr {
        self.domain.evaluate_vanishing_polynomial(*zeta)
    }

    /// Evaluate the first lagrange polynomial at point `zeta`
    /// given the vanishing polynomial evaluation `vanish_eval`.
    #[inline]
    fn evaluate_lagrange(&self, zeta: &E::Fr, vanish_eval: &E::Fr) -> E::Fr {
        let divisor = E::Fr::from(self.domain.size() as u32) * (*zeta - E::Fr::one());
        *vanish_eval / divisor
    }

    /// Evaluate public input polynomial at point `z`.
    /// Define the following as
    /// - H: The domain with generator g
    /// - n: The size of the domain H
    /// - Z_H: The vanishing polynomial for H.
    /// - v_i: A sequence of values, where v_i = g^i / n
    ///
    /// We then compute L_{i,H}(z) as `L_{i,H}(z) = Z_H(z) * v_i / (z - g^i)`
    /// The public input polynomial evaluation is:
    ///
    /// \sum_{i=0..l} L_{i,H}(z) * pub_input[i].
    ///
    /// TODO: reuse the lagrange values
    fn evaluate_pi_poly(
        &self,
        pub_input: &[E::Fr],
        z: &E::Fr,
        vanish_eval: &E::Fr,
    ) -> Result<E::Fr, PlonkError> {
        // If z is a root of the vanishing polynomial, directly return zero.
        if vanish_eval.is_zero() {
            return Ok(E::Fr::zero());
        }

        let vanish_eval_div_n = E::Fr::from(self.domain.size() as u32)
            .inverse()
            .ok_or(PlonkError::DivisionError)?
            * (*vanish_eval);
        let mut result = E::Fr::zero();
        for (i, val) in pub_input.iter().take(pub_input.len()).enumerate() {
            let lagrange_i =
                vanish_eval_div_n * self.domain.element(i) / (*z - self.domain.element(i));
            result += lagrange_i * val;
        }
        Ok(result)
    }
}
