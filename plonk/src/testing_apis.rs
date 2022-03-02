// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This file implements various wrappers of internal functions and structs.
//! It exposes those APIs under `test_apis` feature.
//! The functions and structs in this file should not be used for other
//! purposes.

use crate::{
    circuit::customized::ecc::SWToTEConParam,
    errors::PlonkError,
    proof_system::{
        structs::{self, BatchProof, PlookupProof, ProofEvaluations, VerifyingKey},
        verifier,
    },
    transcript::PlonkTranscript,
};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters};
use ark_ff::Field;
use ark_poly::Radix2EvaluationDomain;
use ark_poly_commit::kzg10::Commitment;
use ark_std::{collections::HashMap, vec::Vec};
use jf_rescue::RescueParameter;

/// A wrapper of crate::proof_system::structs::Challenges
#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub struct Challenges<F: Field> {
    pub tau: F,
    pub alpha: F,
    pub beta: F,
    pub gamma: F,
    pub zeta: F,
    pub v: F,
    pub u: F,
}

impl<F: Field> From<structs::Challenges<F>> for Challenges<F> {
    fn from(other: structs::Challenges<F>) -> Self {
        Self {
            tau: other.tau,
            alpha: other.alpha,
            beta: other.beta,
            gamma: other.gamma,
            zeta: other.zeta,
            v: other.v,
            u: other.u,
        }
    }
}

impl<F: Field> From<Challenges<F>> for structs::Challenges<F> {
    fn from(other: Challenges<F>) -> Self {
        Self {
            tau: other.tau,
            alpha: other.alpha,
            beta: other.beta,
            gamma: other.gamma,
            zeta: other.zeta,
            v: other.v,
            u: other.u,
        }
    }
}

/// A wrapper of crate::proof_system::structs::ScalarsAndBases
#[derive(Debug, Clone)]
pub struct ScalarsAndBases<E: PairingEngine> {
    pub base_scalar_map: HashMap<E::G1Affine, E::Fr>,
}

impl<E: PairingEngine> From<structs::ScalarsAndBases<E>> for ScalarsAndBases<E> {
    fn from(other: structs::ScalarsAndBases<E>) -> Self {
        Self {
            base_scalar_map: other.base_scalar_map,
        }
    }
}

impl<E: PairingEngine> From<ScalarsAndBases<E>> for structs::ScalarsAndBases<E> {
    fn from(other: ScalarsAndBases<E>) -> Self {
        Self {
            base_scalar_map: other.base_scalar_map,
        }
    }
}

impl<E: PairingEngine> ScalarsAndBases<E> {
    /// Compute the multi-scalar multiplication.
    pub fn multi_scalar_mul(&self) -> E::G1Projective {
        let tmp: structs::ScalarsAndBases<E> = self.clone().into();
        tmp.multi_scalar_mul()
    }
}

/// A wrapper of crate::proof_system::verifier::PcsInfo
#[derive(Debug, Clone)]
pub struct PcsInfo<E: PairingEngine> {
    /// TODO: change back these visibilities
    pub u: E::Fr,
    ///
    pub eval_point: E::Fr,
    ///
    pub next_eval_point: E::Fr,
    ///
    pub eval: E::Fr,
    ///
    pub comm_scalars_and_bases: ScalarsAndBases<E>,
    ///
    pub opening_proof: Commitment<E>,
    ///
    pub shifted_opening_proof: Commitment<E>,
}

impl<E: PairingEngine> From<PcsInfo<E>> for verifier::PcsInfo<E> {
    fn from(other: PcsInfo<E>) -> Self {
        Self {
            u: other.u,
            eval_point: other.eval_point,
            next_eval_point: other.next_eval_point,
            eval: other.eval,
            comm_scalars_and_bases: other.comm_scalars_and_bases.into(),
            opening_proof: other.opening_proof,
            shifted_opening_proof: other.shifted_opening_proof,
        }
    }
}

impl<E: PairingEngine> From<verifier::PcsInfo<E>> for PcsInfo<E> {
    fn from(other: verifier::PcsInfo<E>) -> Self {
        Self {
            u: other.u,
            eval_point: other.eval_point,
            next_eval_point: other.next_eval_point,
            eval: other.eval,
            comm_scalars_and_bases: other.comm_scalars_and_bases.into(),
            opening_proof: other.opening_proof,
            shifted_opening_proof: other.shifted_opening_proof,
        }
    }
}

/// A wrapper of crate::proof_system::verifier::Verifier
#[derive(Debug, Clone)]
pub struct Verifier<E: PairingEngine> {
    pub(crate) domain: Radix2EvaluationDomain<E::Fr>,
}

impl<E: PairingEngine> From<Verifier<E>> for verifier::Verifier<E> {
    fn from(other: Verifier<E>) -> Self {
        Self {
            domain: other.domain,
        }
    }
}

impl<E: PairingEngine> From<verifier::Verifier<E>> for Verifier<E> {
    fn from(other: verifier::Verifier<E>) -> Self {
        Self {
            domain: other.domain,
        }
    }
}

impl<E, F, P> Verifier<E>
where
    E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWModelParameters<BaseField = F> + Clone,
{
    /// Construct a Plonk verifier that uses a domain with size `domain_size`.
    pub fn new(domain_size: usize) -> Result<Self, PlonkError> {
        Ok(verifier::Verifier::new(domain_size)?.into())
    }
    /// Prepare the (aggregated) polynomial commitment evaluation information.
    pub fn prepare_pcs_info<T>(
        &self,
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        batch_proof: &BatchProof<E>,
        extra_transcript_init_msg: &Option<Vec<u8>>,
    ) -> Result<PcsInfo<E>, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        let tmp: verifier::Verifier<E> = (*self).clone().into();
        Ok(tmp
            .prepare_pcs_info::<T>(
                verify_keys,
                public_inputs,
                batch_proof,
                extra_transcript_init_msg,
            )?
            .into())
    }

    /// Compute verifier challenges `tau`, `beta`, `gamma`, `alpha`, `zeta`,
    /// 'v', 'u'.
    #[inline]
    pub fn compute_challenges<T>(
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        batch_proof: &BatchProof<E>,
        extra_transcript_init_msg: &Option<Vec<u8>>,
    ) -> Result<Challenges<E::Fr>, PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        Ok(verifier::Verifier::compute_challenges::<T>(
            verify_keys,
            public_inputs,
            batch_proof,
            extra_transcript_init_msg,
        )?
        .into())
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
    pub fn compute_lin_poly_constant_term(
        &self,
        challenges: &Challenges<E::Fr>,
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        batch_proof: &BatchProof<E>,
        vanish_eval: &E::Fr,
        lagrange_1_eval: &E::Fr,
        lagrange_n_eval: &E::Fr,
        alpha_powers: &[E::Fr],
        alpha_bases: &[E::Fr],
    ) -> Result<E::Fr, PlonkError> {
        let tmp: verifier::Verifier<E> = (*self).clone().into();
        let challenges: structs::Challenges<E::Fr> = (*challenges).into();
        Ok(tmp
            .compute_lin_poly_constant_term(
                &challenges,
                verify_keys,
                public_inputs,
                batch_proof,
                vanish_eval,
                lagrange_1_eval,
                lagrange_n_eval,
                alpha_powers,
                alpha_bases,
            )?
            .into())
    }

    /// Aggregate polynomial commitments into a single commitment (in the
    /// ScalarsAndBases form). Useful in batch opening.
    /// The verification key type is guaranteed to match the Plonk proof type.
    /// The returned commitment is a generalization of `[F]1` described in Sec 8.4, step 10 of https://eprint.iacr.org/2019/953.pdf
    #[allow(clippy::too_many_arguments)]
    pub fn aggregate_poly_commitments(
        &self,
        vks: &[&VerifyingKey<E>],
        challenges: &Challenges<E::Fr>,
        vanish_eval: &E::Fr,
        lagrange_1_eval: &E::Fr,
        lagrange_n_eval: &E::Fr,
        batch_proof: &BatchProof<E>,
        alpha_powers: &[E::Fr],
        alpha_bases: &[E::Fr],
    ) -> Result<(ScalarsAndBases<E>, Vec<E::Fr>), PlonkError> {
        let tmp: verifier::Verifier<E> = (*self).clone().into();
        let challenges: structs::Challenges<E::Fr> = (*challenges).into();
        let res = tmp.aggregate_poly_commitments(
            vks,
            &challenges,
            vanish_eval,
            lagrange_1_eval,
            lagrange_n_eval,
            batch_proof,
            alpha_powers,
            alpha_bases,
        )?;
        Ok((res.0.into(), res.1))
    }

    /// Compute the bases and scalars in the batched polynomial commitment,
    /// which is a generalization of `[D]1` specified in Sec 8.3, Verifier
    /// algorithm step 9 of https://eprint.iacr.org/2019/953.pdf.
    #[allow(clippy::too_many_arguments)]
    pub fn linearization_scalars_and_bases(
        &self,
        vks: &[&VerifyingKey<E>],
        challenges: &Challenges<E::Fr>,
        vanish_eval: &E::Fr,
        lagrange_1_eval: &E::Fr,
        lagrange_n_eval: &E::Fr,
        batch_proof: &BatchProof<E>,
        alpha_powers: &[E::Fr],
        alpha_bases: &[E::Fr],
    ) -> Result<ScalarsAndBases<E>, PlonkError> {
        let tmp: verifier::Verifier<E> = (*self).clone().into();
        let challenges: structs::Challenges<E::Fr> = (*challenges).into();
        Ok(tmp
            .linearization_scalars_and_bases(
                vks,
                &challenges,
                vanish_eval,
                lagrange_1_eval,
                lagrange_n_eval,
                batch_proof,
                alpha_powers,
                alpha_bases,
            )?
            .into())
    }

    /// Combine the polynomial evaluations into a single evaluation. Useful in
    /// batch opening.
    /// The returned value is the scalar in `[E]1` described in Sec 8.4, step 11 of https://eprint.iacr.org/2019/953.pdf
    pub fn aggregate_evaluations(
        lin_poly_constant: &E::Fr,
        poly_evals_vec: &[ProofEvaluations<E::Fr>],
        plookup_proofs_vec: &[Option<PlookupProof<E>>],
        buffer_v_and_uv_basis: &[E::Fr],
    ) -> Result<E::Fr, PlonkError> {
        verifier::Verifier::<E>::aggregate_evaluations(
            lin_poly_constant,
            poly_evals_vec,
            plookup_proofs_vec,
            buffer_v_and_uv_basis,
        )
    }
}
