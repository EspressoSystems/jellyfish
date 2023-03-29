// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Data structures used in Plonk proof systems
use crate::{
    circuit::plonk_verifier::{BatchProofVar, ProofEvaluationsVar},
    errors::{
        PlonkError,
        SnarkError::{self, ParameterError, SnarkLookupUnsupported},
    },
};
use ark_ec::{
    pairing::Pairing,
    scalar_mul::variable_base::VariableBaseMSM,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{FftField, Field, Fp2, Fp2Config, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::*;
use ark_std::{
    convert::{TryFrom, TryInto},
    format,
    string::ToString,
    vec,
    vec::Vec,
};
use espresso_systems_common::jellyfish::tag;
use hashbrown::HashMap;
use jf_primitives::{
    pcs::prelude::{
        Commitment, UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam,
    },
    rescue::RescueParameter,
};
use jf_relation::{
    constants::{compute_coset_representatives, GATE_WIDTH, N_TURBO_PLONK_SELECTORS},
    gadgets::{
        ecc::{Point, SWToTEConParam},
        ultraplonk::mod_arith::FpElemVar,
    },
    PlonkCircuit,
};
use jf_utils::{field_switching, fq_to_fr, fr_to_fq};
use tagged_base64::tagged;

/// Universal StructuredReferenceString
pub type UniversalSrs<E> = UnivariateUniversalParams<E>;
/// Commitment key
pub type CommitKey<E> = UnivariateProverParam<<E as Pairing>::G1Affine>;
/// Key for verifying PCS opening proof.
pub type OpenKey<E> = UnivariateVerifierParam<E>;

/// A Plonk SNARK proof.
#[tagged(tag::PROOF)]
#[derive(Debug, Clone, Eq, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "E:Pairing"))]
pub struct Proof<E: Pairing> {
    /// Wire witness polynomials commitments.
    pub(crate) wires_poly_comms: Vec<Commitment<E>>,

    /// The polynomial commitment for the wire permutation argument.
    pub(crate) prod_perm_poly_comm: Commitment<E>,

    /// Splitted quotient polynomial commitments.
    pub(crate) split_quot_poly_comms: Vec<Commitment<E>>,

    /// (Aggregated) proof of evaluations at challenge point `zeta`.
    pub(crate) opening_proof: Commitment<E>,

    /// (Aggregated) proof of evaluation at challenge point `zeta * g` where `g`
    /// is the root of unity.
    pub(crate) shifted_opening_proof: Commitment<E>,

    /// Polynomial evaluations.
    pub(crate) poly_evals: ProofEvaluations<E::ScalarField>,

    /// The partial proof for Plookup argument
    pub(crate) plookup_proof: Option<PlookupProof<E>>,
}

impl<E, P> TryFrom<Vec<E::BaseField>> for Proof<E>
where
    E: Pairing<G1Affine = Affine<P>>,
    P: SWCurveConfig<BaseField = E::BaseField, ScalarField = E::ScalarField>,
{
    type Error = SnarkError;

    fn try_from(value: Vec<E::BaseField>) -> Result<Self, Self::Error> {
        // both wires_poly_comms and split_quot_poly_comms are (GATE_WIDTH +1)
        // // Commitments, each point takes two base fields elements;
        // 3 individual commitment points;
        // (GATE_WIDTH + 1) * 2 scalar fields in poly_evals are  converted to base
        // fields.
        const TURBO_PLONK_LEN: usize = (GATE_WIDTH + 1) * 2 * 2 + 2 * 3 + (GATE_WIDTH + 1) * 2;
        if value.len() == TURBO_PLONK_LEN {
            // NOTE: for convenience, we slightly reordered our fields in Proof.
            let mut ptr = 0;
            let wires_poly_comms: Vec<Commitment<E>> = value[ptr..ptr + (GATE_WIDTH + 1) * 2]
                .chunks_exact(2)
                .map(|chunk| {
                    if chunk.len() == 2 {
                        Commitment(Affine::new(chunk[0], chunk[1]))
                    } else {
                        unreachable!("Internal error");
                    }
                })
                .collect();
            ptr += (GATE_WIDTH + 1) * 2;

            let split_quot_poly_comms = value[ptr..ptr + (GATE_WIDTH + 1) * 2]
                .chunks_exact(2)
                .map(|chunk| {
                    if chunk.len() == 2 {
                        Commitment(Affine::new(chunk[0], chunk[1]))
                    } else {
                        unreachable!("Internal error");
                    }
                })
                .collect();
            ptr += (GATE_WIDTH + 1) * 2;

            let prod_perm_poly_comm = Commitment(Affine::new(value[ptr], value[ptr + 1]));
            ptr += 2;

            let opening_proof = Commitment(Affine::new(value[ptr], value[ptr + 1]));
            ptr += 2;

            let shifted_opening_proof = Commitment(Affine::new(value[ptr], value[ptr + 1]));
            ptr += 2;

            let poly_evals_scalars: Vec<E::ScalarField> = value[ptr..]
                .iter()
                .map(|f| fq_to_fr::<E::BaseField, P>(f))
                .collect();
            let poly_evals = poly_evals_scalars.try_into()?;

            Ok(Self {
                wires_poly_comms,
                prod_perm_poly_comm,
                split_quot_poly_comms,
                opening_proof,
                shifted_opening_proof,
                poly_evals,
                plookup_proof: None,
            })
        } else {
            Err(SnarkError::ParameterError(
                "Wrong number of scalars for proof, only support TurboPlonk for now".to_string(),
            ))
        }
    }
}

// helper function to convert a G1Affine or G2Affine into two base fields
fn group1_to_fields<E, P>(p: Affine<P>) -> Vec<E::BaseField>
where
    E: Pairing<G1Affine = Affine<P>>,
    P: SWCurveConfig<BaseField = E::BaseField>,
{
    // contains x, y, infinity_flag, only need the first 2 field elements
    vec![p.x, p.y]
}

fn group2_to_fields<E, F, P>(p: Affine<P>) -> Vec<E::BaseField>
where
    E: Pairing<G2Affine = Affine<P>>,
    F: Fp2Config<Fp = E::BaseField>,
    P: SWCurveConfig<BaseField = Fp2<F>>,
{
    // contains x, y, infinity_flag, only need the first 2 field elements
    vec![p.x.c0, p.x.c1, p.y.c0, p.y.c1]
}

impl<E, P> From<Proof<E>> for Vec<E::BaseField>
where
    E: Pairing<G1Affine = Affine<P>>,
    P: SWCurveConfig<BaseField = E::BaseField, ScalarField = E::ScalarField>,
{
    fn from(proof: Proof<E>) -> Self {
        if proof.plookup_proof.is_some() {
            panic!("Only support TurboPlonk for now.");
        }
        let poly_evals_scalars: Vec<E::ScalarField> = proof.poly_evals.into();

        // NOTE: order of these fields must match deserialization
        [
            proof
                .wires_poly_comms
                .iter()
                .map(|cm| group1_to_fields::<E, _>(cm.0))
                .collect::<Vec<_>>()
                .concat(),
            proof
                .split_quot_poly_comms
                .iter()
                .map(|cm| group1_to_fields::<E, _>(cm.0))
                .collect::<Vec<_>>()
                .concat(),
            group1_to_fields::<E, _>(proof.prod_perm_poly_comm.0),
            group1_to_fields::<E, _>(proof.opening_proof.0),
            group1_to_fields::<E, _>(proof.shifted_opening_proof.0),
            poly_evals_scalars
                .iter()
                .map(|s| fr_to_fq::<E::BaseField, P>(s))
                .collect::<Vec<_>>(),
        ]
        .concat()
    }
}

/// A Plookup argument proof.
#[derive(Debug, Clone, Eq, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "E:Pairing"))]
pub struct PlookupProof<E: Pairing> {
    /// The commitments for the polynomials that interpolate the sorted
    /// concatenation of the lookup table and the witnesses in the lookup gates.
    pub(crate) h_poly_comms: Vec<Commitment<E>>,

    /// The product accumulation polynomial commitment for the Plookup argument
    pub(crate) prod_lookup_poly_comm: Commitment<E>,

    /// Polynomial evaluations.
    pub(crate) poly_evals: PlookupEvaluations<E::ScalarField>,
}

/// An aggregated SNARK proof that batchly proving multiple instances.
#[tagged(tag::BATCHPROOF)]
#[derive(Debug, Clone, Eq, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(PartialEq, Hash(bound = "E:Pairing"))]
pub struct BatchProof<E: Pairing> {
    /// The list of wire witness polynomials commitments.
    pub(crate) wires_poly_comms_vec: Vec<Vec<Commitment<E>>>,

    /// The list of polynomial commitment for the wire permutation argument.
    pub(crate) prod_perm_poly_comms_vec: Vec<Commitment<E>>,

    /// The list of polynomial evaluations.
    pub(crate) poly_evals_vec: Vec<ProofEvaluations<E::ScalarField>>,

    /// The list of partial proofs for Plookup argument
    pub(crate) plookup_proofs_vec: Vec<Option<PlookupProof<E>>>,

    /// Splitted quotient polynomial commitments.
    pub(crate) split_quot_poly_comms: Vec<Commitment<E>>,

    /// (Aggregated) proof of evaluations at challenge point `zeta`.
    pub(crate) opening_proof: Commitment<E>,

    /// (Aggregated) proof of evaluation at challenge point `zeta * g` where `g`
    /// is the root of unity.
    pub(crate) shifted_opening_proof: Commitment<E>,
}

impl<E: Pairing> BatchProof<E> {
    /// The number of instances being proved in a batch proof.
    pub fn len(&self) -> usize {
        self.prod_perm_poly_comms_vec.len()
    }
    /// Check whether a BatchProof proves nothing.
    pub fn is_empty(&self) -> bool {
        self.prod_perm_poly_comms_vec.is_empty()
    }
    /// Create a dummy batch proof over `n` TurboPlonk instances.
    pub fn dummy(n: usize) -> Self {
        let num_wire_types = GATE_WIDTH + 1;
        Self {
            wires_poly_comms_vec: vec![vec![Commitment::default(); num_wire_types]; n],
            prod_perm_poly_comms_vec: vec![Commitment::default(); n],
            poly_evals_vec: vec![ProofEvaluations::default(); n],
            plookup_proofs_vec: vec![None; n],
            split_quot_poly_comms: vec![Commitment::default(); num_wire_types],
            opening_proof: Commitment::default(),
            shifted_opening_proof: Commitment::default(),
        }
    }
}

impl<E: Pairing> From<Proof<E>> for BatchProof<E> {
    fn from(proof: Proof<E>) -> Self {
        Self {
            wires_poly_comms_vec: vec![proof.wires_poly_comms],
            prod_perm_poly_comms_vec: vec![proof.prod_perm_poly_comm],
            poly_evals_vec: vec![proof.poly_evals],
            plookup_proofs_vec: vec![proof.plookup_proof],
            split_quot_poly_comms: proof.split_quot_poly_comms,
            opening_proof: proof.opening_proof,
            shifted_opening_proof: proof.shifted_opening_proof,
        }
    }
}

impl<T: PrimeField> ProofEvaluations<T> {
    /// create variables for the ProofEvaluations who's field
    /// is smaller than plonk circuit field.
    /// The output wires are in the FpElemVar form.

    pub(crate) fn create_variables<F>(
        &self,
        circuit: &mut PlonkCircuit<F>,
        m: usize,
        two_power_m: Option<F>,
    ) -> Result<ProofEvaluationsVar<F>, PlonkError>
    where
        F: RescueParameter + SWToTEConParam,
    {
        if T::MODULUS_BIT_SIZE >= F::MODULUS_BIT_SIZE {
            return Err(PlonkError::InvalidParameters(format!(
                "circuit field size {} is not greater than Plookup Evaluation field size {}",
                F::MODULUS_BIT_SIZE,
                T::MODULUS_BIT_SIZE
            )));
        }
        let wires_evals = self
            .wires_evals
            .iter()
            .map(|x| {
                FpElemVar::new_from_field_element(circuit, &field_switching(x), m, two_power_m)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let wire_sigma_evals = self
            .wire_sigma_evals
            .iter()
            .map(|x| {
                FpElemVar::new_from_field_element(circuit, &field_switching(x), m, two_power_m)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProofEvaluationsVar {
            wires_evals,
            wire_sigma_evals,
            perm_next_eval: FpElemVar::new_from_field_element(
                circuit,
                &field_switching(&self.perm_next_eval),
                m,
                two_power_m,
            )?,
        })
    }
}

impl<E: Pairing> BatchProof<E> {
    /// Create a `BatchProofVar` variable from a `BatchProof`.
    pub fn create_variables<F, P>(
        &self,
        circuit: &mut PlonkCircuit<F>,
        m: usize,
        two_power_m: Option<F>,
    ) -> Result<BatchProofVar<F>, PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F>,
    {
        let mut wires_poly_comms_vec = Vec::new();
        for e in self.wires_poly_comms_vec.iter() {
            let mut tmp = Vec::new();
            for f in e.iter() {
                let p: Point<F> = (&f.0).into();
                tmp.push(circuit.create_point_variable(p)?);
            }
            wires_poly_comms_vec.push(tmp);
        }
        let mut prod_perm_poly_comms_vec = Vec::new();
        for e in self.prod_perm_poly_comms_vec.iter() {
            let p: Point<F> = (&e.0).into();
            prod_perm_poly_comms_vec.push(circuit.create_point_variable(p)?);
        }

        let poly_evals_vec = self
            .poly_evals_vec
            .iter()
            .map(|x| x.create_variables(circuit, m, two_power_m))
            .collect::<Result<Vec<_>, _>>()?;

        let mut split_quot_poly_comms = Vec::new();
        for e in self.split_quot_poly_comms.iter() {
            let p: Point<F> = (&e.0).into();
            split_quot_poly_comms.push(circuit.create_point_variable(p)?);
        }

        let p: Point<F> = (&self.opening_proof.0).into();
        let opening_proof = circuit.create_point_variable(p)?;

        let p: Point<F> = (&self.shifted_opening_proof.0).into();
        let shifted_opening_proof = circuit.create_point_variable(p)?;

        Ok(BatchProofVar {
            wires_poly_comms_vec,
            prod_perm_poly_comms_vec,
            poly_evals_vec,
            split_quot_poly_comms,
            opening_proof,
            shifted_opening_proof,
        })
    }
}

/// A struct that stores the polynomial evaluations in a Plonk proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofEvaluations<F: Field> {
    /// Wire witness polynomials evaluations at point `zeta`.
    pub(crate) wires_evals: Vec<F>,

    /// Extended permutation (sigma) polynomials evaluations at point `zeta`.
    /// We do not include the last sigma polynomial evaluation.
    pub(crate) wire_sigma_evals: Vec<F>,

    /// Permutation product polynomial evaluation at point `zeta * g`.
    pub(crate) perm_next_eval: F,
}

impl<F: Field> TryFrom<Vec<F>> for ProofEvaluations<F> {
    type Error = SnarkError;

    fn try_from(value: Vec<F>) -> Result<Self, Self::Error> {
        // | wires_evals | = | wire_sigma_evals | + 1
        // = GATE_WIDTH + 1 + 0/1 (0 for TurboPlonk and 1 for UltraPlonk)
        // thanks to Maller optimization.
        const TURBO_PLONK_EVAL_LEN: usize = (GATE_WIDTH + 1) * 2;
        const ULTRA_PLONK_EVAL_LEN: usize = (GATE_WIDTH + 2) * 2;

        if value.len() == TURBO_PLONK_EVAL_LEN || value.len() == ULTRA_PLONK_EVAL_LEN {
            let l = value.len();
            let wires_evals = value[..l / 2].to_vec();
            let wire_sigma_evals = value[l / 2..l - 1].to_vec();
            let perm_next_eval = value[l - 1];
            Ok(Self {
                wires_evals,
                wire_sigma_evals,
                perm_next_eval,
            })
        } else {
            Err(SnarkError::ParameterError(
                "Wrong number of scalars for proof evals.".to_string(),
            ))
        }
    }
}

impl<F: Field> From<ProofEvaluations<F>> for Vec<F> {
    fn from(evals: ProofEvaluations<F>) -> Self {
        [
            evals.wires_evals,
            evals.wire_sigma_evals,
            vec![evals.perm_next_eval],
        ]
        .concat()
    }
}

impl<F> Default for ProofEvaluations<F>
where
    F: Field,
{
    fn default() -> Self {
        let num_wire_types = GATE_WIDTH + 1;
        Self {
            wires_evals: vec![F::zero(); num_wire_types],
            wire_sigma_evals: vec![F::zero(); num_wire_types - 1],
            perm_next_eval: F::zero(),
        }
    }
}

/// A struct that stores the polynomial evaluations in a Plookup argument proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlookupEvaluations<F: Field> {
    /// Range table polynomial evaluation at point `zeta`.
    pub(crate) range_table_eval: F,

    /// Key table polynomial evaluation at point `zeta`.
    pub(crate) key_table_eval: F,

    /// Table domain separation polynomial evaluation at point `zeta`.
    pub(crate) table_dom_sep_eval: F,

    /// Domain separation selector polynomial evaluation at point `zeta`.
    pub(crate) q_dom_sep_eval: F,

    /// The first sorted vector polynomial evaluation at point `zeta`.
    pub(crate) h_1_eval: F,

    /// The lookup selector polynomial evaluation at point `zeta`.
    pub(crate) q_lookup_eval: F,

    /// Lookup product polynomial evaluation at point `zeta * g`.
    pub(crate) prod_next_eval: F,

    /// Range table polynomial evaluation at point `zeta * g`.
    pub(crate) range_table_next_eval: F,

    /// Key table polynomial evaluation at point `zeta * g`.
    pub(crate) key_table_next_eval: F,

    /// Table domain separation polynomial evaluation at point `zeta * g`.
    pub(crate) table_dom_sep_next_eval: F,

    /// The first sorted vector polynomial evaluation at point `zeta * g`.
    pub(crate) h_1_next_eval: F,

    /// The second sorted vector polynomial evaluation at point `zeta * g`.
    pub(crate) h_2_next_eval: F,

    /// The lookup selector polynomial evaluation at point `zeta * g`.
    pub(crate) q_lookup_next_eval: F,

    /// The 4th witness polynomial evaluation at point `zeta * g`.
    pub(crate) w_3_next_eval: F,

    /// The 5th witness polynomial evaluation at point `zeta * g`.
    pub(crate) w_4_next_eval: F,
}

impl<F: Field> PlookupEvaluations<F> {
    /// Return the list of evaluations at point `zeta`.
    pub(crate) fn evals_vec(&self) -> Vec<F> {
        vec![
            self.range_table_eval,
            self.key_table_eval,
            self.h_1_eval,
            self.q_lookup_eval,
            self.table_dom_sep_eval,
            self.q_dom_sep_eval,
        ]
    }

    /// Return the list of evaluations at point `zeta * g`.
    pub(crate) fn next_evals_vec(&self) -> Vec<F> {
        vec![
            self.prod_next_eval,
            self.range_table_next_eval,
            self.key_table_next_eval,
            self.h_1_next_eval,
            self.h_2_next_eval,
            self.q_lookup_next_eval,
            self.w_3_next_eval,
            self.w_4_next_eval,
            self.table_dom_sep_next_eval,
        ]
    }
}

/// Preprocessed prover parameters used to compute Plonk proofs for a certain
/// circuit.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// Extended permutation (sigma) polynomials.
    pub(crate) sigmas: Vec<DensePolynomial<E::ScalarField>>,

    /// Selector polynomials.
    pub(crate) selectors: Vec<DensePolynomial<E::ScalarField>>,

    // KZG PCS committing key.
    pub(crate) commit_key: CommitKey<E>,

    /// The verifying key. It is used by prover to initialize transcripts.
    pub vk: VerifyingKey<E>,

    /// Proving key for Plookup, None if not support lookup.
    pub(crate) plookup_pk: Option<PlookupProvingKey<E>>,
}

/// Preprocessed prover parameters used to compute Plookup proofs for a certain
/// circuit.
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlookupProvingKey<E: Pairing> {
    /// Range table polynomial.
    pub(crate) range_table_poly: DensePolynomial<E::ScalarField>,

    /// Key table polynomial.
    pub(crate) key_table_poly: DensePolynomial<E::ScalarField>,

    /// Table domain separation polynomial.
    pub(crate) table_dom_sep_poly: DensePolynomial<E::ScalarField>,

    /// Lookup domain separation selector polynomial.
    pub(crate) q_dom_sep_poly: DensePolynomial<E::ScalarField>,
}

impl<E: Pairing> ProvingKey<E> {
    /// The size of the evaluation domain. Should be a power of two.
    pub(crate) fn domain_size(&self) -> usize {
        self.vk.domain_size
    }
    /// The number of public inputs.
    #[allow(dead_code)]
    pub(crate) fn num_inputs(&self) -> usize {
        self.vk.num_inputs
    }
    /// The constants K0, ..., K4 that ensure wire subsets are disjoint.
    pub(crate) fn k(&self) -> &[E::ScalarField] {
        &self.vk.k
    }

    /// The lookup selector polynomial
    pub(crate) fn q_lookup_poly(&self) -> Result<&DensePolynomial<E::ScalarField>, PlonkError> {
        if self.plookup_pk.is_none() {
            return Err(SnarkLookupUnsupported.into());
        }
        Ok(self.selectors.last().unwrap())
    }

    /// Merge with another TurboPlonk proving key to obtain a new TurboPlonk
    /// proving key. Return error if any of the following holds:
    /// 1. the other proving key has a different domain size;
    /// 2. the circuit underlying the other key has different number of inputs;
    /// 3. the key or the other key is not a TurboPlonk key.
    #[allow(dead_code)]
    pub(crate) fn merge(&self, other_pk: &Self) -> Result<Self, PlonkError> {
        if self.domain_size() != other_pk.domain_size() {
            return Err(ParameterError(format!(
                "mismatched domain size ({} vs {}) when merging proving keys",
                self.domain_size(),
                other_pk.domain_size()
            ))
            .into());
        }
        if self.num_inputs() != other_pk.num_inputs() {
            return Err(ParameterError(
                "mismatched number of public inputs when merging proving keys".to_string(),
            )
            .into());
        }
        if self.plookup_pk.is_some() || other_pk.plookup_pk.is_some() {
            return Err(ParameterError("cannot merge UltraPlonk proving keys".to_string()).into());
        }
        let sigmas: Vec<DensePolynomial<E::ScalarField>> = self
            .sigmas
            .iter()
            .zip(other_pk.sigmas.iter())
            .map(|(poly1, poly2)| poly1 + poly2)
            .collect();
        let selectors: Vec<DensePolynomial<E::ScalarField>> = self
            .selectors
            .iter()
            .zip(other_pk.selectors.iter())
            .map(|(poly1, poly2)| poly1 + poly2)
            .collect();

        Ok(Self {
            sigmas,
            selectors,
            commit_key: self.commit_key.clone(),
            vk: self.vk.merge(&other_pk.vk)?,
            plookup_pk: None,
        })
    }
}

/// Preprocessed verifier parameters used to verify Plonk proofs for a certain
/// circuit.
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The size of the evaluation domain. Should be a power of two.
    pub(crate) domain_size: usize,

    /// The number of public inputs.
    pub(crate) num_inputs: usize,

    /// The permutation polynomial commitments. The commitments are not hiding.
    pub(crate) sigma_comms: Vec<Commitment<E>>,

    /// The selector polynomial commitments. The commitments are not hiding.
    pub(crate) selector_comms: Vec<Commitment<E>>,

    /// The constants K0, ..., K_num_wire_types that ensure wire subsets are
    /// disjoint.
    pub(crate) k: Vec<E::ScalarField>,

    /// KZG PCS opening key.
    pub open_key: OpenKey<E>,

    /// A flag indicating whether the key is a merged key.
    pub(crate) is_merged: bool,

    /// Plookup verifying key, None if not support lookup.
    pub(crate) plookup_vk: Option<PlookupVerifyingKey<E>>,
}

impl<E, F, P1, P2> From<VerifyingKey<E>> for Vec<E::BaseField>
where
    E: Pairing<G1Affine = Affine<P1>, G2Affine = Affine<P2>, TargetField = Fp2<F>>,
    F: Fp2Config<Fp = E::BaseField>,
    P1: SWCurveConfig<BaseField = E::BaseField, ScalarField = E::ScalarField>,
    P2: SWCurveConfig<BaseField = E::TargetField, ScalarField = E::ScalarField>,
{
    fn from(vk: VerifyingKey<E>) -> Self {
        if vk.plookup_vk.is_some() {
            panic!("Only support TurboPlonk VerifyingKey for now.");
        }

        [
            vec![E::BaseField::from(vk.domain_size as u64)],
            vec![E::BaseField::from(vk.num_inputs as u64)],
            vk.sigma_comms
                .iter()
                .map(|cm| group1_to_fields::<E, _>(cm.0))
                .collect::<Vec<_>>()
                .concat(),
            vk.selector_comms
                .iter()
                .map(|cm| group1_to_fields::<E, _>(cm.0))
                .collect::<Vec<_>>()
                .concat(),
            vk.k.iter()
                .map(|fr| fr_to_fq::<E::BaseField, P1>(fr))
                .collect(),
            // NOTE: only adding g, h, beta_h since only these are used.
            group1_to_fields::<E, P1>(vk.open_key.g),
            group2_to_fields::<E, F, P2>(vk.open_key.h),
            group2_to_fields::<E, F, P2>(vk.open_key.beta_h),
        ]
        .concat()
    }
}

impl<E, F, P> VerifyingKey<E>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
{
    /// Convert the group elements to a list of scalars that represent the
    /// Twisted Edwards coordinates.
    pub fn convert_te_coordinates_to_scalars(&self) -> Vec<F> {
        let mut res = vec![];
        for sigma_comm in self.sigma_comms.iter() {
            let point: Point<F> = (&sigma_comm.0).into();
            res.push(point.get_x());
            res.push(point.get_y());
        }
        for selector_comm in self.selector_comms.iter() {
            let point: Point<F> = (&selector_comm.0).into();
            res.push(point.get_x());
            res.push(point.get_y());
        }
        res
    }
}

/// Preprocessed verifier parameters used to verify Plookup proofs for a certain
/// circuit.
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlookupVerifyingKey<E: Pairing> {
    /// Range table polynomial commitment. The commitment is not hiding.
    pub(crate) range_table_comm: Commitment<E>,

    /// Key table polynomial commitment. The commitment is not hiding.
    pub(crate) key_table_comm: Commitment<E>,

    /// Table domain separation polynomial commitment. The commitment is not
    /// hiding.
    pub(crate) table_dom_sep_comm: Commitment<E>,

    /// Lookup domain separation selector polynomial commitment. The commitment
    /// is not hiding.
    pub(crate) q_dom_sep_comm: Commitment<E>,
}

impl<E: Pairing> VerifyingKey<E> {
    /// Create a dummy TurboPlonk verification key for a circuit with
    /// `num_inputs` public inputs and domain size `domain_size`.
    pub fn dummy(num_inputs: usize, domain_size: usize) -> Self {
        let num_wire_types = GATE_WIDTH + 1;
        Self {
            domain_size,
            num_inputs,
            sigma_comms: vec![Commitment::default(); num_wire_types],
            selector_comms: vec![Commitment::default(); N_TURBO_PLONK_SELECTORS],
            k: compute_coset_representatives(num_wire_types, Some(domain_size)),
            open_key: OpenKey::default(),
            is_merged: false,
            plookup_vk: None,
        }
    }
    /// Merge with another TurboPlonk verifying key to obtain a new TurboPlonk
    /// verifying key. Return error if any of the following holds:
    /// 1. the other verifying key has a different domain size;
    /// 2. the circuit underlying the other key has different number of inputs.
    /// 3. the key or the other key is not a TurboPlonk key.
    pub(crate) fn merge(&self, other_vk: &Self) -> Result<Self, PlonkError> {
        if self.is_merged || other_vk.is_merged {
            return Err(ParameterError("cannot merge a merged key again".to_string()).into());
        }
        if self.domain_size != other_vk.domain_size {
            return Err(ParameterError(
                "mismatched domain size when merging verifying keys".to_string(),
            )
            .into());
        }
        if self.num_inputs != other_vk.num_inputs {
            return Err(ParameterError(
                "mismatched number of public inputs when merging verifying keys".to_string(),
            )
            .into());
        }
        if self.plookup_vk.is_some() || other_vk.plookup_vk.is_some() {
            return Err(
                ParameterError("cannot merge UltraPlonk verifying keys".to_string()).into(),
            );
        }
        let sigma_comms: Vec<Commitment<E>> = self
            .sigma_comms
            .iter()
            .zip(other_vk.sigma_comms.iter())
            .map(|(com1, com2)| Commitment((com1.0 + com2.0).into_affine()))
            .collect();
        let selector_comms: Vec<Commitment<E>> = self
            .selector_comms
            .iter()
            .zip(other_vk.selector_comms.iter())
            .map(|(com1, com2)| Commitment((com1.0 + com2.0).into_affine()))
            .collect();

        Ok(Self {
            domain_size: self.domain_size,
            num_inputs: self.num_inputs + other_vk.num_inputs,
            sigma_comms,
            selector_comms,
            k: self.k.clone(),
            open_key: self.open_key,
            plookup_vk: None,
            is_merged: true,
        })
    }

    /// The lookup selector polynomial commitment
    pub(crate) fn q_lookup_comm(&self) -> Result<&Commitment<E>, PlonkError> {
        if self.plookup_vk.is_none() {
            return Err(SnarkLookupUnsupported.into());
        }
        Ok(self.selector_comms.last().unwrap())
    }
}

/// Plonk IOP verifier challenges.
#[derive(Debug, Default)]
pub(crate) struct Challenges<F: Field> {
    pub(crate) tau: F,
    pub(crate) alpha: F,
    pub(crate) beta: F,
    pub(crate) gamma: F,
    pub(crate) zeta: F,
    pub(crate) v: F,
    pub(crate) u: F,
}

/// Plonk IOP online polynomial oracles.
#[derive(Debug, Default, Clone)]
pub(crate) struct Oracles<F: FftField> {
    pub(crate) wire_polys: Vec<DensePolynomial<F>>,
    pub(crate) pub_inp_poly: DensePolynomial<F>,
    pub(crate) prod_perm_poly: DensePolynomial<F>,
    pub(crate) plookup_oracles: PlookupOracles<F>,
}

/// Plookup IOP online polynomial oracles.
#[derive(Debug, Default, Clone)]
pub(crate) struct PlookupOracles<F: FftField> {
    pub(crate) h_polys: Vec<DensePolynomial<F>>,
    pub(crate) prod_lookup_poly: DensePolynomial<F>,
}

/// The vector representation of bases and corresponding scalars.
#[derive(Debug)]
pub(crate) struct ScalarsAndBases<E: Pairing> {
    pub(crate) base_scalar_map: HashMap<E::G1Affine, E::ScalarField>,
}

impl<E: Pairing> ScalarsAndBases<E> {
    pub(crate) fn new() -> Self {
        Self {
            base_scalar_map: HashMap::new(),
        }
    }
    /// Insert a base point and the corresponding scalar.
    pub(crate) fn push(&mut self, scalar: E::ScalarField, base: E::G1Affine) {
        let entry_scalar = self
            .base_scalar_map
            .entry(base)
            .or_insert_with(E::ScalarField::zero);
        *entry_scalar += scalar;
    }

    /// Add a list of scalars and bases into self, where each scalar is
    /// multiplied by a constant c.
    pub(crate) fn merge(&mut self, c: E::ScalarField, scalars_and_bases: &Self) {
        for (base, scalar) in &scalars_and_bases.base_scalar_map {
            self.push(c * scalar, *base);
        }
    }
    /// Compute the multi-scalar multiplication.
    pub(crate) fn multi_scalar_mul(&self) -> E::G1 {
        let mut bases = vec![];
        let mut scalars = vec![];
        for (base, scalar) in &self.base_scalar_map {
            bases.push(*base);
            scalars.push(scalar.into_bigint());
        }
        VariableBaseMSM::msm_bigint(&bases, &scalars)
    }
}

// Utility function for computing merged table evaluations.
#[inline]
pub(crate) fn eval_merged_table<E: Pairing>(
    tau: E::ScalarField,
    range_eval: E::ScalarField,
    key_eval: E::ScalarField,
    q_lookup_eval: E::ScalarField,
    w3_eval: E::ScalarField,
    w4_eval: E::ScalarField,
    table_dom_sep_eval: E::ScalarField,
) -> E::ScalarField {
    range_eval
        + q_lookup_eval
            * tau
            * (table_dom_sep_eval + tau * (key_eval + tau * (w3_eval + tau * w4_eval)))
}

// Utility function for computing merged lookup witness evaluations.
#[inline]
pub(crate) fn eval_merged_lookup_witness<E: Pairing>(
    tau: E::ScalarField,
    w_range_eval: E::ScalarField,
    w_0_eval: E::ScalarField,
    w_1_eval: E::ScalarField,
    w_2_eval: E::ScalarField,
    q_lookup_eval: E::ScalarField,
    q_dom_sep_eval: E::ScalarField,
) -> E::ScalarField {
    w_range_eval
        + q_lookup_eval
            * tau
            * (q_dom_sep_eval + tau * (w_0_eval + tau * (w_1_eval + tau * w_2_eval)))
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{g1::Config, Bn254, Fq};
    use ark_ec::AffineRepr;

    #[test]
    fn test_group_to_field() {
        let g1 = <Bn254 as Pairing>::G1Affine::generator();
        let f1: Vec<Fq> = group1_to_fields::<Bn254, Config>(g1);
        assert_eq!(f1.len(), 2);
        let g2 = <Bn254 as Pairing>::G2Affine::generator();
        let f2: Vec<Fq> = group2_to_fields::<Bn254, _, _>(g2);
        assert_eq!(f2.len(), 4);
    }
}
