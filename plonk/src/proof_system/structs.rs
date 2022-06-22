// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Data structures used in Plonk proof systems
use crate::{
    circuit::customized::ecc::{Point, SWToTEConParam},
    constants::{compute_coset_representatives, GATE_WIDTH, N_TURBO_PLONK_SELECTORS},
    errors::SnarkError,
};
use ark_ec::{
    msm::VariableBaseMSM, short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters,
};
use ark_ff::{FftField, Field, Fp2, Fp2Parameters, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::{Commitment, Powers, UniversalParams, VerifierKey};
use ark_serialize::*;
use ark_std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_utils::{fq_to_fr, fr_to_fq, tagged_blob};

/// Universal Structured Reference String for PlonkKzgSnark
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct UniversalSrs<E: PairingEngine>(pub(crate) UniversalParams<E>);

impl<E: PairingEngine> UniversalSrs<E> {
    /// Expose powers of g via reference.
    pub fn powers_of_g_ref(&self) -> &[E::G1Affine] {
        &self.0.powers_of_g
    }
}

/// Key for committing to and creating evaluation proofs
/// (alias to kzg10::Powers).
pub type CommitKey<'a, E> = Powers<'a, E>;

/// Key for verifying PCS opening proof (alias to kzg10::VerifierKey).
pub type OpenKey<E> = VerifierKey<E>;

/// A Plonk SNARK proof.
#[tagged_blob("PROOF")]
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(Hash(bound = "E:PairingEngine"))]
pub struct Proof<E: PairingEngine> {
    /// Wire witness polynomials commitments.
    pub wires_poly_comms: Vec<Commitment<E>>,

    /// The polynomial commitment for the wire permutation argument.
    pub prod_perm_poly_comm: Commitment<E>,

    /// Splitted quotient polynomial commitments.
    pub split_quot_poly_comms: Vec<Commitment<E>>,

    /// (Aggregated) proof of evaluations at challenge point `zeta`.
    pub opening_proof: Commitment<E>,

    /// (Aggregated) proof of evaluation at challenge point `zeta * g` where `g`
    /// is the root of unity.
    pub shifted_opening_proof: Commitment<E>,

    /// Polynomial evaluations.
    pub poly_evals: ProofEvaluations<E::Fr>,
}

impl<E, P> TryFrom<Vec<E::Fq>> for Proof<E>
where
    E: PairingEngine<G1Affine = GroupAffine<P>>,
    P: SWModelParameters<BaseField = E::Fq, ScalarField = E::Fr> + Clone,
{
    type Error = SnarkError;

    fn try_from(value: Vec<E::Fq>) -> Result<Self, Self::Error> {
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
                        Commitment(GroupAffine::new(chunk[0], chunk[1], false))
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
                        Commitment(GroupAffine::new(chunk[0], chunk[1], false))
                    } else {
                        unreachable!("Internal error");
                    }
                })
                .collect();
            ptr += (GATE_WIDTH + 1) * 2;

            let prod_perm_poly_comm =
                Commitment(GroupAffine::new(value[ptr], value[ptr + 1], false));
            ptr += 2;

            let opening_proof = Commitment(GroupAffine::new(value[ptr], value[ptr + 1], false));
            ptr += 2;

            let shifted_opening_proof =
                Commitment(GroupAffine::new(value[ptr], value[ptr + 1], false));
            ptr += 2;

            let poly_evals_scalars: Vec<E::Fr> = value[ptr..]
                .iter()
                .map(|f| fq_to_fr::<E::Fq, P>(f))
                .collect();
            let poly_evals = poly_evals_scalars.try_into()?;

            Ok(Self {
                wires_poly_comms,
                prod_perm_poly_comm,
                split_quot_poly_comms,
                opening_proof,
                shifted_opening_proof,
                poly_evals,
            })
        } else {
            Err(SnarkError::ParameterError(
                "Wrong number of scalars for proof, only support TurboPlonk for now".to_string(),
            ))
        }
    }
}

// helper function to convert a G1Affine or G2Affine into two base fields
fn group1_to_fields<E, P>(p: GroupAffine<P>) -> Vec<E::Fq>
where
    E: PairingEngine<G1Affine = GroupAffine<P>>,
    P: SWModelParameters<BaseField = E::Fq>,
{
    // contains x, y, infinity_flag, only need the first 2 field elements
    vec![p.x, p.y]
}

fn group2_to_fields<E, F, P>(p: GroupAffine<P>) -> Vec<E::Fq>
where
    E: PairingEngine<G2Affine = GroupAffine<P>, Fqe = Fp2<F>>,
    F: Fp2Parameters<Fp = E::Fq>,
    P: SWModelParameters<BaseField = E::Fqe>,
{
    // contains x, y, infinity_flag, only need the first 2 field elements
    vec![p.x.c0, p.x.c1, p.y.c0, p.y.c1]
}

impl<E, P> From<Proof<E>> for Vec<E::Fq>
where
    E: PairingEngine<G1Affine = GroupAffine<P>>,
    P: SWModelParameters<BaseField = E::Fq, ScalarField = E::Fr> + Clone,
{
    fn from(proof: Proof<E>) -> Self {
        let poly_evals_scalars: Vec<E::Fr> = proof.poly_evals.into();

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
                .map(|s| fr_to_fq::<E::Fq, P>(s))
                .collect::<Vec<_>>(),
        ]
        .concat()
    }
}

/// An aggregated SNARK proof that batchly proving multiple instances.
#[tagged_blob("BATCHPROOF")]
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Derivative)]
#[derivative(Hash(bound = "E:PairingEngine"))]
pub struct BatchProof<E: PairingEngine> {
    /// The list of wire witness polynomials commitments.
    pub(crate) wires_poly_comms_vec: Vec<Vec<Commitment<E>>>,

    /// The list of polynomial commitment for the wire permutation argument.
    pub(crate) prod_perm_poly_comms_vec: Vec<Commitment<E>>,

    /// The list of polynomial evaluations.
    pub(crate) poly_evals_vec: Vec<ProofEvaluations<E::Fr>>,

    /// Splitted quotient polynomial commitments.
    pub(crate) split_quot_poly_comms: Vec<Commitment<E>>,

    /// (Aggregated) proof of evaluations at challenge point `zeta`.
    pub(crate) opening_proof: Commitment<E>,

    /// (Aggregated) proof of evaluation at challenge point `zeta * g` where `g`
    /// is the root of unity.
    pub(crate) shifted_opening_proof: Commitment<E>,
}

impl<E: PairingEngine> BatchProof<E> {
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
            split_quot_poly_comms: vec![Commitment::default(); num_wire_types],
            opening_proof: Commitment::default(),
            shifted_opening_proof: Commitment::default(),
        }
    }
}

impl<E: PairingEngine> From<Proof<E>> for BatchProof<E> {
    fn from(proof: Proof<E>) -> Self {
        Self {
            wires_poly_comms_vec: vec![proof.wires_poly_comms],
            prod_perm_poly_comms_vec: vec![proof.prod_perm_poly_comm],
            poly_evals_vec: vec![proof.poly_evals],
            split_quot_poly_comms: proof.split_quot_poly_comms,
            opening_proof: proof.opening_proof,
            shifted_opening_proof: proof.shifted_opening_proof,
        }
    }
}

/// A struct that stores the polynomial evaluations in a Plonk proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofEvaluations<F: Field> {
    /// Wire witness polynomials evaluations at point `zeta`.
    pub wires_evals: Vec<F>,

    /// Extended permutation (sigma) polynomials evaluations at point `zeta`.
    /// We do not include the last sigma polynomial evaluation.
    pub wire_sigma_evals: Vec<F>,

    /// Permutation product polynomial evaluation at point `zeta * g`.
    pub perm_next_eval: F,
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

/// Preprocessed prover parameters used to compute Plonk proofs for a certain
/// circuit.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<'a, E: PairingEngine> {
    /// Extended permutation (sigma) polynomials.
    pub sigmas: Vec<DensePolynomial<E::Fr>>,

    /// Selector polynomials.
    pub selectors: Vec<DensePolynomial<E::Fr>>,

    /// KZG PCS committing key.
    pub commit_key: CommitKey<'a, E>,

    /// The verifying key. It is used by prover to initialize transcripts.
    pub vk: VerifyingKey<E>,
}

impl<'a, E: PairingEngine> ProvingKey<'a, E> {
    /// The size of the evaluation domain. Should be a power of two.
    pub fn domain_size(&self) -> usize {
        self.vk.domain_size
    }
    /// The number of public inputs.
    #[allow(dead_code)]
    pub fn num_inputs(&self) -> usize {
        self.vk.num_inputs
    }
    /// The constants K0, ..., K4 that ensure wire subsets are disjoint.
    pub fn k(&self) -> &[E::Fr] {
        &self.vk.k
    }
}

/// Preprocessed verifier parameters used to verify Plonk proofs for a certain
/// circuit.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: PairingEngine> {
    /// The size of the evaluation domain. Should be a power of two.
    pub domain_size: usize,

    /// The number of public inputs.
    pub num_inputs: usize,

    /// The permutation polynomial commitments. The commitments are not hiding.
    pub sigma_comms: Vec<Commitment<E>>,

    /// The selector polynomial commitments. The commitments are not hiding.
    pub selector_comms: Vec<Commitment<E>>,

    /// The constants K0, ..., K_num_wire_types that ensure wire subsets are
    /// disjoint.
    pub k: Vec<E::Fr>,

    /// KZG PCS opening key.
    pub open_key: OpenKey<E>,
}

impl<E, F, P1, P2> From<VerifyingKey<E>> for Vec<E::Fq>
where
    E: PairingEngine<G1Affine = GroupAffine<P1>, G2Affine = GroupAffine<P2>, Fqe = Fp2<F>>,
    F: Fp2Parameters<Fp = E::Fq>,
    P1: SWModelParameters<BaseField = E::Fq, ScalarField = E::Fr> + Clone,
    P2: SWModelParameters<BaseField = E::Fqe, ScalarField = E::Fr> + Clone,
{
    fn from(vk: VerifyingKey<E>) -> Self {
        [
            vec![E::Fq::from(vk.domain_size as u64)],
            vec![E::Fq::from(vk.num_inputs as u64)],
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
            vk.k.iter().map(|fr| fr_to_fq::<E::Fq, P1>(fr)).collect(),
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
    E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
    F: SWToTEConParam,
    P: SWModelParameters<BaseField = F> + Clone,
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

impl<E: PairingEngine> VerifyingKey<E> {
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
        }
    }
}

/// Plonk IOP verifier challenges.
#[derive(Debug, Default)]
pub(crate) struct Challenges<F: Field> {
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
}

/// The vector representation of bases and corresponding scalars.
#[derive(Debug)]
pub(crate) struct ScalarsAndBases<E: PairingEngine> {
    pub(crate) base_scalar_map: HashMap<E::G1Affine, E::Fr>,
}

impl<E: PairingEngine> ScalarsAndBases<E> {
    pub(crate) fn new() -> Self {
        Self {
            base_scalar_map: HashMap::new(),
        }
    }
    /// Insert a base point and the corresponding scalar.
    pub(crate) fn push(&mut self, scalar: E::Fr, base: E::G1Affine) {
        let entry_scalar = self.base_scalar_map.entry(base).or_insert_with(E::Fr::zero);
        *entry_scalar += scalar;
    }
    /// Add a list of scalars and bases into self, where each scalar is
    /// multiplied by a constant c.
    pub(crate) fn merge(&mut self, c: E::Fr, scalars_and_bases: &Self) {
        for (&base, scalar) in &scalars_and_bases.base_scalar_map {
            self.push(c * scalar, base);
        }
    }
    /// Compute the multi-scalar multiplication.
    pub(crate) fn multi_scalar_mul(&self) -> E::G1Projective {
        let mut bases = vec![];
        let mut scalars = vec![];
        for (&base, scalar) in &self.base_scalar_map {
            bases.push(base);
            scalars.push(scalar.into_repr());
        }
        VariableBaseMSM::multi_scalar_mul(&bases, &scalars)
    }
}

/// Specializes the public parameters for a given maximum degree `d` for
/// polynomials `d` should be less that `pp.max_degree()`.
/// TODO: (binyi) This is copied from a `pub(crate)` method in Arkworks, we
/// should fork Arkwork's KZG10 library and make this method public.
/// NOTE: This doesn't support hiding variant of KZG10 since Plonk don't need
/// it, and `powers_of_gamma_g` is empty and `gamma_g` is dummy.
pub(crate) fn trim<E: PairingEngine>(
    pp: &UniversalParams<E>,
    mut supported_degree: usize,
) -> (Powers<E>, VerifierKey<E>) {
    if supported_degree == 1 {
        supported_degree += 1;
    }
    let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
    let powers_of_gamma_g = vec![]; // not used

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: E::G1Affine::default(), // not used
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    (powers, vk)
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::{g1::Parameters, Bn254, Fq};
    use ark_ec::AffineCurve;

    #[test]
    fn test_group_to_field() {
        let g1 = <Bn254 as PairingEngine>::G1Affine::prime_subgroup_generator();
        let f1: Vec<Fq> = group1_to_fields::<Bn254, Parameters>(g1);
        assert_eq!(f1.len(), 2);
        let g2 = <Bn254 as PairingEngine>::G2Affine::prime_subgroup_generator();
        let f2: Vec<Fq> = group2_to_fields::<Bn254, _, _>(g2);
        assert_eq!(f2.len(), 4);
    }
}
