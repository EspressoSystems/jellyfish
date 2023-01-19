// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait definitions for a Merkle tree gadget.

use crate::{
    merkle_tree::{MerkleTreeScheme, UniversalMerkleTreeScheme},
    rescue::RescueParameter,
};
use ark_ff::PrimeField;
use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};

mod rescue_merkle_tree;
mod sparse_merkle_tree;
use ark_std::vec::Vec;

use super::rescue::RescueNativeGadget;

/// Gadget for a Merkle tree
///
/// # Examples
///
/// ```
/// use ark_bls12_377::Fq;
/// use jf_primitives::circuit::merkle_tree::MerkleTreeGadget;
/// use jf_relation::{Circuit, PlonkCircuit};
/// use jf_primitives::merkle_tree::{prelude::RescueMerkleTree, MerkleTreeScheme, MerkleCommitment};
///
/// let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
/// // Create a 3-ary MT, instantiated with a Rescue-based hash, of height 1.
/// let elements = vec![Fq::from(1_u64), Fq::from(2_u64), Fq::from(100_u64)];
/// let mt = RescueMerkleTree::<Fq>::from_elems(1, elements).unwrap();
/// let expected_root = mt.commitment().digest();
/// // Get a proof for the element in position 2
/// let (_, proof) = mt.lookup(2).expect_ok().unwrap();
///
/// // Circuit computation with a MT
/// let elem_idx = circuit.create_variable(2_u64.into()).unwrap();
/// let proof_var =
///     MerkleTreeGadget::<RescueMerkleTree<Fq>>::create_membership_proof_variable(
///         &mut circuit,
///         &proof
///     )
///     .unwrap();
/// let root_var =
///     MerkleTreeGadget::<RescueMerkleTree<Fq>>::create_root_variable(
///         &mut circuit,
///         expected_root
///     )
///     .unwrap();
/// MerkleTreeGadget::<RescueMerkleTree<Fq>>::enforce_membership_proof(
///     &mut circuit,
///     elem_idx,
///     proof_var,
///     root_var
/// )
/// .unwrap();
/// assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
/// ```
pub trait MerkleTreeGadget<M>
where
    M: MerkleTreeScheme,
    M::NodeValue: PrimeField,
{
    /// Type to represent the merkle proof of the concrete MT instantiation.
    /// It is MT-specific, e.g arity will affect the exact definition of the
    /// underlying Merkle path.
    type MembershipProofVar;

    /// Gadget for the digest algorithm.
    type DigestGadget: DigestAlgorithmGadget<M::NodeValue>;

    /// Allocate a variable for the membership proof.
    fn create_membership_proof_variable(
        &mut self,
        membership_proof: &M::MembershipProof,
    ) -> Result<Self::MembershipProofVar, CircuitError>;

    /// Allocate a variable for the merkle root.
    fn create_root_variable(&mut self, root: M::NodeValue) -> Result<Variable, CircuitError>;

    /// Given variables representing:
    /// * an element index
    /// * its merkle proof
    /// * root
    /// * return `BoolVar` indicating the correctness of its membership proof.
    fn is_member(
        &mut self,
        elem_idx_var: Variable,
        proof_var: Self::MembershipProofVar,
        root_var: Variable,
    ) -> Result<BoolVar, CircuitError>;

    /// Enforce correct `proof_var` for the `elem_idx_var` against
    /// `expected_root_var`.
    fn enforce_membership_proof(
        &mut self,
        elem_idx_var: Variable,
        proof_var: Self::MembershipProofVar,
        expected_root_var: Variable,
    ) -> Result<(), CircuitError>;
}

/// Gadget for the universal Merkle tree
///
/// # Examples
///
/// ```
/// use ark_bls12_377::Fq;
/// use jf_primitives::circuit::merkle_tree::{MerkleTreeGadget, UniversalMerkleTreeGadget};
/// use jf_relation::{Circuit, PlonkCircuit};
/// use jf_primitives::merkle_tree::{MerkleTreeScheme, MerkleCommitment, UniversalMerkleTreeScheme,
///     prelude::RescueSparseMerkleTree};
/// use hashbrown::HashMap;
/// use num_bigint::BigUint;
///
/// type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;
/// let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
/// // Create a 3-ary universal MT, instantiated with a Rescue-based hash, of height 2.
/// let mut hashmap = HashMap::new();
/// hashmap.insert(BigUint::from(1u64), Fq::from(2u64));
/// hashmap.insert(BigUint::from(2u64), Fq::from(2u64));
/// hashmap.insert(BigUint::from(1u64), Fq::from(3u64));
/// let mt = SparseMerkleTree::<Fq>::from_kv_set(2, &hashmap).unwrap();
/// let expected_root = mt.commitment().digest();
/// // Get a proof for the element in position 2
/// let proof = mt.universal_lookup(&BigUint::from(3u64)).expect_not_found().unwrap();
///
/// // Circuit computation with a MT
/// let non_elem_idx_var = circuit.create_variable(BigUint::from(3u64).into()).unwrap();
///
/// let proof_var =
///     UniversalMerkleTreeGadget::<SparseMerkleTree<Fq>>::create_non_membership_proof_variable(
///         &mut circuit,
///         &proof
///     )
///     .unwrap();
/// let root_var =
///     MerkleTreeGadget::<SparseMerkleTree<Fq>>::create_root_variable(
///         &mut circuit,
///         expected_root
///     )
///     .unwrap();
/// UniversalMerkleTreeGadget::<SparseMerkleTree<Fq>>::enforce_non_membership_proof(
///     &mut circuit,
///     non_elem_idx_var,
///     proof_var,
///     root_var
/// )
/// .unwrap();
/// assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
/// ```
pub trait UniversalMerkleTreeGadget<M>: MerkleTreeGadget<M>
where
    M: UniversalMerkleTreeScheme,
    M::NodeValue: PrimeField,
{
    /// Type to represent the merkle non-membership proof of the concrete MT
    /// instantiation. It is MT-specific, e.g arity will affect the exact
    /// definition of the underlying Merkle path.
    type NonMembershipProofVar;

    /// Allocate a variable for the membership proof.
    fn create_non_membership_proof_variable(
        &mut self,
        membership_proof: &M::NonMembershipProof,
    ) -> Result<Self::NonMembershipProofVar, CircuitError>;

    /// checking non-membership proof
    fn is_non_member(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: Self::NonMembershipProofVar,
        root_var: Variable,
    ) -> Result<BoolVar, CircuitError>;

    /// Enforce correct `proof_var` for the empty elem `empty_elem_idx_var`
    /// against `expected_root_var`.
    fn enforce_non_membership_proof(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: Self::NonMembershipProofVar,
        expected_root_var: Variable,
    ) -> Result<(), CircuitError>;
}

/// Produces a list of circuit variables representing the ordered nodes,
/// based on the location of a `node` among its siblings, and otherwise
/// preserving the relative location of the siblings.
/// * `node` - node to be placed in the correct position
/// * `sibling1` - first sibling
/// * `sibling2` - second sibling
/// * `node_is_left` - variable that is true if node is the leftmost one.
/// * `node_is_right` -  variable that is true if node is the rightmost one.
/// * `returns` - list of variables corresponding to the node and its siblings
///   in the correct order.
fn constrain_sibling_order<F: RescueParameter>(
    circuit: &mut PlonkCircuit<F>,
    node: Variable,
    sib1: Variable,
    sib2: Variable,
    node_is_left: BoolVar,
    node_is_right: BoolVar,
) -> Result<[Variable; 3], CircuitError> {
    let one = F::one();
    let left_node = circuit.conditional_select(node_is_left, sib1, node)?;
    let right_node = circuit.conditional_select(node_is_right, sib2, node)?;
    let left_plus_right = circuit.add(left_node, right_node)?;
    let mid_node = circuit.lc(
        &[node, sib1, sib2, left_plus_right],
        &[one, one, one, one.neg()],
    )?;
    Ok([left_node, mid_node, right_node])
}

#[derive(Debug, Clone)]
/// Circuit variable for a node in the Merkle path.
pub struct Merkle3AryNodeVar {
    /// First sibling of the node.
    sibling1: Variable,
    /// Second sibling of the node.
    sibling2: Variable,
    /// Boolean variable indicating whether the node is a left child.
    is_left_child: BoolVar,
    /// Boolean variable indicating whether the node is a right child.
    is_right_child: BoolVar,
}

/// Circuit variable for a Merkle non-membership proof of a 3-ary Merkle tree.
/// Constains:
/// * a list of node variables in the path,
/// * a variable correseponsing to the position of the element.
#[derive(Debug, Clone)]
pub struct Merkle3AryNonMembershipProofVar {
    node_vars: Vec<Merkle3AryNodeVar>,
    pos_var: Variable,
}

/// Circuit variable for a Merkle proof of a 3-ary Merkle tree.
/// Constains:
/// * a list of node variables in the path,
/// * a variable correseponsing to the value of the element.
#[derive(Debug, Clone)]
pub struct Merkle3AryMembershipProofVar {
    node_vars: Vec<Merkle3AryNodeVar>,
    elem_var: Variable,
}
/// Circuit counterpart to DigestAlgorithm
pub trait DigestAlgorithmGadget<F>
where
    F: PrimeField,
{
    /// Digest a list of variables
    fn digest(circuit: &mut PlonkCircuit<F>, data: &[Variable]) -> Result<Variable, CircuitError>;

    /// Digest an indexed element
    fn digest_leaf(
        circuit: &mut PlonkCircuit<F>,
        pos: usize,
        elem: Variable,
    ) -> Result<Variable, CircuitError>;
}

/// Digest gadget using for the Rescue hash function.
pub struct RescueDigestGadget {}

impl<F: RescueParameter> DigestAlgorithmGadget<F> for RescueDigestGadget {
    fn digest(circuit: &mut PlonkCircuit<F>, data: &[Variable]) -> Result<Variable, CircuitError> {
        Ok(RescueNativeGadget::<F>::rescue_sponge_no_padding(circuit, data, 1)?[0])
    }

    fn digest_leaf(
        circuit: &mut PlonkCircuit<F>,
        pos: Variable,
        elem: Variable,
    ) -> Result<Variable, CircuitError> {
        let zero = circuit.zero();
        Ok(RescueNativeGadget::<F>::rescue_sponge_no_padding(circuit, &[zero, pos, elem], 1)?[0])
    }
}
