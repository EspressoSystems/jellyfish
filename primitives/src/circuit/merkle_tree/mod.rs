// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait definitions for a Merkle tree gadget.

use crate::merkle_tree::MerkleTreeScheme;
use jf_relation::{errors::CircuitError, BoolVar, Variable};

mod rescue_merkle_tree;
mod sparse_merkle_tree;
use ark_std::vec::Vec;

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
/// let leaf_var = circuit.create_leaf_variable(Fq::from(2_u64), Fq::from(100_u64)).unwrap();
/// let path_vars = circuit.create_membership_proof_variable(&proof).unwrap();
/// let root_var = circuit.create_root_variable(expected_root).unwrap();
/// circuit.enforce_merkle_proof(leaf_var, path_vars, root_var).unwrap();
/// assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
/// ```
pub trait MerkleTreeGadget<M>
where
    M: MerkleTreeScheme,
{
    /// Type to represent the leaf element of the concrete MT instantiation.
    type LeafVar;

    /// Type to represent the merkle path of the concrete MT instantiation.
    /// It is MT-specific, e.g arity will affect the exact definition of the
    /// Merkle path.
    type MerklePathVar;

    /// Allocate a variable for the leaf element.
    fn create_leaf_variable(
        &mut self,
        pos: M::Index,
        elem: M::Element,
    ) -> Result<Self::LeafVar, CircuitError>;

    /// Allocate a variable for the membership proof.
    fn create_membership_proof_variable(
        &mut self,
        membership_proof: &M::MembershipProof,
    ) -> Result<Self::MerklePathVar, CircuitError>;

    /// Allocate a variable for the merkle root.
    fn create_root_variable(&mut self, root: M::NodeValue) -> Result<Variable, CircuitError>;

    /// Given a leaf element and its merkle proof,
    /// return `BoolVar` indicating the correctness of its membership proof
    fn is_member(
        &mut self,
        elem: Self::LeafVar,
        merkle_proof: Self::MerklePathVar,
        merkle_root: Variable,
    ) -> Result<BoolVar, CircuitError>;

    /// Enforce correct `merkle_proof` for the `elem` against
    /// `expected_merkle_root`.
    fn enforce_membership_proof(
        &mut self,
        elem: Self::LeafVar,
        merkle_proof: Self::MerklePathVar,
        expected_merkle_root: Variable,
    ) -> Result<(), CircuitError>;
}

/// Gadget for the sparse merkle tree
pub trait SparseMerkleTreeGadget<M>: MerkleTreeGadget<M>
where
    M: MerkleTreeScheme,
{
    /// checking non-membership proof
    fn is_non_member(
        &mut self,
        elem: Self::LeafVar,
        merkle_proof: Self::MerklePathVar,
        merkle_root: Variable,
    ) -> Result<BoolVar, CircuitError>;

    /// Enforce correct `merkle_proof` for the empty leaf `elem` against
    /// `expected_merkle_root`.
    fn enforce_non_membership_proof(
        &mut self,
        empty_elem: Self::LeafVar,
        merkle_proof: Self::MerklePathVar,
        expected_merkle_root: Variable,
    ) -> Result<(), CircuitError>;
}

pub(crate) trait MerkleTreeHelperGadget<M>
where
    M: MerkleTreeScheme,
{
    type MembershipProofBooleanEncoding;
    type MembershipProofVar;
    /// Produces an ordered list of variables based on the relative position of
    /// a node and its siblings.
    /// * `node` - node to be inserted in the final list.
    /// * `sibling1` - first sibling
    /// * `sibling2` - second sibling
    /// * `node_is_left` - variable that is true if node is the leftmost one.
    /// * `node_is_right` -  variable that is true if node is the rightmost one.
    /// * `returns` - list of variables corresponding to the node and its
    ///   siblings in the correct order.
    fn permute(
        &mut self,
        node: Variable,
        sib1: Variable,
        sib2: Variable,
        node_is_left: BoolVar,
        node_is_right: BoolVar,
    ) -> Result<[Variable; 3], CircuitError>;

    /// Ensure that the position of each node of the path is correctly encoded
    /// Used for testing purposes.
    /// * `merkle_path` - list of node of an authentication path
    /// * `pos` - position of the missing leaf
    /// * `returns` - list of variables corresponding to the authentication path
    fn constrain_membership_proof(
        &mut self,
        merkle_path: &Self::MembershipProofBooleanEncoding,
        pos: M::Index,
    ) -> Result<Self::MembershipProofVar, CircuitError>;

    /// Computes the merkle root based on some element placed at a leaf and a
    /// merkle path.
    /// * `elem` - variables corresponding to the uid and the element value
    ///   (e.g.: record commitment).
    /// * `path_vars` - variables corresponding to the Merkle path.
    /// * `return` - variable corresponding to the root value of the Merkle
    ///   tree.
    fn compute_merkle_root(
        &mut self,
        elem: StandardLeafVar,
        path_vars: &Self::MembershipProofVar,
    ) -> Result<Variable, CircuitError>;
}

#[derive(Debug, Clone)]
/// Circuit variable for a Merkle node.
pub struct Rescue3AryNodeVar {
    /// First sibling of the node.
    pub sibling1: Variable,
    /// Second sibling of the node.
    pub sibling2: Variable,
    /// Boolean variable indicating whether the node is a left child.
    pub is_left_child: BoolVar,
    /// Boolean variable indicating whether the node is a right child.
    pub is_right_child: BoolVar,
}

/// Circuit variable for a leaf element.
#[derive(Debug, Clone)]
pub struct StandardLeafVar {
    /// Position of the leaf element in the MT. Serves as UID.
    pub uid: Variable,
    /// The value of the leaf element.
    pub elem: Variable,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct MerkleNodeBooleanEncoding<M: MerkleTreeScheme> {
    sibling1: M::NodeValue,
    sibling2: M::NodeValue,
    is_left_child: bool,
    is_right_child: bool,
}

impl<M: MerkleTreeScheme> MerkleNodeBooleanEncoding<M> {
    fn new(
        sibling1: M::NodeValue,
        sibling2: M::NodeValue,
        is_left_child: bool,
        is_right_child: bool,
    ) -> Self {
        MerkleNodeBooleanEncoding {
            sibling1,
            sibling2,
            is_left_child,
            is_right_child,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct MembershipProofBooleanEncoding<M: MerkleTreeScheme> {
    pub(crate) nodes: Vec<MerkleNodeBooleanEncoding<M>>,
}
