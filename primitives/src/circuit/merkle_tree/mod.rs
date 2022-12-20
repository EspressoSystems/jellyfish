// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait definitions for a Merkle tree gadget.

use crate::merkle_tree::MerkleTreeScheme;
use jf_relation::{errors::CircuitError, BoolVar, Variable};

mod rescue_merkle_tree;
mod sparse_merkle_tree;

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
    fn enforce_merkle_proof(
        &mut self,
        elem: Self::LeafVar,
        merkle_proof: Self::MerklePathVar,
        expected_merkle_root: Variable,
    ) -> Result<(), CircuitError>;
}
