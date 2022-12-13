// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![allow(missing_docs)]

//! Trait definitions for a Merkle tree gadget.

use crate::merkle_tree::MerkleTreeScheme;
use ark_ff::PrimeField;
use jf_relation::{errors::CircuitError, BoolVar, Variable};

mod rescue_merkle_tree;

/// Circuit variable for an accumulated element.
#[derive(Debug, Clone)]
pub struct LeafVar {
    pub uid: Variable,
    pub elem: Variable,
}

/// Gadgets for rescue-based merkle tree
pub trait MerkleTreeGadget<F, M>
where
    F: PrimeField,
    M: MerkleTreeScheme,
{
    // Type to represent the merkle path of the concrete instantiation.
    // It is MT-specific, since arity will affect the exact definition of the Merkle
    // path.
    type MerklePathVar;

    /// Allocate a variable for the leaf element.
    fn create_leaf_variable(&mut self, pos: F, elem: M::Element) -> Result<LeafVar, CircuitError>;

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
        elem: LeafVar,
        merkle_proof: Self::MerklePathVar,
        merkle_root: Variable,
    ) -> Result<BoolVar, CircuitError>;

    /// Enforce correct `merkle_proof` for the `elem` against
    /// `expected_merkle_root`.
    fn enforce_merkle_proof(
        &mut self,
        elem: LeafVar,
        merkle_proof: Self::MerklePathVar,
        expected_merkle_root: Variable,
    ) -> Result<(), CircuitError>;
}
