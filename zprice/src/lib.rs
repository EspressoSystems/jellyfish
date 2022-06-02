// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Helper functions and testing/bechmark code for ZPrice: Plonk-DIZK GPU
//! acceleration

#![no_std]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

use ark_bls12_381::Fr;
use ark_std::{rand::Rng, vec, UniformRand};
use jf_plonk::prelude::*;
use jf_primitives::{
    circuit::merkle_tree::{AccElemVars, AccMemberWitnessVar, MerkleTreeGadget},
    merkle_tree::{AccMemberWitness, MerkleTree},
};

/// Merkle Tree height
pub const TREE_HEIGHT: u8 = 5;
/// Number of memberships proofs to be verified in the circuit
pub const NUM_MEMBERSHIP_PROOFS: usize = 10;

/// generate a gigantic circuit (with random, satisfiable wire assignments)
pub fn generate_circuit<R: Rng>(rng: &mut R) -> Result<PlonkCircuit<Fr>, PlonkError> {
    let mut leaves = vec![];
    let mut merkle_proofs = vec![];

    // sample leaves and insert into the merkle tree
    let mut mt = MerkleTree::new(TREE_HEIGHT).expect("Failed to initialize merkle tree");

    for _ in 0..NUM_MEMBERSHIP_PROOFS {
        let leaf = Fr::rand(rng);
        mt.push(leaf);
        leaves.push(leaf);
    }
    for uid in 0..NUM_MEMBERSHIP_PROOFS {
        merkle_proofs.push(
            AccMemberWitness::lookup_from_tree(&mt, uid as u64)
                .expect_ok()
                .expect("Failed to generate merkle proof")
                .1,
        );
    }
    let root = mt.commitment().root_value.to_scalar();

    // construct circuit constraining membership proof check
    let mut circuit = PlonkCircuit::new();
    // add root as a public input
    let root_var = circuit.create_public_variable(root)?;
    for (uid, proof) in merkle_proofs.iter().enumerate() {
        let leaf_var = circuit.create_variable(leaves[uid])?;
        let proof_var = AccMemberWitnessVar::new(&mut circuit, proof)?;
        let acc_elem_var = AccElemVars {
            uid: proof_var.uid,
            elem: leaf_var,
        };

        let claimed_root_var = circuit.compute_merkle_root(acc_elem_var, &proof_var.merkle_path)?;

        // enforce matching merkle root
        circuit.equal_gate(root_var, claimed_root_var)?;
    }

    // sanity check: the circuit must be satisfied.
    assert!(circuit.check_circuit_satisfiability(&[root]).is_ok());
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_constant_config() {
        assert!(
            3usize.pow(TREE_HEIGHT as u32) >= NUM_MEMBERSHIP_PROOFS,
            "Insufficient TREE_HEIGHT!"
        );
    }

    #[test]
    fn test_generate_circuit() -> Result<(), PlonkError> {
        let mut rng = ark_std::test_rng();
        generate_circuit(&mut rng)?;
        Ok(())
    }
}
