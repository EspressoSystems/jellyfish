// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of a sparse, 3-ary Merkle tree using a Rescue hash function.

use crate::{
    internal::MerkleNode,
    prelude::{MerkleTreeProof, RescueSparseMerkleTree},
    MerkleProof, MerkleTreeScheme, ToTraversalPath,
};
use ark_std::vec::Vec;
use jf_relation::{BoolVar, Circuit, CircuitError, PlonkCircuit, Variable};
use jf_rescue::RescueParameter;
use num_bigint::BigUint;

use super::{
    constrain_sibling_order, DigestAlgorithmGadget, Merkle3AryNodeVar, Merkle3AryProofVar,
    UniversalMerkleTreeGadget,
};

type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;

impl<F> UniversalMerkleTreeGadget<SparseMerkleTree<F>> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    type NonMembershipProofVar = Merkle3AryProofVar;

    /// Checks if a given element is not a member of the Merkle tree.
    fn is_non_member(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: &Merkle3AryProofVar,
        commitment_var: Variable,
    ) -> Result<BoolVar, CircuitError> {
        let computed_commitment_var = self.compute_commitment(proof_var)?;
        self.is_equal(computed_commitment_var, commitment_var)
    }

    /// Enforces constraints for non-membership proofs in the circuit.
    fn enforce_non_membership_proof(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: &Merkle3AryProofVar,
        expected_commitment_var: Variable,
    ) -> Result<(), CircuitError> {
        let is_valid = self.is_non_member(non_elem_idx_var, proof_var, expected_commitment_var)?;
        self.enforce_true(is_valid.into())
    }

    /// Creates variables for the non-membership proof.
    fn create_non_membership_proof_variable(
        &mut self,
        pos: &<SparseMerkleTree<F> as MerkleTreeScheme>::Index,
        merkle_proof: &MerkleTreeProof<F>,
    ) -> Result<Merkle3AryProofVar, CircuitError> {
        let path = <BigUint as ToTraversalPath<3>>::to_traversal_path(&pos, merkle_proof.height());
        let nodes = self.build_merkle_nodes(&path, merkle_proof)?;
        self.validate_nodes(&nodes)?;
        Ok(Merkle3AryProofVar { node_vars: nodes })
    }
}

impl<F> PlonkCircuit<F>
where
    F: RescueParameter,
{
    /// Computes the commitment variable from the Merkle proof.
    fn compute_commitment(
        &mut self,
        proof_var: &Merkle3AryProofVar,
    ) -> Result<Variable, CircuitError> {
        let mut current_label = self.zero();
        for node in &proof_var.node_vars {
            let input_labels = constrain_sibling_order(
                self,
                current_label,
                node.sibling1,
                node.sibling2,
                node.is_left_child,
                node.is_right_child,
            )?;
            current_label = Self::DigestGadget::digest(self, &input_labels)?;
        }
        Ok(current_label)
    }

    /// Builds Merkle tree nodes from the given path and proof.
    fn build_merkle_nodes(
        &mut self,
        path: &[usize],
        merkle_proof: &MerkleTreeProof<F>,
    ) -> Result<Vec<Merkle3AryNodeVar>, CircuitError> {
        path.iter()
            .zip(merkle_proof.path_values().iter())
            .filter(|(_, siblings)| !siblings.is_empty())
            .map(|(branch, siblings)| {
                Ok(Merkle3AryNodeVar {
                    sibling1: self.create_variable(siblings[0])?,
                    sibling2: self.create_variable(siblings[1])?,
                    is_left_child: self.create_boolean_variable(branch == &0)?,
                    is_right_child: self.create_boolean_variable(branch == &2)?,
                })
            })
            .collect()
    }

    /// Validates Merkle tree nodes by enforcing boolean constraints.
    fn validate_nodes(&mut self, nodes: &[Merkle3AryNodeVar]) -> Result<(), CircuitError> {
        for node in nodes {
            let left_plus_right = self.add(node.is_left_child.into(), node.is_right_child.into())?;
            self.enforce_bool(left_plus_right)?;
        }
        Ok(())
    }
}

// ============================= Tests =============================

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        gadgets::{MerkleTreeGadget, UniversalMerkleTreeGadget},
        prelude::RescueSparseMerkleTree,
        MerkleTreeScheme, UniversalMerkleTreeScheme,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use hashbrown::HashMap;

    type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;

    #[test]
    fn test_universal_mt_gadget() {
        for field in [
            test_non_membership_helper::<FqEd254>,
            test_non_membership_helper::<FqEd377>,
            test_non_membership_helper::<FqEd381>,
            test_non_membership_helper::<FqEd381b>,
            test_non_membership_helper::<Fq377>,
        ] {
            field();
        }
    }

    fn test_non_membership_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let uid = BigUint::from(3u64);

        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));

        let mt = SparseMerkleTree::<F>::from_kv_set(2, &hashmap).unwrap();
        let commitment = mt.commitment();
        let proof = mt.universal_lookup(&uid).expect_not_found().unwrap();

        let non_elem_idx_var = circuit.create_variable(uid.clone().into()).unwrap();
        let proof_var =
            UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::create_non_membership_proof_variable(
                &mut circuit,
                &uid.into(),
                &proof,
            )
            .unwrap();

        let commitment_var = MerkleTreeGadget::<SparseMerkleTree<F>>::create_commitment_variable(
            &mut circuit,
            &commitment,
        )
        .unwrap();

        UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::enforce_non_membership_proof(
            &mut circuit,
            non_elem_idx_var,
            &proof_var,
            commitment_var,
        )
        .unwrap();

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Mutate commitment for invalid proof.
        *circuit.witness_mut(commitment_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
