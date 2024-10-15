// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of a sparse, 3-ary Merkle tree, instantiated
//! with a Rescue hash function.

use crate::{
    internal::MerkleNode,
    prelude::{MerkleTreeProof, RescueSparseMerkleTree},
    MerkleProof, MerkleTreeScheme, ToTraversalPath,
};
use ark_std::vec::Vec;
use jf_relation::{BoolVar, Circuit, CircuitError, PlonkCircuit, Variable};
use jf_rescue::RescueParameter;

type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;
use super::{
    constrain_sibling_order, DigestAlgorithmGadget, Merkle3AryNodeVar, Merkle3AryProofVar,
    UniversalMerkleTreeGadget,
};
use num_bigint::BigUint;

impl<F> UniversalMerkleTreeGadget<SparseMerkleTree<F>> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    type NonMembershipProofVar = Merkle3AryProofVar;

    fn is_non_member(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: &Merkle3AryProofVar,
        commitment_var: Variable,
    ) -> Result<BoolVar, CircuitError> {
        let computed_commitment_var = {
            let mut cur_label = self.zero();
            for cur_node in proof_var.node_vars.iter() {
                let input_labels = constrain_sibling_order(
                    self,
                    cur_label,
                    cur_node.sibling1,
                    cur_node.sibling2,
                    cur_node.is_left_child,
                    cur_node.is_right_child,
                )?;
                let is_zero_vars = [
                    self.is_zero(input_labels[0])?,
                    self.is_zero(input_labels[1])?,
                    self.is_zero(input_labels[2])?,
                ];
                cur_label = Self::DigestGadget::digest(self, &input_labels)?;
            }
            Ok(cur_label)
        }?;
        self.is_equal(computed_commitment_var, commitment_var)
    }

    fn enforce_non_membership_proof(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: &Merkle3AryProofVar,
        expected_commitment_var: Variable,
    ) -> Result<(), CircuitError> {
        let bool_val = self.is_non_member(non_elem_idx_var, proof_var, expected_commitment_var)?;
        self.enforce_true(bool_val.into())
    }

    fn create_non_membership_proof_variable(
        &mut self,
        pos: &<SparseMerkleTree<F> as MerkleTreeScheme>::Index,
        merkle_proof: &MerkleTreeProof<F>,
    ) -> Result<Merkle3AryProofVar, CircuitError> {
        let path = <BigUint as ToTraversalPath<3>>::to_traversal_path(&pos, merkle_proof.height());

        let nodes = path
            .iter()
            .zip(merkle_proof.path_values().iter())
            .filter(|(_, v)| v.len() > 0)
            .map(|(branch, siblings)| {
                Ok(Merkle3AryNodeVar {
                    sibling1: self.create_variable(siblings[0])?,
                    sibling2: self.create_variable(siblings[1])?,
                    is_left_child: self.create_boolean_variable(branch == &0)?,
                    is_right_child: self.create_boolean_variable(branch == &2)?,
                })
            })
            .collect::<Result<Vec<Merkle3AryNodeVar>, CircuitError>>()?;

        // `is_left_child`, `is_right_child` and `is_left_child+is_right_child` are
        // boolean
        for node in nodes.iter() {
            // Boolean constrain `is_left_child + is_right_child` because a node
            // can either be the left or the right child of its parent
            let left_plus_right =
                self.add(node.is_left_child.into(), node.is_right_child.into())?;
            self.enforce_bool(left_plus_right)?;
        }

        Ok(Merkle3AryProofVar { node_vars: nodes })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        gadgets::{MerkleTreeGadget, UniversalMerkleTreeGadget},
        prelude::RescueSparseMerkleTree,
        MerkleCommitment, MerkleTreeScheme, UniversalMerkleTreeScheme,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use hashbrown::HashMap;
    use jf_relation::{Circuit, PlonkCircuit};
    use jf_rescue::RescueParameter;
    use num_bigint::BigUint;

    type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;

    #[test]
    fn test_universal_mt_gadget() {
        test_non_membership_helper::<FqEd254>();
        test_non_membership_helper::<FqEd377>();
        test_non_membership_helper::<FqEd381>();
        test_non_membership_helper::<FqEd381b>();
        test_non_membership_helper::<Fq377>();
    }

    fn test_non_membership_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        // Happy path

        // An element we care about is inserted in position 2
        let uid = BigUint::from(3u64);

        // native computation with a MT
        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));
        hashmap.insert(BigUint::from(1u64), F::from(3u64));
        let mt = SparseMerkleTree::<F>::from_kv_set(2, &hashmap).unwrap();
        let commitment = mt.commitment();

        // proof of non-membership
        let proof = mt.universal_lookup(&uid).expect_not_found().unwrap();

        // Circuit computation with a MT
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
        *circuit.witness_mut(commitment_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Bad path:
        // The circuit cannot be satisfied if we try to prove non-membership of an
        // existing element.
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let pos = 2u64;
        let elem_idx_var = circuit.create_variable(pos.into()).unwrap();

        let proof_var =
            UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::create_non_membership_proof_variable(
                &mut circuit,
                &pos.into(),
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
            elem_idx_var,
            &proof_var,
            commitment_var,
        )
        .unwrap();

        // Circuit does not verify because a left node value is 0
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
