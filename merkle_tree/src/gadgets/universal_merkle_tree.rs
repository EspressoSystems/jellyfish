// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of a sparse, 3-ary Merkle tree, instantiated
//! with a Rescue hash function.

use crate::{
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
        // First check that if the input index is consistent with the proof branches
        let mut base = F::from(1u64);
        let mut cumulative = self.zero();
        for node_var in &proof_var.node_vars {
            let coef = self.sub(self.one(), node_var.is_left_child.into())?;
            let coef = self.add(coef, node_var.is_right_child.into())?;
            let to_add = self.mul_constant(coef, &base)?;
            cumulative = self.add(cumulative, to_add)?;
            base = base + base + base;
        }
        let index_check = self.is_equal(cumulative, non_elem_idx_var)?;
        // Compute the commitment from the proof and check if it matches the expected
        // commitment.
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
                let all_zero = self.logic_and_all(&is_zero_vars)?;
                cur_label = Self::DigestGadget::digest(self, &input_labels)?;
                // Current label remains zero if all input labels are zero
                cur_label = self.conditional_select(all_zero, cur_label, self.zero())?;
            }
            Ok(cur_label)
        }?;
        let commitment_check = self.is_equal(computed_commitment_var, commitment_var)?;
        self.logic_and(index_check, commitment_check)
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
        let path = <BigUint as ToTraversalPath<3>>::to_traversal_path(pos, merkle_proof.height());

        let nodes = path
            .iter()
            .zip(merkle_proof.path_values().iter())
            .map(|(branch, siblings)| {
                let is_empty = siblings.is_empty();
                Ok(Merkle3AryNodeVar {
                    sibling1: if is_empty {
                        self.zero()
                    } else {
                        self.create_variable(siblings[0])?
                    },
                    sibling2: if is_empty {
                        self.zero()
                    } else {
                        self.create_variable(siblings[1])?
                    },
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
        gadgets::{
            DigestAlgorithmGadget, Merkle3AryNodeVar, Merkle3AryProofVar, MerkleTreeGadget,
            RescueDigestGadget, UniversalMerkleTreeGadget,
        },
        internal::MerkleTreeProof,
        prelude::RescueSparseMerkleTree,
        MerkleProof, MerkleTreeScheme, ToTraversalPath, UniversalMerkleTreeScheme,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::vec::Vec;
    use hashbrown::HashMap;
    use jf_relation::{BoolVar, Circuit, CircuitError, PlonkCircuit, Variable};
    use jf_rescue::RescueParameter;
    use num_bigint::BigUint;

    type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;

    // -----------------------------------------------------------------------
    // Verbatim copy of the two functions as they existed before PR #862.
    // Kept here so the regression test can directly demonstrate the bug:
    // the old `buggy_is_non_member` ignored `non_elem_idx_var` entirely, and
    // `buggy_create_non_membership_proof_variable` silently dropped path levels
    // whose sibling array was empty (early-termination in sparse proofs).
    // -----------------------------------------------------------------------

    /// Old `is_non_member` — `non_elem_idx_var` is accepted but never used.
    fn buggy_is_non_member<F: RescueParameter>(
        circuit: &mut PlonkCircuit<F>,
        _non_elem_idx_var: Variable, // BUG: intentionally ignored
        proof_var: &Merkle3AryProofVar,
        commitment_var: Variable,
    ) -> Result<BoolVar, CircuitError> {
        let computed_commitment_var = {
            let mut cur_label = circuit.zero();
            for cur_node in proof_var.node_vars.iter() {
                let input_labels = super::super::constrain_sibling_order(
                    circuit,
                    cur_label,
                    cur_node.sibling1,
                    cur_node.sibling2,
                    cur_node.is_left_child,
                    cur_node.is_right_child,
                )?;
                // BUG: is_zero_vars computed but never used — all-zero subtrees
                // are not handled and the index is never checked.
                let _is_zero_vars = [
                    circuit.is_zero(input_labels[0])?,
                    circuit.is_zero(input_labels[1])?,
                    circuit.is_zero(input_labels[2])?,
                ];
                cur_label = RescueDigestGadget::digest(circuit, &input_labels)?;
            }
            Ok(cur_label)
        }?;
        circuit.is_equal(computed_commitment_var, commitment_var)
    }

    /// Old `create_non_membership_proof_variable` — filters out path levels
    /// where all siblings are empty (the absent-subtree shortcut), which
    /// shortens the proof and breaks the index reconstruction added by the fix.
    fn buggy_create_non_membership_proof_variable<F: RescueParameter>(
        circuit: &mut PlonkCircuit<F>,
        pos: &BigUint,
        merkle_proof: &MerkleTreeProof<F>,
    ) -> Result<Merkle3AryProofVar, CircuitError> {
        let path = <BigUint as ToTraversalPath<3>>::to_traversal_path(pos, merkle_proof.height());

        let nodes = path
            .iter()
            .zip(merkle_proof.path_values().iter())
            .filter(|(_, v)| !v.is_empty()) // BUG: drops empty-sibling levels
            .map(|(branch, siblings)| {
                Ok(Merkle3AryNodeVar {
                    sibling1: circuit.create_variable(siblings[0])?,
                    sibling2: circuit.create_variable(siblings[1])?,
                    is_left_child: circuit.create_boolean_variable(branch == &0)?,
                    is_right_child: circuit.create_boolean_variable(branch == &2)?,
                })
            })
            .collect::<Result<Vec<Merkle3AryNodeVar>, CircuitError>>()?;

        for node in nodes.iter() {
            let left_plus_right =
                circuit.add(node.is_left_child.into(), node.is_right_child.into())?;
            circuit.enforce_bool(left_plus_right)?;
        }

        Ok(Merkle3AryProofVar { node_vars: nodes })
    }

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

        assert!(
            SparseMerkleTree::<F>::non_membership_verify(commitment, &uid, &proof)
                .unwrap()
                .is_ok()
        );

        // Circuit computation with a MT
        let non_elem_idx_var = circuit.create_variable(uid.clone().into()).unwrap();
        let proof_var =
            UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::create_non_membership_proof_variable(
                &mut circuit,
                &uid,
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

    /// Regression test for the index-forgery soundness bug fixed in PR #862.
    ///
    /// Setup: a height-2 arity-3 tree holds one element at index 1.
    ///   index 1 → base-3 path [1, 0]  (present in tree)
    ///   index 5 → base-3 path [2, 1]  (absent from tree)
    ///
    /// The attack: take the valid non-membership proof for absent index 5 and
    /// present it in-circuit as a non-membership proof for present index 1.
    /// The commitment check passes (the proof for index 5 is structurally
    /// valid), so the old code accepted it — falsely "proving" that an element
    /// which IS in the tree is absent.
    ///
    /// The test has two halves:
    ///  1. Runs the forgery through `buggy_is_non_member` (the old impl) and
    ///     asserts the circuit IS satisfied — confirming the bug existed.
    ///  2. Runs the same forgery through the fixed
    ///     `enforce_non_membership_proof` and asserts the circuit is NOT
    ///     satisfied — confirming the fix works.
    #[test]
    fn test_non_membership_proof_index_forgery() {
        test_index_forgery_helper::<FqEd254>();
        test_index_forgery_helper::<FqEd377>();
        test_index_forgery_helper::<FqEd381>();
        test_index_forgery_helper::<FqEd381b>();
        test_index_forgery_helper::<Fq377>();
    }

    fn test_index_forgery_helper<F: RescueParameter>() {
        let present = BigUint::from(1u64); // IS in the tree
        let absent = BigUint::from(5u64); // is NOT in the tree

        let mut hashmap = HashMap::new();
        hashmap.insert(present.clone(), F::from(42u64));
        let mt = SparseMerkleTree::<F>::from_kv_set(2, &hashmap).unwrap();
        let commitment = mt.commitment();

        // Confirm the native layer is correct.
        assert!(mt.universal_lookup(&present).expect_ok().is_ok());
        let proof_for_absent = mt.universal_lookup(&absent).expect_not_found().unwrap();
        assert!(
            SparseMerkleTree::<F>::non_membership_verify(commitment, &absent, &proof_for_absent)
                .unwrap()
                .is_ok(),
            "native non-membership verify must accept a valid proof"
        );

        // ── Half 1: old (buggy) implementation ──────────────────────────────
        // Use `buggy_create_non_membership_proof_variable` (drops empty-sibling
        // levels) and `buggy_is_non_member` (ignores non_elem_idx_var).
        // The commitment check alone passes because the proof for index 5 is
        // structurally valid.  The circuit should be satisfiable — that is the
        // bug we are documenting.
        {
            let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
            let forged_idx_var = circuit.create_variable(present.clone().into()).unwrap();
            let proof_var = buggy_create_non_membership_proof_variable(
                &mut circuit,
                &absent,
                &proof_for_absent,
            )
            .unwrap();
            let commitment_var =
                MerkleTreeGadget::<SparseMerkleTree<F>>::create_commitment_variable(
                    &mut circuit,
                    &commitment,
                )
                .unwrap();

            let result =
                buggy_is_non_member(&mut circuit, forged_idx_var, &proof_var, commitment_var)
                    .unwrap();
            circuit.enforce_true(result.into()).unwrap();

            assert!(
                circuit.check_circuit_satisfiability(&[]).is_ok(),
                "buggy implementation must incorrectly accept the index forgery"
            );
        }

        // ── Half 2: fixed implementation ────────────────────────────────────
        // Same forgery attempt, but through the fixed trait implementation.
        // The index-consistency check reconstructs base-3(path) = 5 and
        // compares it with non_elem_idx_var = 1 → mismatch → circuit fails.
        {
            let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
            let forged_idx_var = circuit.create_variable(present.clone().into()).unwrap();
            let proof_var = UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::create_non_membership_proof_variable(
                &mut circuit,
                &absent,
                &proof_for_absent,
            )
            .unwrap();
            let commitment_var =
                MerkleTreeGadget::<SparseMerkleTree<F>>::create_commitment_variable(
                    &mut circuit,
                    &commitment,
                )
                .unwrap();

            UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::enforce_non_membership_proof(
                &mut circuit,
                forged_idx_var,
                &proof_var,
                commitment_var,
            )
            .unwrap();

            assert!(
                circuit.check_circuit_satisfiability(&[]).is_err(),
                "fixed implementation must reject the index forgery"
            );
        }
    }
}
