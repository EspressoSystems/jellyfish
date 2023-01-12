// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of a sparse, 3-ary Merkle tree, instantiated
//! with a Rescue hash function.

use crate::{
    circuit::rescue::RescueNativeGadget,
    merkle_tree::{
        internal::MerkleNode, prelude::RescueSparseMerkleTree, MerkleTreeScheme, ToTraversalPath,
    },
    rescue::RescueParameter,
};
use ark_std::{string::ToString, vec::Vec};
use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};

type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;

type NodeVal<F> = <SparseMerkleTree<F> as MerkleTreeScheme>::NodeValue;
type MembershipProof<F> = <SparseMerkleTree<F> as MerkleTreeScheme>::MembershipProof;
use num_bigint::BigUint;
use typenum::U3;

use super::{
    Merkle3AryMembershipProofVar, Merkle3AryNodeVar, Merkle3AryNonMembershipProofVar,
    MerkleTreeGadget, MerkleTreeHelperGadget, UniversalMerkleTreeGadget,
};

impl<F> UniversalMerkleTreeGadget<SparseMerkleTree<F>> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    type NonMembershipProofVar = Merkle3AryNonMembershipProofVar;

    fn is_non_member(
        &mut self,
        non_leaf_idx_var: Variable,
        proof_var: Self::NonMembershipProofVar,
        root_var: Variable,
    ) -> Result<BoolVar, CircuitError> {
        // constrain that the element's index is part of the proof
        self.enforce_equal(proof_var.pos_var, non_leaf_idx_var)?;
        let computed_root_var = self.compute_merkle_root_for_empty(&proof_var)?;
        self.is_equal(computed_root_var, root_var)
    }

    fn enforce_non_membership_proof(
        &mut self,
        non_leaf_idx_var: Variable,
        proof_var: Self::NonMembershipProofVar,
        expected_root_var: Variable,
    ) -> Result<(), CircuitError> {
        let bool_val = self.is_non_member(non_leaf_idx_var, proof_var, expected_root_var)?;
        self.enforce_true(bool_val.into())
    }

    fn create_non_membership_proof_variable(
        &mut self,
        merkle_proof: &<SparseMerkleTree<F> as MerkleTreeScheme>::MembershipProof,
    ) -> Result<Self::NonMembershipProofVar, CircuitError> {
        let path = <BigUint as ToTraversalPath<U3>>::to_traversal_path(
            &merkle_proof.pos,
            merkle_proof.tree_height() - 1,
        );

        let nodes = path
            .iter()
            .zip(merkle_proof.proof.iter().skip(1))
            .filter_map(|(branch, node)| match node {
                MerkleNode::Branch { value: _, children } => Some((children, branch)),
                _ => None,
            })
            .map(|(children, branch)| {
                Ok(Merkle3AryNodeVar {
                    sibling1: self.create_variable(children[0].value())?,
                    sibling2: self.create_variable(children[1].value())?,
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

        let pos = self.create_variable(merkle_proof.pos.clone().into())?;

        Ok(Self::NonMembershipProofVar {
            node_vars: nodes,
            pos_var: pos,
        })
    }
}

impl<F> MerkleTreeGadget<SparseMerkleTree<F>> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    type MembershipProofVar = Merkle3AryMembershipProofVar;

    fn create_membership_proof_variable(
        &mut self,
        merkle_proof: &MembershipProof<F>,
    ) -> Result<Self::MembershipProofVar, CircuitError> {
        MerkleTreeHelperGadget::<SparseMerkleTree<F>>::constrain_membership_proof(
            self,
            merkle_proof,
        )
    }

    fn create_root_variable(&mut self, root: NodeVal<F>) -> Result<Variable, CircuitError> {
        self.create_variable(root)
    }

    fn is_member(
        &mut self,
        leaf_idx_var: Variable,
        proof_var: Self::MembershipProofVar,
        root_var: Variable,
    ) -> Result<BoolVar, CircuitError> {
        let computed_root_var = MerkleTreeHelperGadget::<SparseMerkleTree<F>>::compute_merkle_root(
            self,
            leaf_idx_var,
            &proof_var,
        )?;
        self.is_equal(root_var, computed_root_var)
    }

    fn enforce_membership_proof(
        &mut self,
        leaf_idx_var: Variable,
        proof_var: Self::MembershipProofVar,
        expected_root_var: Variable,
    ) -> Result<(), CircuitError> {
        let bool_val = MerkleTreeGadget::<SparseMerkleTree<F>>::is_member(
            self,
            leaf_idx_var,
            proof_var,
            expected_root_var,
        )?;
        self.enforce_true(bool_val.into())
    }
}

trait SparseMerkleTreeHelperGadget<F: RescueParameter> {
    /// Computes the merkle root based on an empty leaf element and a
    /// merkle path.
    /// * `path_vars` - variables corresponding to the Merkle path.
    /// * `return` - variable corresponding to the root value of the Merkle
    ///   tree.
    fn compute_merkle_root_for_empty(
        &mut self,
        path_vars: &Merkle3AryNonMembershipProofVar,
    ) -> Result<Variable, CircuitError>;
}

impl<F: RescueParameter> SparseMerkleTreeHelperGadget<F> for PlonkCircuit<F> {
    fn compute_merkle_root_for_empty(
        &mut self,
        path_vars: &Merkle3AryNonMembershipProofVar,
    ) -> Result<Variable, CircuitError> {
        let mut cur_label = self.zero();
        for cur_node in path_vars.node_vars.iter() {
            let input_labels =
                MerkleTreeHelperGadget::<SparseMerkleTree<F>>::constrain_sibling_order(
                    self,
                    cur_label,
                    cur_node.sibling1,
                    cur_node.sibling2,
                    cur_node.is_left_child,
                    cur_node.is_right_child,
                )?;
            // check that the left child's label is non-zero
            self.non_zero_gate(input_labels[0])?;
            cur_label =
                RescueNativeGadget::<F>::rescue_sponge_no_padding(self, &input_labels, 1)?[0];
        }
        Ok(cur_label)
    }
}

impl<F: RescueParameter> MerkleTreeHelperGadget<SparseMerkleTree<F>> for PlonkCircuit<F> {
    type MembershipProofVar = Merkle3AryMembershipProofVar;

    fn constrain_sibling_order(
        &mut self,
        node: Variable,
        sib1: Variable,
        sib2: Variable,
        node_is_left: BoolVar,
        node_is_right: BoolVar,
    ) -> Result<[Variable; 3], CircuitError> {
        let one = F::one();
        let left_node = self.conditional_select(node_is_left, sib1, node)?;
        let right_node = self.conditional_select(node_is_right, sib2, node)?;
        let left_plus_right = self.add(left_node, right_node)?;
        let mid_node = self.lc(
            &[node, sib1, sib2, left_plus_right],
            &[one, one, one, one.neg()],
        )?;
        Ok([left_node, mid_node, right_node])
    }

    fn constrain_membership_proof(
        &mut self,
        merkle_proof: &MembershipProof<F>,
    ) -> Result<Self::MembershipProofVar, CircuitError> {
        let path = <BigUint as ToTraversalPath<U3>>::to_traversal_path(
            &merkle_proof.pos,
            merkle_proof.tree_height() - 1,
        );

        let leaf_elem = match merkle_proof.elem() {
            Some(elem) => elem,
            None => {
                return Err(CircuitError::InternalError(
                    "The proof doesn't contain a leaf element".to_string(),
                ))
            },
        };

        let leaf = self.create_variable(*leaf_elem)?;

        let nodes = path
            .iter()
            .zip(merkle_proof.proof.iter().skip(1))
            .filter_map(|(branch, node)| match node {
                MerkleNode::Branch { value: _, children } => Some((children, branch)),
                _ => None,
            })
            .map(|(children, branch)| {
                Ok(Merkle3AryNodeVar {
                    sibling1: self.create_variable(children[0].value())?,
                    sibling2: self.create_variable(children[1].value())?,
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

        Ok(Self::MembershipProofVar {
            node_vars: nodes,
            leaf_var: leaf,
        })
    }

    fn compute_merkle_root(
        &mut self,
        elem: Variable,
        proof_var: &Self::MembershipProofVar,
    ) -> Result<Variable, CircuitError> {
        let zero_var = self.zero();

        // leaf label = H(0, uid, elem)
        let mut cur_label = RescueNativeGadget::<F>::rescue_sponge_no_padding(
            self,
            &[zero_var, elem, proof_var.leaf_var],
            1,
        )?[0];
        for cur_node in proof_var.node_vars.iter() {
            let input_labels =
                MerkleTreeHelperGadget::<SparseMerkleTree<F>>::constrain_sibling_order(
                    self,
                    cur_label,
                    cur_node.sibling1,
                    cur_node.sibling2,
                    cur_node.is_left_child,
                    cur_node.is_right_child,
                )?;
            // check that the left child's label is non-zero
            self.non_zero_gate(input_labels[0])?;
            cur_label =
                RescueNativeGadget::<F>::rescue_sponge_no_padding(self, &input_labels, 1)?[0];
        }
        Ok(cur_label)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuit::merkle_tree::{
            sparse_merkle_tree::MerkleTreeHelperGadget, MerkleTreeGadget, UniversalMerkleTreeGadget,
        },
        merkle_tree::{
            internal::MerkleNode, prelude::RescueSparseMerkleTree, MerkleCommitment,
            MerkleTreeScheme, UniversalMerkleTreeScheme,
        },
        rescue::RescueParameter,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::{boxed::Box, vec, vec::Vec};
    use hashbrown::HashMap;
    use jf_relation::{Circuit, PlonkCircuit, Variable};
    use num_bigint::BigUint;

    type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;

    #[test]
    fn test_permute() {
        test_permute_helper::<FqEd254>();
        test_permute_helper::<FqEd377>();
        test_permute_helper::<FqEd381>();
        test_permute_helper::<FqEd381b>();
        test_permute_helper::<Fq377>();
    }

    fn test_permute_helper<F: RescueParameter>() {
        fn check_permute<F: RescueParameter>(
            circuit: &mut PlonkCircuit<F>,
            is_left: bool,
            is_right: bool,
            input_vars: &[Variable],
            expected_output_vars: &[Variable],
        ) {
            let zero = F::zero();

            let node_is_left = circuit.create_boolean_variable(is_left).unwrap();
            let node_is_right = circuit.create_boolean_variable(is_right).unwrap();

            let node = input_vars[0];
            let sib1 = input_vars[1];
            let sib2 = input_vars[2];

            let out_vars = MerkleTreeHelperGadget::<SparseMerkleTree<F>>::constrain_sibling_order(
                circuit,
                node,
                sib1,
                sib2,
                node_is_left,
                node_is_right,
            )
            .unwrap();

            let output: Vec<F> = out_vars[..]
                .iter()
                .map(|&idx| circuit.witness(idx).unwrap())
                .collect();

            let expected_output: Vec<F> = expected_output_vars
                .iter()
                .map(|v| circuit.witness(*v).unwrap())
                .collect();

            assert_eq!(output, expected_output);

            // Check constraints
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            *circuit.witness_mut(sib1) = zero;
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }

        fn gen_permutation_circuit_and_vars<F: RescueParameter>(
        ) -> (PlonkCircuit<F>, Variable, Variable, Variable) {
            let mut circuit = PlonkCircuit::new_turbo_plonk();
            let mut prng = ark_std::test_rng();
            let node = circuit.create_variable(F::rand(&mut prng)).unwrap();
            let sib1 = circuit.create_variable(F::rand(&mut prng)).unwrap();
            let sib2 = circuit.create_variable(F::rand(&mut prng)).unwrap();

            (circuit, node, sib1, sib2)
        }

        let (mut circuit, node, sib1, sib2) = gen_permutation_circuit_and_vars::<F>();
        check_permute(
            &mut circuit,
            false,
            true,
            &[node, sib1, sib2],
            &[sib1, sib2, node],
        );

        let (mut circuit, node, sib1, sib2) = gen_permutation_circuit_and_vars::<F>();
        check_permute(
            &mut circuit,
            true,
            false,
            &[node, sib1, sib2],
            &[node, sib1, sib2],
        );

        let (mut circuit, node, sib1, sib2) = gen_permutation_circuit_and_vars::<F>();
        check_permute(
            &mut circuit,
            false,
            false,
            &[node, sib1, sib2],
            &[sib1, node, sib2],
        );
    }

    #[test]
    fn test_sparse_mt_gadget() {
        test_membership_helper::<FqEd254>();
        test_non_membership_helper::<FqEd254>();
        test_membership_helper::<FqEd377>();
        test_membership_helper::<FqEd381>();
        test_membership_helper::<FqEd381b>();
        test_membership_helper::<Fq377>();
    }

    fn test_membership_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        // Happy path

        // A leaf we care about is inserted in position 2
        let uid = BigUint::from(2u64);
        let elem = F::from(310_u64);

        // native computation with a MT
        let elements = vec![F::from(1_u64), F::from(2_u64), elem];
        let mt = SparseMerkleTree::<F>::from_elems(1, elements).unwrap();
        let expected_root = mt.commitment().digest();
        let (retrieved_elem, proof) = mt.lookup(&uid).expect_ok().unwrap();
        assert_eq!(retrieved_elem, elem);

        // Circuit computation with a MT
        let leaf_idx_var = circuit.create_variable(uid.clone().into()).unwrap();
        let proof_var = MerkleTreeGadget::<SparseMerkleTree<F>>::create_membership_proof_variable(
            &mut circuit,
            &proof,
        )
        .unwrap();
        let root_var = MerkleTreeGadget::<SparseMerkleTree<F>>::create_root_variable(
            &mut circuit,
            expected_root,
        )
        .unwrap();

        MerkleTreeGadget::<SparseMerkleTree<F>>::enforce_membership_proof(
            &mut circuit,
            leaf_idx_var,
            proof_var,
            root_var,
        )
        .unwrap();

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(root_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Bad path:
        // The circuit cannot be satisfied if an internal node has a left child with
        // zero value.
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let leaf_idx_var = circuit.create_variable(uid.into()).unwrap();

        let mut bad_proof = proof.clone();

        if let MerkleNode::Branch { value: _, children } = &mut bad_proof.proof[1] {
            children[0] = Box::new(MerkleNode::Leaf {
                value: F::zero(),
                pos: BigUint::from(0u64),
                elem: F::one(),
            });
        }
        let path_vars = MerkleTreeGadget::<SparseMerkleTree<F>>::create_membership_proof_variable(
            &mut circuit,
            &bad_proof,
        )
        .unwrap();
        let root_var = MerkleTreeGadget::<SparseMerkleTree<F>>::create_root_variable(
            &mut circuit,
            expected_root,
        )
        .unwrap();

        MerkleTreeGadget::<SparseMerkleTree<F>>::enforce_membership_proof(
            &mut circuit,
            leaf_idx_var.clone(),
            path_vars.clone(),
            root_var,
        )
        .unwrap();

        // Circuit does not verify because a left node value is 0
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    fn test_non_membership_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        // Happy path

        // A leaf we care about is inserted in position 2
        let uid = BigUint::from(3u64);

        // native computation with a MT
        let mut hashmap = HashMap::new();
        hashmap.insert(BigUint::from(1u64), F::from(2u64));
        hashmap.insert(BigUint::from(2u64), F::from(2u64));
        hashmap.insert(BigUint::from(1u64), F::from(3u64));
        let mt = SparseMerkleTree::<F>::from_kv_set(2, &hashmap).unwrap();
        let expected_root = mt.commitment().digest();

        // proof of non-membership
        let proof = mt.universal_lookup(&uid).expect_not_found().unwrap();

        // Circuit computation with a MT
        let non_leaf_idx_var = circuit.create_variable(uid.into()).unwrap();
        let proof_var =
            UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::create_non_membership_proof_variable(
                &mut circuit,
                &proof,
            )
            .unwrap();

        let root_var = MerkleTreeGadget::<SparseMerkleTree<F>>::create_root_variable(
            &mut circuit,
            expected_root,
        )
        .unwrap();

        UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::enforce_non_membership_proof(
            &mut circuit,
            non_leaf_idx_var,
            proof_var,
            root_var,
        )
        .unwrap();

        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(root_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Bad path:
        // The circuit cannot be satisfied if we try to prove non-membership of an
        // actual leaf.
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let leaf_idx_var = circuit.create_variable(2u64.into()).unwrap();

        let path_vars =
            UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::create_non_membership_proof_variable(
                &mut circuit,
                &proof,
            )
            .unwrap();

        let root_var = MerkleTreeGadget::<SparseMerkleTree<F>>::create_root_variable(
            &mut circuit,
            expected_root,
        )
        .unwrap();

        UniversalMerkleTreeGadget::<SparseMerkleTree<F>>::enforce_non_membership_proof(
            &mut circuit,
            leaf_idx_var.clone(),
            path_vars.clone(),
            root_var,
        )
        .unwrap();

        // Circuit does not verify because a left node value is 0
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
