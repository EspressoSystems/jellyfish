// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of an append-only, 3-ary Merkle tree, instantiated
//! with a Rescue hash function.

use crate::{
    circuit::merkle_tree::DigestAlgorithmGadget,
    merkle_tree::{
        internal::MerkleNode, prelude::RescueMerkleTree, MerkleTreeScheme, ToTraversalPath,
    },
    rescue::RescueParameter,
};
use ark_std::{string::ToString, vec::Vec};
use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};
type NodeVal<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::NodeValue;
type MembershipProof<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::MembershipProof;
use typenum::U3;

use super::{
    constrain_sibling_order, Merkle3AryMembershipProofVar, Merkle3AryNodeVar, MerkleTreeGadget,
    RescueDigestGadget,
};

impl<F> MerkleTreeGadget<RescueMerkleTree<F>> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    type MembershipProofVar = Merkle3AryMembershipProofVar;

    type DigestGadget = RescueDigestGadget;

    fn create_membership_proof_variable(
        &mut self,
        merkle_proof: &MembershipProof<F>,
    ) -> Result<Merkle3AryMembershipProofVar, CircuitError> {
        let path = <u64 as ToTraversalPath<U3>>::to_traversal_path(
            &merkle_proof.pos,
            merkle_proof.tree_height() - 1,
        );

        let elem = match merkle_proof.elem() {
            Some(elem) => elem,
            None => {
                return Err(CircuitError::InternalError(
                    "The proof doesn't contain a leaf element".to_string(),
                ))
            },
        };

        let elem_var = self.create_variable(*elem)?;

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

        Ok(Merkle3AryMembershipProofVar {
            node_vars: nodes,
            elem_var,
        })
    }

    fn create_root_variable(&mut self, root: NodeVal<F>) -> Result<Variable, CircuitError> {
        self.create_variable(root)
    }

    fn is_member(
        &mut self,
        elem_idx_var: Variable,
        proof_var: Merkle3AryMembershipProofVar,
        root_var: Variable,
    ) -> Result<BoolVar, CircuitError> {
        let computed_root_var = {
            let proof_var = &proof_var;

            // elem label = H(0, uid, elem)
            let mut cur_label =
                Self::DigestGadget::digest_leaf(self, elem_idx_var, proof_var.elem_var)?;
            for cur_node in proof_var.node_vars.iter() {
                let input_labels = constrain_sibling_order(
                    self,
                    cur_label,
                    cur_node.sibling1,
                    cur_node.sibling2,
                    cur_node.is_left_child,
                    cur_node.is_right_child,
                )?;
                // check that the left child's label is non-zero
                self.non_zero_gate(input_labels[0])?;
                cur_label = Self::DigestGadget::digest(self, &input_labels)?;
            }
            Ok(cur_label)
        }?;
        self.is_equal(root_var, computed_root_var)
    }

    fn enforce_membership_proof(
        &mut self,
        elem_idx_var: Variable,
        proof_var: Merkle3AryMembershipProofVar,
        expected_root_var: Variable,
    ) -> Result<(), CircuitError> {
        let bool_val = MerkleTreeGadget::<RescueMerkleTree<F>>::is_member(
            self,
            elem_idx_var,
            proof_var,
            expected_root_var,
        )?;
        self.enforce_true(bool_val.into())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuit::merkle_tree::{
            constrain_sibling_order, rescue_merkle_tree::Merkle3AryMembershipProofVar,
            MerkleTreeGadget,
        },
        merkle_tree::{
            internal::MerkleNode, prelude::RescueMerkleTree, MerkleCommitment, MerkleTreeScheme,
        },
        rescue::RescueParameter,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::{boxed::Box, vec, vec::Vec};
    use jf_relation::{Circuit, PlonkCircuit, Variable};

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

            let out_vars =
                constrain_sibling_order(circuit, node, sib1, sib2, node_is_left, node_is_right)
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
            let mut prng = jf_utils::test_rng();
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
    fn test_mt_gadget() {
        test_mt_gadget_helper::<FqEd254>();
        test_mt_gadget_helper::<FqEd377>();
        test_mt_gadget_helper::<FqEd381>();
        test_mt_gadget_helper::<FqEd381b>();
        test_mt_gadget_helper::<Fq377>();
    }

    fn test_mt_gadget_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        // Happy path

        // An elemement we care about is inserted in position 2
        let uid = 2u64;
        let elem = F::from(310_u64);

        // native computation with a MT
        let elements = vec![F::from(1_u64), F::from(2_u64), elem];
        let mt = RescueMerkleTree::<F>::from_elems(1, elements).unwrap();
        let expected_root = mt.commitment().digest();
        let (retrieved_elem, proof) = mt.lookup(uid).expect_ok().unwrap();
        assert_eq!(retrieved_elem, elem);

        // Circuit computation with a MT
        let elem_idx_var: Variable = circuit.create_variable(uid.into()).unwrap();
        let proof_var: Merkle3AryMembershipProofVar =
            MerkleTreeGadget::<RescueMerkleTree<F>>::create_membership_proof_variable(
                &mut circuit,
                &proof,
            )
            .unwrap();
        let root_var = MerkleTreeGadget::<RescueMerkleTree<F>>::create_root_variable(
            &mut circuit,
            expected_root,
        )
        .unwrap();

        MerkleTreeGadget::<RescueMerkleTree<F>>::enforce_membership_proof(
            &mut circuit,
            elem_idx_var,
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
        let elem_idx_var: Variable = circuit.create_variable(uid.into()).unwrap();

        let mut bad_proof = proof.clone();

        if let MerkleNode::Branch { value: _, children } = &mut bad_proof.proof[1] {
            children[0] = Box::new(MerkleNode::Leaf {
                value: F::zero(),
                pos: 0,
                elem: F::one(),
            });
        }
        let path_vars: Merkle3AryMembershipProofVar =
            MerkleTreeGadget::<RescueMerkleTree<F>>::create_membership_proof_variable(
                &mut circuit,
                &bad_proof,
            )
            .unwrap();
        let root_var = MerkleTreeGadget::<RescueMerkleTree<F>>::create_root_variable(
            &mut circuit,
            expected_root,
        )
        .unwrap();

        MerkleTreeGadget::<RescueMerkleTree<F>>::enforce_membership_proof(
            &mut circuit,
            elem_idx_var,
            path_vars,
            root_var,
        )
        .unwrap();

        // Circuit does not verify because a left node value is 0
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
