// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of an append-only, 3-ary Merkle tree, instantiated
//! with a Rescue hash function.

use crate::{
    circuit::rescue::RescueNativeGadget,
    merkle_tree::{
        internal::MerkleNode, prelude::RescueMerkleTree, MerkleTreeScheme, ToTraversalPath,
    },
    rescue::RescueParameter,
};
use ark_std::vec::Vec;
use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};

type NodeVal<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::NodeValue;
type MembershipProof<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::MembershipProof;
type Element<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::Element;
type Index<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::Index;
use typenum::U3;

use super::{
    LeafVar, MembershipProofBooleanEncoding, Merkle3AryMembershipProofVar, Merkle3AryNodeVar,
    MerkleNodeBooleanEncoding, MerkleTreeGadget, MerkleTreeHelperGadget,
};

impl<F: RescueParameter> MembershipProofBooleanEncoding<RescueMerkleTree<F>> {
    fn new(nodes: &[MerkleNodeBooleanEncoding<RescueMerkleTree<F>>]) -> Self {
        MembershipProofBooleanEncoding {
            nodes: nodes.to_vec(),
        }
    }
}

impl<F> MerkleTreeGadget<RescueMerkleTree<F>> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    type LeafVar = LeafVar;
    type MerklePathVar = Merkle3AryMembershipProofVar;

    fn create_leaf_variable(
        &mut self,
        pos: Index<F>,
        elem: Element<F>,
    ) -> Result<LeafVar, CircuitError> {
        let committed_elem = LeafVar {
            uid: self.create_variable(pos.into())?,
            elem: self.create_variable(elem)?,
        };
        Ok(committed_elem)
    }

    fn create_membership_proof_variable(
        &mut self,
        merkle_proof: &MembershipProof<F>,
    ) -> Result<Merkle3AryMembershipProofVar, CircuitError> {
        // Encode Merkle path nodes positions with boolean variables
        let merkle_path = MembershipProofBooleanEncoding::from(merkle_proof);

        <PlonkCircuit<F> as MerkleTreeHelperGadget<RescueMerkleTree<F>>>::constrain_membership_proof(
            self,
            &merkle_path,
            merkle_proof.pos,
        )
    }

    fn create_root_variable(&mut self, root: NodeVal<F>) -> Result<Variable, CircuitError> {
        self.create_variable(root)
    }

    fn is_member(
        &mut self,
        elem: LeafVar,
        merkle_proof: Merkle3AryMembershipProofVar,
        merkle_root: Variable,
    ) -> Result<BoolVar, CircuitError> {
        let root_var =
            <PlonkCircuit<F> as MerkleTreeHelperGadget<RescueMerkleTree<F>>>::compute_merkle_root(
                self,
                elem,
                &merkle_proof,
            )?;
        self.is_equal(root_var, merkle_root)
    }

    fn enforce_membership_proof(
        &mut self,
        elem: LeafVar,
        merkle_proof: Merkle3AryMembershipProofVar,
        expected_merkle_root: Variable,
    ) -> Result<(), CircuitError> {
        let bool_val = <PlonkCircuit<F> as MerkleTreeGadget<RescueMerkleTree<F>>>::is_member(
            self,
            elem,
            merkle_proof,
            expected_merkle_root,
        )?;
        self.enforce_true(bool_val.into())
    }
}

impl<F: RescueParameter> From<&MembershipProof<F>>
    for MembershipProofBooleanEncoding<RescueMerkleTree<F>>
{
    fn from(proof: &MembershipProof<F>) -> Self {
        let path =
            <u64 as ToTraversalPath<U3>>::to_traversal_path(&proof.pos, proof.tree_height() - 1);

        let nodes: Vec<MerkleNodeBooleanEncoding<RescueMerkleTree<F>>> = path
            .iter()
            .zip(proof.proof.iter().skip(1))
            .filter_map(|(branch, node)| match node {
                MerkleNode::Branch { value: _, children } => Some(MerkleNodeBooleanEncoding::new(
                    children[0].value(),
                    children[1].value(),
                    branch == &0,
                    branch == &2,
                )),
                _ => None,
            })
            .collect();

        Self::new(&nodes)
    }
}

impl<F: RescueParameter> MerkleTreeHelperGadget<RescueMerkleTree<F>> for PlonkCircuit<F> {
    type MembershipProofBooleanEncoding = MembershipProofBooleanEncoding<RescueMerkleTree<F>>;

    type MembershipProofVar = Merkle3AryMembershipProofVar;

    fn permute(
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
        merkle_path: &MembershipProofBooleanEncoding<RescueMerkleTree<F>>,
        _pos: u64,
    ) -> Result<Merkle3AryMembershipProofVar, CircuitError> {
        // Setup node variables
        let nodes = merkle_path
            .nodes
            .clone()
            .into_iter()
            .map(|node| -> Result<Merkle3AryNodeVar, CircuitError> {
                Ok(Merkle3AryNodeVar {
                    sibling1: self.create_variable(node.sibling1)?,
                    sibling2: self.create_variable(node.sibling2)?,
                    is_left_child: self.create_boolean_variable(node.is_left_child)?,
                    is_right_child: self.create_boolean_variable(node.is_right_child)?,
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
            nodes,
            // position is only used for universal MT
            pos: Variable::default(),
        })
    }

    fn compute_merkle_root(
        &mut self,
        elem: LeafVar,
        path_vars: &Merkle3AryMembershipProofVar,
    ) -> Result<Variable, CircuitError> {
        let zero_var = self.zero();

        // leaf label = H(0, uid, elem)
        let mut cur_label = RescueNativeGadget::<F>::rescue_sponge_no_padding(
            self,
            &[zero_var, elem.uid, elem.elem],
            1,
        )?[0];
        for cur_node in path_vars.nodes.iter() {
            let input_labels =
                <PlonkCircuit<F> as MerkleTreeHelperGadget<RescueMerkleTree<F>>>::permute(
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
            rescue_merkle_tree::{
                LeafVar, MembershipProofBooleanEncoding, Merkle3AryMembershipProofVar,
                MerkleNodeBooleanEncoding, MerkleTreeHelperGadget,
            },
            MerkleTreeGadget,
        },
        merkle_tree::{
            internal::MerkleNode,
            prelude::{RescueHash, RescueMerkleTree},
            DigestAlgorithm, MerkleCommitment, MerkleTreeScheme,
        },
        rescue::RescueParameter,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::UniformRand;
    use ark_std::{boxed::Box, test_rng, vec, vec::Vec};
    use jf_relation::{Circuit, PlonkCircuit, Variable};

    #[test]
    fn test_constrain_merkle_path() {
        test_constrain_merkle_path_helper::<FqEd254>();
        test_constrain_merkle_path_helper::<FqEd377>();
        test_constrain_merkle_path_helper::<FqEd381>();
        test_constrain_merkle_path_helper::<FqEd381b>();
        test_constrain_merkle_path_helper::<Fq377>();
    }
    fn test_constrain_merkle_path_helper<F: RescueParameter>() {
        fn check_merkle_path<F: RescueParameter>(
            is_left_child: bool,
            is_right_child: bool,
            accept: bool,
        ) {
            let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
            let zero = F::zero();
            let one = F::one();
            let node = MerkleNodeBooleanEncoding::new(one, zero, is_left_child, is_right_child);
            let path = MembershipProofBooleanEncoding::new(&[node]);
            let _ = <PlonkCircuit<F> as MerkleTreeHelperGadget<RescueMerkleTree<F>>>::constrain_membership_proof(&mut circuit, &path, 0);
            if accept {
                assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
            } else {
                assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            }
        }
        // Happy path:
        // `is_left_child`,`is_right_child` and `is_left_child + is_right_child` are
        // boolean
        check_merkle_path::<F>(true, false, true);
        check_merkle_path::<F>(false, true, true);
        check_merkle_path::<F>(false, false, true);

        // Circuit cannot be satisfied when `is_left_child + is_right_child` is not
        // boolean
        check_merkle_path::<F>(true, true, false);
    }

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
                <PlonkCircuit<F> as MerkleTreeHelperGadget<RescueMerkleTree<F>>>::permute(
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
    fn test_bool_encoding_from_merkle_proof() {
        let rng = &mut test_rng();
        let elements = vec![FqEd254::rand(rng); 3];
        let mt = RescueMerkleTree::<FqEd254>::from_elems(1, elements.clone()).unwrap();

        let tests = vec![
            (0u64, true, false),
            (1u64, false, false),
            (2u64, false, true),
        ];

        for (i, left, right) in tests {
            let (_elem, proof) = mt.lookup(i).expect_ok().unwrap();
            assert_eq!(proof.tree_height(), 2);

            let expected_bool_node = MerkleNodeBooleanEncoding::<RescueMerkleTree<FqEd254>> {
                sibling1: RescueHash::digest_leaf(&0, &elements[0].clone()),
                sibling2: RescueHash::digest_leaf(&1, &elements[1].clone()),
                is_left_child: left,
                is_right_child: right,
            };

            let expected_bool_path = MembershipProofBooleanEncoding::new(&[expected_bool_node]);
            let bool_path = MembershipProofBooleanEncoding::from(&proof);

            assert_eq!(bool_path, expected_bool_path);
        }
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

        // A leaf we care about is inserted in position 2
        let uid = 2u64;
        let elem = F::from(310_u64);

        // native computation with a MT
        let elements = vec![F::from(1_u64), F::from(2_u64), elem];
        let mt = RescueMerkleTree::<F>::from_elems(1, elements).unwrap();
        let expected_root = mt.commitment().digest();
        let (retrieved_elem, proof) = mt.lookup(uid).expect_ok().unwrap();
        assert_eq!(retrieved_elem, elem);

        // Circuit computation with a MT
        let leaf_var: LeafVar =
            <PlonkCircuit<F> as MerkleTreeGadget<RescueMerkleTree<F>>>::create_leaf_variable(
                &mut circuit,
                uid,
                elem,
            )
            .unwrap();
        let path_vars: Merkle3AryMembershipProofVar = <PlonkCircuit<F> as MerkleTreeGadget<
            RescueMerkleTree<F>,
        >>::create_membership_proof_variable(
            &mut circuit, &proof
        )
        .unwrap();
        let root_var =
            <PlonkCircuit<F> as MerkleTreeGadget<RescueMerkleTree<F>>>::create_root_variable(
                &mut circuit,
                expected_root,
            )
            .unwrap();

        <PlonkCircuit<F> as MerkleTreeGadget<RescueMerkleTree<F>>>::enforce_membership_proof(
            &mut circuit,
            leaf_var,
            path_vars,
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
        let leaf_var: LeafVar =
            <PlonkCircuit<F> as MerkleTreeGadget<RescueMerkleTree<F>>>::create_leaf_variable(
                &mut circuit,
                uid,
                elem,
            )
            .unwrap();

        let mut bad_proof = proof.clone();

        if let MerkleNode::Branch { value: _, children } = &mut bad_proof.proof[1] {
            children[0] = Box::new(MerkleNode::Leaf {
                value: F::zero(),
                pos: 0,
                elem: F::one(),
            });
        }
        let path_vars: Merkle3AryMembershipProofVar = <PlonkCircuit<F> as MerkleTreeGadget<
            RescueMerkleTree<F>,
        >>::create_membership_proof_variable(
            &mut circuit, &bad_proof
        )
        .unwrap();
        let root_var =
            <PlonkCircuit<F> as MerkleTreeGadget<RescueMerkleTree<F>>>::create_root_variable(
                &mut circuit,
                expected_root,
            )
            .unwrap();

        <PlonkCircuit<F> as MerkleTreeGadget<RescueMerkleTree<F>>>::enforce_membership_proof(
            &mut circuit,
            leaf_var.clone(),
            path_vars.clone(),
            root_var,
        )
        .unwrap();

        // Circuit does not verify because a left node value is 0
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
