// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![allow(missing_docs)]

//! Circuit implementation of an append-only, 3-ary Merkle tree, instantiated
//! with a Rescue hash function.

use crate::{
    circuit::rescue::RescueGadget,
    merkle_tree::{
        internal::MerkleNode, prelude::RescueMerkleTree, MerkleTreeScheme, ToTraversalPath,
    },
    rescue::RescueParameter,
};
use ark_ec::TEModelParameters as Parameters;
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};

type NodeVal<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::NodeValue;
type MembershipProof<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::MembershipProof;
use typenum::U3;

#[derive(PartialEq, Eq, Clone, Debug)]
struct MerkleNodeBooleanEncoding<F: PrimeField + RescueParameter> {
    sibling1: NodeVal<F>,
    sibling2: NodeVal<F>,
    is_left_child: bool,
    is_right_child: bool,
}

impl<F: PrimeField + RescueParameter> MerkleNodeBooleanEncoding<F> {
    fn new(
        sibling1: NodeVal<F>,
        sibling2: NodeVal<F>,
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
struct MembershipProofBooleanEncoding<F: PrimeField + RescueParameter> {
    pub nodes: Vec<MerkleNodeBooleanEncoding<F>>,
}

impl<F: PrimeField + RescueParameter> MembershipProofBooleanEncoding<F> {
    fn new(nodes: &[MerkleNodeBooleanEncoding<F>]) -> Self {
        MembershipProofBooleanEncoding {
            nodes: nodes.to_vec(),
        }
    }
}

impl<F: PrimeField + RescueParameter> From<&MembershipProof<F>>
    for MembershipProofBooleanEncoding<F>
{
    fn from(proof: &MembershipProof<F>) -> Self {
        let path =
            <u64 as ToTraversalPath<U3>>::to_traversal_path(&proof.pos, proof.tree_height() - 1);

        let nodes: Vec<MerkleNodeBooleanEncoding<F>> = path
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

#[derive(Debug)]
/// Circuit variable for a Merkle node.
pub struct MerkleNodeVar {
    pub sibling1: Variable,
    pub sibling2: Variable,
    pub is_left_child: BoolVar,
    pub is_right_child: BoolVar,
}

#[derive(Debug)]
/// Circuit variable for a Merkle authentication path.
pub struct MerklePathVar {
    pub nodes: Vec<MerkleNodeVar>,
}

/// Circuit variable for an accumulated element.
pub struct CommittedElemVar {
    pub uid: Variable,
    pub elem: Variable,
}

/// Circuit variable for a membership proof.
#[derive(Debug)]
pub struct MembershipProofVar {
    pub uid: Variable,
    pub merkle_path: MerklePathVar,
}

impl MembershipProofVar {
    pub fn new<F, P>(
        circuit: &mut PlonkCircuit<F>,
        acc_member_witness: &MembershipProof<F>,
    ) -> Result<Self, CircuitError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F>,
    {
        Ok(Self {
            uid: circuit.create_variable(F::from(acc_member_witness.pos as u64))?,
            merkle_path: circuit.add_merkle_path_variable(acc_member_witness)?,
        })
    }
}
trait MerkleTreeHelperGadget<F: PrimeField + RescueParameter> {
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
    /// * `returns` - list of variables corresponding to the authentication path
    fn constrain_merkle_path(
        &mut self,
        merkle_path: &MembershipProofBooleanEncoding<F>,
    ) -> Result<MerklePathVar, CircuitError>;
}

/// Circuit implementation of a Merkle tree.
pub trait MerkleTreeGadget<F: PrimeField + RescueParameter> {
    /// Wrapper around Circuit.constrain_merkle_path. Adds and checks the
    /// variables related to the Merkle path.
    /// * `merkle_path` - list of node of an authentication path
    /// * `returns` - list of variables corresponding to the authentication path
    fn add_merkle_path_variable(
        &mut self,
        merkle_proof: &MembershipProof<F>,
    ) -> Result<MerklePathVar, CircuitError>;

    /// Computes the merkle root based on some element placed at a leaf and a
    /// merkle path.
    /// * `elem` - variables corresponding to the uid and the element value
    ///   (e.g.: record commitment).
    /// * `path_vars` - variables corresponding to the Merkle path.
    /// * `return` - variable corresponding to the root value of the Merkle
    ///   tree.
    fn compute_merkle_root(
        &mut self,
        elem: CommittedElemVar,
        path_vars: &MerklePathVar,
    ) -> Result<Variable, CircuitError>;
}

impl<F> MerkleTreeGadget<F> for PlonkCircuit<F>
where
    F: PrimeField + RescueParameter,
{
    fn add_merkle_path_variable(
        &mut self,
        merkle_proof: &MembershipProof<F>,
    ) -> Result<MerklePathVar, CircuitError> {
        // Encode Merkle path nodes positions with boolean variables
        let merkle_path = MembershipProofBooleanEncoding::from(merkle_proof);

        self.constrain_merkle_path(&merkle_path)
    }

    fn compute_merkle_root(
        &mut self,
        elem: CommittedElemVar,
        path_vars: &MerklePathVar,
    ) -> Result<Variable, CircuitError> {
        let zero_var = self.zero();

        // leaf label = H(0, uid, arc)
        let mut cur_label = self.rescue_sponge_no_padding(&[zero_var, elem.uid, elem.elem], 1)?[0];
        for cur_node in path_vars.nodes.iter() {
            let input_labels = self.permute(
                cur_label,
                cur_node.sibling1,
                cur_node.sibling2,
                cur_node.is_left_child,
                cur_node.is_right_child,
            )?;
            // check that the left child's label is non-zero
            self.non_zero_gate(input_labels[0])?;
            cur_label = self.rescue_sponge_no_padding(&input_labels, 1)?[0];
        }
        Ok(cur_label)
    }
}

impl<F> MerkleTreeHelperGadget<F> for PlonkCircuit<F>
where
    F: PrimeField + RescueParameter,
{
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

    fn constrain_merkle_path(
        &mut self,
        merkle_path: &MembershipProofBooleanEncoding<F>,
    ) -> Result<MerklePathVar, CircuitError> {
        // Setup node variables
        let nodes = merkle_path
            .nodes
            .clone()
            .into_iter()
            .map(|node| -> Result<MerkleNodeVar, CircuitError> {
                Ok(MerkleNodeVar {
                    sibling1: self.create_variable(node.sibling1)?,
                    sibling2: self.create_variable(node.sibling2)?,
                    is_left_child: self.create_boolean_variable(node.is_left_child)?,
                    is_right_child: self.create_boolean_variable(node.is_right_child)?,
                })
            })
            .collect::<Result<Vec<MerkleNodeVar>, CircuitError>>()?;

        // `is_left_child`, `is_right_child` and `is_left_child+is_right_child` are
        // boolean
        for node in nodes.iter() {
            // Boolean constrain `is_left_child + is_right_child` because a node
            // can either be the left or the right child of its parent
            let left_plus_right =
                self.add(node.is_left_child.into(), node.is_right_child.into())?;
            self.enforce_bool(left_plus_right)?;
        }

        Ok(MerklePathVar { nodes })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuit::merkle_tree::{
            CommittedElemVar, MembershipProofBooleanEncoding, MerkleNodeBooleanEncoding,
            MerkleTreeGadget, MerkleTreeHelperGadget,
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
    use ark_ff::{PrimeField, UniformRand};
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
    fn test_constrain_merkle_path_helper<F: PrimeField + RescueParameter>() {
        fn check_merkle_path<F: PrimeField + RescueParameter>(
            is_left_child: bool,
            is_right_child: bool,
            accept: bool,
        ) {
            let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
            let zero = F::zero();
            let one = F::one();
            let node = MerkleNodeBooleanEncoding::new(one, zero, is_left_child, is_right_child);
            let path = MembershipProofBooleanEncoding::new(&[node]);
            let _ = circuit.constrain_merkle_path(&path);
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

    fn test_permute_helper<F: PrimeField + RescueParameter>() {
        fn check_permute<F: PrimeField + RescueParameter>(
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

            let out_vars = circuit
                .permute(node, sib1, sib2, node_is_left, node_is_right)
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

        fn gen_permutation_circuit_and_vars<F: PrimeField + RescueParameter>(
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

            let expected_bool_node = MerkleNodeBooleanEncoding::<FqEd254> {
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
    fn test_merkle_root() {
        test_merkle_root_helper::<FqEd254>();
        test_merkle_root_helper::<FqEd377>();
        test_merkle_root_helper::<FqEd381>();
        test_merkle_root_helper::<FqEd381b>();
        test_merkle_root_helper::<Fq377>();
    }
    fn test_merkle_root_helper<F: RescueParameter>() {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        //// Happy path

        // 2, because the leaf is inserted in position 2 (see gen_merkle_path_for_test)
        let uid_u64 = 2u64;
        let uid = F::from(uid_u64);
        let comm = F::from(310_u64);

        let uid_var = circuit.create_variable(uid).unwrap();
        let comm_var = circuit.create_variable(comm).unwrap();

        let elem = CommittedElemVar {
            uid: uid_var,
            elem: comm_var,
        };
        let elements = vec![F::from(1_u64), F::from(2_u64), comm];
        let mt = RescueMerkleTree::<F>::from_elems(1, elements).unwrap();
        let expected_root = mt.commitment().digest();
        let (_elem, proof) = mt.lookup(uid_u64).expect_ok().unwrap();

        let path_vars = circuit.add_merkle_path_variable(&proof).unwrap();

        let root_var = circuit.compute_merkle_root(elem, &path_vars).unwrap();

        // Check Merkle root correctness
        let actual_root = circuit.witness(root_var).unwrap();
        assert_eq!(actual_root, expected_root);

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(root_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        //// Bad path:
        //// The circuit cannot be satisfied if an internal node has a left child with
        //// zero value.
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let uid_var = circuit.create_variable(uid).unwrap();
        let comm_var = circuit.create_variable(comm).unwrap();

        let elem = CommittedElemVar {
            uid: uid_var,
            elem: comm_var,
        };

        let mut bad_proof = proof.clone();

        if let MerkleNode::Branch { value: _, children } = &mut bad_proof.proof[1] {
            children[0] = Box::new(MerkleNode::Leaf {
                value: F::zero(),
                pos: 0,
                elem: F::one(),
            });
        }
        let path_vars = circuit.add_merkle_path_variable(&bad_proof).unwrap();

        // new root witness is not correct
        let root_var = circuit.compute_merkle_root(elem, &path_vars).unwrap();
        assert_ne!(circuit.witness(root_var).unwrap(), expected_root);

        // Circuit does not verify because a left node value is 0
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
