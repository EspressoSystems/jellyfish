// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![allow(missing_docs)]

//! Circuit implementation of a Merkle tree.

use crate::merkle_tree::{AccMemberWitness, MerklePath, MerkleTree, NodePos, NodeValue};
use ark_ec::TEModelParameters as Parameters;
use ark_ff::PrimeField;
use ark_std::{vec, vec::Vec};
use jf_plonk::{
    circuit::{customized::rescue::RescueGadget, BoolVar, Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use jf_rescue::RescueParameter;

#[derive(Clone)]
struct MerkleNodeBooleanEncoding<F: PrimeField> {
    sibling1: NodeValue<F>,
    sibling2: NodeValue<F>,
    is_left_child: bool,
    is_right_child: bool,
}

impl<F: PrimeField> MerkleNodeBooleanEncoding<F> {
    fn new(
        sibling1: NodeValue<F>,
        sibling2: NodeValue<F>,
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

struct MerklePathBooleanEncoding<F: PrimeField> {
    pub nodes: Vec<MerkleNodeBooleanEncoding<F>>,
}

impl<F: PrimeField> MerklePathBooleanEncoding<F> {
    fn new(nodes: &[MerkleNodeBooleanEncoding<F>]) -> Self {
        MerklePathBooleanEncoding {
            nodes: nodes.to_vec(),
        }
    }
}

impl<F: PrimeField> From<&MerklePath<F>> for MerklePathBooleanEncoding<F> {
    fn from(path: &MerklePath<F>) -> Self {
        let mut nodes = vec![];
        for node in path.nodes.iter() {
            let circuit_node = match node.pos {
                NodePos::Left => {
                    MerkleNodeBooleanEncoding::new(node.sibling1, node.sibling2, true, false)
                },
                NodePos::Middle => {
                    MerkleNodeBooleanEncoding::new(node.sibling1, node.sibling2, false, false)
                },
                NodePos::Right => {
                    MerkleNodeBooleanEncoding::new(node.sibling1, node.sibling2, false, true)
                },
            };
            nodes.push(circuit_node);
        }

        Self::new(&nodes)
    }
}

#[derive(Debug)]
/// Circuit variables for a Merkle node
pub struct MerkleNodeVars {
    pub sibling1: Variable,
    pub sibling2: Variable,
    pub is_left_child: BoolVar,
    pub is_right_child: BoolVar,
}

#[derive(Debug)]
/// Circuit variables for a Merkle authentication path
pub struct MerklePathVars {
    pub nodes: Vec<MerkleNodeVars>,
}

/// Circuit variables for an accumulated element
pub struct AccElemVars {
    pub uid: Variable,
    pub elem: Variable,
}

/// Circuit variables for membership proof.
#[derive(Debug)]
pub struct AccMemberWitnessVar {
    pub uid: Variable,
    pub merkle_path: MerklePathVars,
}

impl AccMemberWitnessVar {
    pub fn new<F, P>(
        circuit: &mut PlonkCircuit<F>,
        acc_member_witness: &AccMemberWitness<F>,
    ) -> Result<Self, PlonkError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F> + Clone,
    {
        Ok(Self {
            uid: circuit.create_variable(F::from(acc_member_witness.uid as u64))?,
            merkle_path: circuit.add_merkle_path_variable(&acc_member_witness.merkle_path)?,
        })
    }
}
trait MerkleTreeHelperGadget<F: PrimeField> {
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
    ) -> Result<[Variable; 3], PlonkError>;

    /// Ensure that the position of each node of the path is correctly encoded
    /// Used for testing purposes.
    /// * `merkle_path` - list of node of an authentication path
    /// * `returns` - list of variables corresponding to the authentication path
    fn constrain_merkle_path(
        &mut self,
        merkle_path: &MerklePathBooleanEncoding<F>,
    ) -> Result<MerklePathVars, PlonkError>;
}

/// Circuit implementation of a Merkle tree.
pub trait MerkleTreeGadget<F: PrimeField> {
    /// Wrapper around Circuit.constrain_merkle_path. Adds and checks the
    /// variables related to the Merkle path.
    /// * `merkle_path` - list of node of an authentication path
    /// * `returns` - list of variables corresponding to the authentication path
    fn add_merkle_path_variable(
        &mut self,
        merkle_path: &MerklePath<F>,
    ) -> Result<MerklePathVars, PlonkError>;

    /// Computes the merkle root based on some element placed at a leaf and a
    /// merkle path.
    /// * `elem` - variables corresponding to the uid and the element value
    ///   (e.g.: record commitment).
    /// * `path_vars` - variables corresponding to the Merkle path.
    /// * `return` - variable corresponding to the root value of the Merkle
    ///   tree.
    fn compute_merkle_root(
        &mut self,
        elem: AccElemVars,
        path_vars: &MerklePathVars,
    ) -> Result<Variable, PlonkError>;
}

impl<F> MerkleTreeGadget<F> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn add_merkle_path_variable(
        &mut self,
        merkle_path: &MerklePath<F>,
    ) -> Result<MerklePathVars, PlonkError> {
        // Encode Merkle path nodes positions with boolean variables
        let merkle_path = MerklePathBooleanEncoding::from(merkle_path);

        self.constrain_merkle_path(&merkle_path)
    }

    fn compute_merkle_root(
        &mut self,
        elem: AccElemVars,
        path_vars: &MerklePathVars,
    ) -> Result<Variable, PlonkError> {
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
    F: PrimeField,
{
    fn permute(
        &mut self,
        node: Variable,
        sib1: Variable,
        sib2: Variable,
        node_is_left: BoolVar,
        node_is_right: BoolVar,
    ) -> Result<[Variable; 3], PlonkError> {
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
        merkle_path: &MerklePathBooleanEncoding<F>,
    ) -> Result<MerklePathVars, PlonkError> {
        // Setup node variables
        let nodes = merkle_path
            .nodes
            .clone()
            .into_iter()
            .map(|node| -> Result<MerkleNodeVars, PlonkError> {
                Ok(MerkleNodeVars {
                    sibling1: self.create_variable(node.sibling1.0)?,
                    sibling2: self.create_variable(node.sibling2.0)?,
                    is_left_child: self.create_boolean_variable(node.is_left_child)?,
                    is_right_child: self.create_boolean_variable(node.is_right_child)?,
                })
            })
            .collect::<Result<Vec<MerkleNodeVars>, PlonkError>>()?;

        // `is_left_child`, `is_right_child` and `is_left_child+is_right_child` are
        // boolean
        for node in nodes.iter() {
            // Boolean constrain `is_left_child + is_right_child` because a node
            // can either be the left or the right child of its parent
            let left_plus_right =
                self.add(node.is_left_child.into(), node.is_right_child.into())?;
            self.bool_gate(left_plus_right)?;
        }

        Ok(MerklePathVars { nodes })
    }
}

/// Create a merkle path for position `uid` and element `comm`.
/// **Only used for testing**
pub fn gen_merkle_path_for_test<F: RescueParameter>(uid: u64, comm: F) -> (AccMemberWitness<F>, F) {
    let mut elem = F::one();
    let mut mt = MerkleTree::new((uid as f64).log(3.0) as u8 + 1).unwrap();
    for _ in 0..uid {
        mt.push(elem);
        elem += F::one();
    }
    mt.push(comm);

    let root = mt.commitment().root_value;
    let leaf_info = AccMemberWitness::lookup_from_tree(&mt, uid)
        .expect_ok()
        .unwrap()
        .1; // safe unwrap
    (leaf_info, root.to_scalar())
}

#[cfg(test)]
mod test {
    use crate::{
        circuit::merkle_tree::{
            gen_merkle_path_for_test, AccElemVars, MerkleNodeBooleanEncoding,
            MerklePathBooleanEncoding, MerkleTreeGadget, MerkleTreeHelperGadget,
        },
        merkle_tree::{hash, MerklePath, MerklePathNode, NodePos, NodeValue},
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bls12_381_bandersnatch::Fq as FqEd381b;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::PrimeField;
    use ark_std::{vec, vec::Vec};
    use jf_plonk::circuit::{Circuit, PlonkCircuit, Variable};
    use jf_rescue::RescueParameter;

    fn check_merkle_path<F: PrimeField>(is_left_child: bool, is_right_child: bool, accept: bool) {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let zero = F::zero();
        let one = F::one();
        let node = MerkleNodeBooleanEncoding::new(
            NodeValue(one),
            NodeValue(zero),
            is_left_child,
            is_right_child,
        );
        let path = MerklePathBooleanEncoding::new(&vec![node]);
        let _ = circuit.constrain_merkle_path(&path);
        if accept {
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        } else {
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        }
    }

    #[test]
    fn test_constrain_merkle_path() {
        test_constrain_merkle_path_helper::<FqEd254>();
        test_constrain_merkle_path_helper::<FqEd377>();
        test_constrain_merkle_path_helper::<FqEd381>();
        test_constrain_merkle_path_helper::<FqEd381b>();
        test_constrain_merkle_path_helper::<Fq377>();
    }
    fn test_constrain_merkle_path_helper<F: PrimeField>() {
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

    fn check_permute<F: PrimeField>(
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

    fn gen_permutation_circuit_and_vars<F: PrimeField>(
    ) -> (PlonkCircuit<F>, Variable, Variable, Variable) {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let mut prng = ark_std::test_rng();
        let node = circuit.create_variable(F::rand(&mut prng)).unwrap();
        let sib1 = circuit.create_variable(F::rand(&mut prng)).unwrap();
        let sib2 = circuit.create_variable(F::rand(&mut prng)).unwrap();

        (circuit, node, sib1, sib2)
    }

    #[test]
    fn test_permute() {
        test_permute_helper::<FqEd254>();
        test_permute_helper::<FqEd377>();
        test_permute_helper::<FqEd381>();
        test_permute_helper::<FqEd381b>();
        test_permute_helper::<Fq377>();
    }

    fn test_permute_helper<F: PrimeField>() {
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
        let uid_u32 = 2u32;
        let uid = F::from(uid_u32);
        let comm = F::from(310_u32);

        let uid_var = circuit.create_variable(uid).unwrap();
        let comm_var = circuit.create_variable(comm).unwrap();

        let elem = AccElemVars {
            uid: uid_var,
            elem: comm_var,
        };

        let (leaf_info, expected_root) = gen_merkle_path_for_test(uid_u32 as u64, comm);

        let path_vars = circuit
            .add_merkle_path_variable(&leaf_info.merkle_path)
            .unwrap();

        let root_var = circuit.compute_merkle_root(elem, &path_vars).unwrap();

        // Check Merkle root correctness
        assert_eq!(circuit.witness(root_var).unwrap(), expected_root);

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

        let elem = AccElemVars {
            uid: uid_var,
            elem: comm_var,
        };

        let node = MerklePathNode::new(
            NodePos::Right,
            NodeValue(F::zero()), // Left node is zero which is not allowed
            NodeValue(F::from(4_u32)),
        );
        let leaf = hash(&NodeValue(F::zero()), &NodeValue(uid), &NodeValue(comm));
        let expected_root = hash(&node.sibling1, &node.sibling2, &leaf);

        let merkle_path = MerklePath::new(vec![node]);
        let path_vars = circuit.add_merkle_path_variable(&merkle_path).unwrap();

        let root_var = circuit.compute_merkle_root(elem, &path_vars).unwrap();

        // Check Merkle root correctness
        assert_eq!(circuit.witness(root_var).unwrap(), expected_root.0);

        // Circuit does not verify because a left node value is 0
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }
}
