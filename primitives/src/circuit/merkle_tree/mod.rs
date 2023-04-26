// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait definitions for a Merkle tree gadget and implementations for
//! RescueMerkleTree and RescueSparseMerkleTree.

use ark_ff::PrimeField;
use jf_relation::{errors::CircuitError, BoolVar, Circuit, PlonkCircuit, Variable};

mod universal_merkle_tree;
use ark_std::{string::ToString, vec::Vec};
use typenum::{Unsigned, U3};

use crate::{
    merkle_tree::{
        internal::{MerkleNode, MerklePath, MerkleProof},
        prelude::RescueMerkleTree,
        Element, Index, MerkleTreeScheme, NodeValue, ToTraversalPath, UniversalMerkleTreeScheme,
    },
    rescue::RescueParameter,
};
type NodeVal<F> = <RescueMerkleTree<F> as MerkleTreeScheme>::NodeValue;
use super::rescue::RescueNativeGadget;

/// Gadget for a Merkle tree
///
/// # Examples
///
/// ```
/// use ark_bls12_377::Fq;
/// use jf_primitives::circuit::merkle_tree::MerkleTreeGadget;
/// use jf_relation::{Circuit, PlonkCircuit};
/// use jf_primitives::merkle_tree::{prelude::RescueMerkleTree, MerkleTreeScheme, MerkleCommitment};
///
/// let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
/// // Create a 3-ary MT, instantiated with a Rescue-based hash, of height 1.
/// let elements = vec![Fq::from(1_u64), Fq::from(2_u64), Fq::from(100_u64)];
/// let mt = RescueMerkleTree::<Fq>::from_elems(1, elements).unwrap();
/// let expected_root = mt.commitment().digest();
/// // Get a proof for the element in position 2
/// let (_, proof) = mt.lookup(2).expect_ok().unwrap();
///
/// // Circuit computation with a MT
/// let elem_idx = circuit.create_variable(2_u64.into()).unwrap();
/// let proof_var =
///     MerkleTreeGadget::<RescueMerkleTree<Fq>>::create_membership_proof_variable(
///         &mut circuit,
///         &proof
///     )
///     .unwrap();
/// let root_var =
///     MerkleTreeGadget::<RescueMerkleTree<Fq>>::create_root_variable(
///         &mut circuit,
///         expected_root
///     )
///     .unwrap();
/// MerkleTreeGadget::<RescueMerkleTree<Fq>>::enforce_membership_proof(
///     &mut circuit,
///     elem_idx,
///     proof_var,
///     root_var
/// )
/// .unwrap();
/// assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
/// ```
pub trait MerkleTreeGadget<M>
where
    M: MerkleTreeScheme,
    M::NodeValue: PrimeField,
{
    /// Type to represent the merkle proof of the concrete MT instantiation.
    /// It is MT-specific, e.g arity will affect the exact definition of the
    /// underlying Merkle path.
    type MembershipProofVar;

    /// Gadget for the digest algorithm.
    type DigestGadget: DigestAlgorithmGadget<M::NodeValue>;

    /// Allocate a variable for the membership proof.
    fn create_membership_proof_variable(
        &mut self,
        membership_proof: &M::MembershipProof,
    ) -> Result<Self::MembershipProofVar, CircuitError>;

    /// Allocate a variable for the merkle root.
    fn create_root_variable(&mut self, root: M::NodeValue) -> Result<Variable, CircuitError>;

    /// Given variables representing:
    /// * an element index
    /// * its merkle proof
    /// * root
    /// * return `BoolVar` indicating the correctness of its membership proof.
    fn is_member(
        &mut self,
        elem_idx_var: Variable,
        proof_var: Self::MembershipProofVar,
        root_var: Variable,
    ) -> Result<BoolVar, CircuitError>;

    /// Enforce correct `proof_var` for the `elem_idx_var` against
    /// `expected_root_var`.
    fn enforce_membership_proof(
        &mut self,
        elem_idx_var: Variable,
        proof_var: Self::MembershipProofVar,
        expected_root_var: Variable,
    ) -> Result<(), CircuitError>;
}

/// Gadget for the universal Merkle tree
///
/// # Examples
///
/// ```
/// use ark_bls12_377::Fq;
/// use jf_primitives::circuit::merkle_tree::{MerkleTreeGadget, UniversalMerkleTreeGadget};
/// use jf_relation::{Circuit, PlonkCircuit};
/// use jf_primitives::merkle_tree::{MerkleTreeScheme, MerkleCommitment, UniversalMerkleTreeScheme,
///     prelude::RescueSparseMerkleTree};
/// use hashbrown::HashMap;
/// use num_bigint::BigUint;
///
/// type SparseMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;
/// let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();
/// // Create a 3-ary universal MT, instantiated with a Rescue-based hash, of height 2.
/// let mut hashmap = HashMap::new();
/// hashmap.insert(BigUint::from(1u64), Fq::from(2u64));
/// hashmap.insert(BigUint::from(2u64), Fq::from(2u64));
/// hashmap.insert(BigUint::from(1u64), Fq::from(3u64));
/// let mt = SparseMerkleTree::<Fq>::from_kv_set(2, &hashmap).unwrap();
/// let expected_root = mt.commitment().digest();
/// // Get a proof for the element in position 2
/// let proof = mt.universal_lookup(&BigUint::from(3u64)).expect_not_found().unwrap();
///
/// // Circuit computation with a MT
/// let non_elem_idx_var = circuit.create_variable(BigUint::from(3u64).into()).unwrap();
///
/// let proof_var =
///     UniversalMerkleTreeGadget::<SparseMerkleTree<Fq>>::create_non_membership_proof_variable(
///         &mut circuit,
///         &proof
///     )
///     .unwrap();
/// let root_var =
///     MerkleTreeGadget::<SparseMerkleTree<Fq>>::create_root_variable(
///         &mut circuit,
///         expected_root
///     )
///     .unwrap();
/// UniversalMerkleTreeGadget::<SparseMerkleTree<Fq>>::enforce_non_membership_proof(
///     &mut circuit,
///     non_elem_idx_var,
///     proof_var,
///     root_var
/// )
/// .unwrap();
/// assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
/// ```
pub trait UniversalMerkleTreeGadget<M>: MerkleTreeGadget<M>
where
    M: UniversalMerkleTreeScheme,
    M::NodeValue: PrimeField,
{
    /// Type to represent the merkle non-membership proof of the concrete MT
    /// instantiation. It is MT-specific, e.g arity will affect the exact
    /// definition of the underlying Merkle path.
    type NonMembershipProofVar;

    /// Allocate a variable for the membership proof.
    fn create_non_membership_proof_variable(
        &mut self,
        membership_proof: &M::NonMembershipProof,
    ) -> Result<Self::NonMembershipProofVar, CircuitError>;

    /// checking non-membership proof
    fn is_non_member(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: Self::NonMembershipProofVar,
        root_var: Variable,
    ) -> Result<BoolVar, CircuitError>;

    /// Enforce correct `proof_var` for the empty elem `empty_elem_idx_var`
    /// against `expected_root_var`.
    fn enforce_non_membership_proof(
        &mut self,
        non_elem_idx_var: Variable,
        proof_var: Self::NonMembershipProofVar,
        expected_root_var: Variable,
    ) -> Result<(), CircuitError>;
}

/// Produces a list of circuit variables representing the ordered nodes,
/// based on the location of a `node` among its siblings, and otherwise
/// preserving the relative location of the siblings.
/// * `node` - node to be placed in the correct position
/// * `sibling1` - first sibling
/// * `sibling2` - second sibling
/// * `node_is_left` - variable that is true if node is the leftmost one.
/// * `node_is_right` -  variable that is true if node is the rightmost one.
/// * `returns` - list of variables corresponding to the node and its siblings
///   in the correct order.
fn constrain_sibling_order<F: RescueParameter>(
    circuit: &mut PlonkCircuit<F>,
    node: Variable,
    sib1: Variable,
    sib2: Variable,
    node_is_left: BoolVar,
    node_is_right: BoolVar,
) -> Result<[Variable; 3], CircuitError> {
    let one = F::one();
    let left_node = circuit.conditional_select(node_is_left, sib1, node)?;
    let right_node = circuit.conditional_select(node_is_right, sib2, node)?;
    let left_plus_right = circuit.add(left_node, right_node)?;
    let mid_node = circuit.lc(
        &[node, sib1, sib2, left_plus_right],
        &[one, one, one, one.neg()],
    )?;
    Ok([left_node, mid_node, right_node])
}

#[derive(Debug, Clone)]
/// Circuit variable for a node in the Merkle path.
pub struct Merkle3AryNodeVar {
    /// First sibling of the node.
    sibling1: Variable,
    /// Second sibling of the node.
    sibling2: Variable,
    /// Boolean variable indicating whether the node is a left child.
    is_left_child: BoolVar,
    /// Boolean variable indicating whether the node is a right child.
    is_right_child: BoolVar,
}

/// Circuit variable for a Merkle non-membership proof of a 3-ary Merkle tree.
/// Constains:
/// * a list of node variables in the path,
/// * a variable correseponsing to the position of the element.
#[derive(Debug, Clone)]
pub struct Merkle3AryNonMembershipProofVar {
    node_vars: Vec<Merkle3AryNodeVar>,
    pos_var: Variable,
}

/// Circuit variable for a Merkle proof of a 3-ary Merkle tree.
/// Constains:
/// * a list of node variables in the path,
/// * a variable correseponsing to the value of the element.
#[derive(Debug, Clone)]
pub struct Merkle3AryMembershipProofVar {
    node_vars: Vec<Merkle3AryNodeVar>,
    elem_var: Variable,
}
/// Circuit counterpart to DigestAlgorithm
pub trait DigestAlgorithmGadget<F>
where
    F: PrimeField,
{
    /// Digest a list of variables
    fn digest(circuit: &mut PlonkCircuit<F>, data: &[Variable]) -> Result<Variable, CircuitError>;

    /// Digest an indexed element
    fn digest_leaf(
        circuit: &mut PlonkCircuit<F>,
        pos: usize,
        elem: Variable,
    ) -> Result<Variable, CircuitError>;
}

/// Digest gadget using for the Rescue hash function.
pub struct RescueDigestGadget {}

impl<F: RescueParameter> DigestAlgorithmGadget<F> for RescueDigestGadget {
    fn digest(circuit: &mut PlonkCircuit<F>, data: &[Variable]) -> Result<Variable, CircuitError> {
        Ok(RescueNativeGadget::<F>::rescue_sponge_no_padding(circuit, data, 1)?[0])
    }

    fn digest_leaf(
        circuit: &mut PlonkCircuit<F>,
        pos: Variable,
        elem: Variable,
    ) -> Result<Variable, CircuitError> {
        let zero = circuit.zero();
        Ok(RescueNativeGadget::<F>::rescue_sponge_no_padding(circuit, &[zero, pos, elem], 1)?[0])
    }
}

/// Proof of membership
pub trait MembershipProof<E, I, T>
where
    E: Element,
    I: Index,
    T: NodeValue,
{
    /// Get the tree height
    fn tree_height(&self) -> usize;
    /// Get index of element
    fn index(&self) -> &I;
    /// Get the element
    fn elem(&self) -> Option<&E>;
    /// Get the merkle path to the element
    fn merkle_path(&self) -> &MerklePath<E, I, T>;
}

impl<E, I, T, Arity> MembershipProof<E, I, T> for MerkleProof<E, I, T, Arity>
where
    E: Element,
    I: Index,
    T: NodeValue,
    Arity: Unsigned,
{
    fn tree_height(&self) -> usize {
        self.tree_height()
    }
    fn index(&self) -> &I {
        self.index()
    }
    fn elem(&self) -> Option<&E> {
        self.elem()
    }
    fn merkle_path(&self) -> &MerklePath<E, I, T> {
        &self.proof
    }
}

impl<T> MerkleTreeGadget<T> for PlonkCircuit<T::NodeValue>
where
    T: MerkleTreeScheme,
    T::MembershipProof: MembershipProof<T::NodeValue, T::Index, T::NodeValue>,
    T::NodeValue: PrimeField + RescueParameter,
    T::Index: ToTraversalPath<U3>,
{
    type MembershipProofVar = Merkle3AryMembershipProofVar;

    type DigestGadget = RescueDigestGadget;

    fn create_membership_proof_variable(
        &mut self,
        merkle_proof: &<T as MerkleTreeScheme>::MembershipProof,
    ) -> Result<Merkle3AryMembershipProofVar, CircuitError> {
        let path = merkle_proof
            .index()
            .to_traversal_path(merkle_proof.tree_height() - 1);

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
            .zip(merkle_proof.merkle_path().iter().skip(1))
            .filter_map(|(branch, node)| match node {
                MerkleNode::Branch { value: _, children } => Some((children, branch)),
                _ => None,
            })
            .map(|(children, branch)| {
                let sib_branch1 = if branch == &0 { 1 } else { 0 };
                let sib_branch2 = if branch == &2 { 1 } else { 2 };
                Ok(Merkle3AryNodeVar {
                    sibling1: self.create_variable(children[sib_branch1].value())?,
                    sibling2: self.create_variable(children[sib_branch2].value())?,
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

    fn create_root_variable(
        &mut self,
        root: NodeVal<T::NodeValue>,
    ) -> Result<Variable, CircuitError> {
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
        let bool_val =
            MerkleTreeGadget::<T>::is_member(self, elem_idx_var, proof_var, expected_root_var)?;
        self.enforce_true(bool_val.into())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        circuit::merkle_tree::{
            constrain_sibling_order, Merkle3AryMembershipProofVar, MerkleTreeGadget,
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
    use ark_std::{boxed::Box, vec::Vec};
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
        // An elemement we care about
        let elem = F::from(310_u64);

        // Iterate over the positions for the given element
        for uid in 1u64..9u64 {
            // native computation with a MT
            let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
            let mut elements = (1u64..=9u64).map(|x| F::from(x)).collect::<Vec<_>>();
            elements[uid as usize] = elem;
            let mt = RescueMerkleTree::<F>::from_elems(2, elements).unwrap();
            let expected_root = mt.commitment().digest();
            let (retrieved_elem, proof) = mt.lookup(uid).expect_ok().unwrap();
            assert_eq!(retrieved_elem, elem);

            // Happy path
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
                let left_sib = if uid % 3 == 0 { 1 } else { 0 };
                children[left_sib] = Box::new(MerkleNode::ForgettenSubtree { value: F::zero() });
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
}
