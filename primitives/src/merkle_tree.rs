// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![allow(missing_docs)]
//! Implementation of the Merkle tree data structure.
//!
//! At a high level the Merkle tree is a ternary tree and the hash function H
//! used is the rescue hash function. The node values are BlsScalar and each
//! internal node value is obtained by computing v:=H(a,b,c) where a,b,c are
//! the values of the left,middle and right child respectively. Leaf values
//! for an element (uid,elem) is obtained as H(0,uid,elem).
//! The tree height is fixed during initial instantiation and a new leaf will
//! be inserted at the leftmost available slot in the tree.
use crate::errors::PrimitivesError;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::{
    boxed::Box,
    mem,
    rand::{
        distributions::{Distribution, Standard},
        Rng,
    },
    string::ToString,
    vec,
    vec::Vec,
};
use core::{convert::TryFrom, fmt::Debug};
use jf_rescue::{Permutation, RescueParameter};
use jf_utils::tagged_blob;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Deserialize, Serialize)]
/// Enum for identifying a position of a node (left, middle or right).
pub enum NodePos {
    /// Left.
    Left,
    /// Middle.
    Middle,
    /// Right.
    Right,
}

impl CanonicalSerialize for NodePos
where
    u8: From<NodePos>,
{
    fn serialize<W>(&self, mut writer: W) -> Result<(), ark_serialize::SerializationError>
    where
        W: ark_serialize::Write,
    {
        CanonicalSerialize::serialize(&u8::from(*self), &mut writer)
    }
    fn serialized_size(&self) -> usize {
        1
    }
}

impl CanonicalDeserialize for NodePos {
    fn deserialize<R>(mut reader: R) -> Result<Self, ark_serialize::SerializationError>
    where
        R: ark_serialize::Read,
    {
        let buf = <u8 as CanonicalDeserialize>::deserialize(&mut reader)?;
        if buf > 2 {
            return Err(SerializationError::InvalidData);
        }
        Ok(buf.into())
    }
}

impl From<NodePos> for usize {
    fn from(pos: NodePos) -> Self {
        use NodePos::*;
        match pos {
            Left => 0,
            Middle => 1,
            Right => 2,
        }
    }
}

impl From<NodePos> for u8 {
    fn from(pos: NodePos) -> Self {
        use NodePos::*;
        match pos {
            Left => 0,
            Middle => 1,
            Right => 2,
        }
    }
}

impl From<u8> for NodePos {
    fn from(pos: u8) -> Self {
        match pos {
            0 => NodePos::Left,
            1 => NodePos::Middle,
            2 => NodePos::Right,
            _ => panic!("unable to cast an u8 ({}) to node position", pos),
        }
    }
}

impl Default for NodePos {
    fn default() -> Self {
        Self::Left
    }
}

/// A 3-ary Merkle tree node.
///
/// It consists of the following:
/// * `sibling1` - the 1st sibling of the tree node
/// * `sibling2` - the 2nd sibling of the tree node
/// * `is_left_child` - indicates whether the tree node is the left child of its
///   parent
/// * `is_right_child` - indicates whether the tree node is the right child of
///   its parent
#[derive(
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerklePathNode<F: PrimeField> {
    /// First sibling.
    pub sibling1: NodeValue<F>,
    /// Second sibling.
    pub sibling2: NodeValue<F>,
    /// Position.
    pub pos: NodePos,
}

impl<F: PrimeField> MerklePathNode<F> {
    /// Creates a new node on some Merkle path given the position of the node
    /// and the value of the siblings
    /// * `pos` - position of the node (left, middle or right)
    /// * `sibling1` - first sibling value
    /// * `sibling2` - second sibling value
    /// * `returns` - Merkle path node
    pub fn new(pos: NodePos, sibling1: NodeValue<F>, sibling2: NodeValue<F>) -> Self {
        MerklePathNode {
            sibling1,
            sibling2,
            pos,
        }
    }
}

/// An authentication path of a ternary Merkle tree.
/// While node information can come in any order, in this implementation we
/// expect the first item to correspond to the leaf and the last to the root.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerklePath<F: PrimeField> {
    /// Nodes along the path.
    pub nodes: Vec<MerklePathNode<F>>,
}

impl<F: PrimeField> MerklePath<F> {
    /// Create a Merkle path from the list of nodes
    /// * `nodes` - ordered list of Merkle path nodes
    /// * `returns - Merkle path
    pub fn new(nodes: Vec<MerklePathNode<F>>) -> Self {
        Self { nodes }
    }
}

/// Represents the value for a node in the merkle tree.
#[tagged_blob("NODE")]
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Default, CanonicalSerialize, CanonicalDeserialize, Copy,
)]
pub struct NodeValue<F: Field>(pub(crate) F);

impl<F: Field> Distribution<NodeValue<F>> for Standard
where
    Standard: Distribution<F>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> NodeValue<F> {
        NodeValue(rng.gen())
    }
}

impl<F: PrimeField> From<u64> for NodeValue<F> {
    fn from(s: u64) -> Self {
        Self(F::from(s))
    }
}

// TODO: those APIs can be replaced with From/Into and Default?
impl<F: PrimeField> NodeValue<F> {
    /// Convert a node into a scalar field element.
    pub fn to_scalar(self) -> F {
        self.0
    }

    /// Convert a scalar field element into anode.
    pub fn from_scalar(scalar: F) -> Self {
        Self(scalar)
    }

    #[allow(dead_code)]
    fn to_bytes(self) -> Vec<u8> {
        self.0.into_repr().to_bytes_le()
    }

    /// Empty node.
    pub fn empty_node_value() -> Self {
        Self(F::zero())
    }
}

impl TryFrom<usize> for NodePos {
    type Error = ();

    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(NodePos::Left),
            1 => Ok(NodePos::Middle),
            2 => Ok(NodePos::Right),
            _ => Err(()),
        }
    }
}

/// Hash function used to compute an internal node value
/// * `a` - first input value (e.g.: left child value)
/// * `b` - second input value (e.g.: middle child value)
/// * `c` - third input value (e.g.: right child value)
/// * `returns` - rescue_sponge_no_padding(a,b,c)
pub(crate) fn hash<F: RescueParameter>(
    a: &NodeValue<F>,
    b: &NodeValue<F>,
    c: &NodeValue<F>,
) -> NodeValue<F> {
    let perm = Permutation::default();
    let digest = perm.sponge_no_padding(&[a.0, b.0, c.0], 1).unwrap()[0];
    NodeValue(digest)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
/// The result of querying at an index in the tree
pub enum LookupResult<F, P> {
    /// The value at the given index, and a proof of validity
    Ok(F, P),
    /// The index is valid but we do not have the leaf in memory
    NotInMemory,
    /// The index is outside the occupied range in the tree
    EmptyLeaf,
}

impl<F, P> LookupResult<F, P> {
    /// Assert the lookup result is Ok.
    pub fn expect_ok(self) -> Result<(F, P), PrimitivesError> {
        match self {
            LookupResult::Ok(x, proof) => Ok((x, proof)),
            LookupResult::NotInMemory => Err(PrimitivesError::InternalError(
                "Expected Ok, found NotInMemory".to_string(),
            )),
            LookupResult::EmptyLeaf => Err(PrimitivesError::InternalError(
                "Expected Ok, found EmptyLeaf".to_string(),
            )),
        }
    }

    /// FIXME: Not sure what this function does :-(.
    pub fn map<Fn, T2, P2>(self, f: Fn) -> LookupResult<T2, P2>
    where
        Fn: FnOnce(F, P) -> (T2, P2),
    {
        match self {
            LookupResult::Ok(x, proof) => {
                let (x, proof) = f(x, proof);
                LookupResult::Ok(x, proof)
            },
            LookupResult::NotInMemory => LookupResult::NotInMemory,
            LookupResult::EmptyLeaf => LookupResult::EmptyLeaf,
        }
    }
}

impl<F, P> From<LookupResult<F, P>> for Option<Option<(F, P)>> {
    fn from(v: LookupResult<F, P>) -> Self {
        match v {
            LookupResult::Ok(x, proof) => Some(Some((x, proof))),
            LookupResult::NotInMemory => None,
            LookupResult::EmptyLeaf => Some(None),
        }
    }
}

/// Data structure storing the information of a node in the Merkle tree.
/// The node has at most three children.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) enum MerkleNode<F>
where
    //  Clone + Copy + PartialEq + Eq + Debug,
    F: PrimeField,
{
    EmptySubtree,
    Branch {
        value: NodeValue<F>,
        children: [Box<MerkleNode<F>>; 3],
    },
    /// A forgotten subtree fully occupied in the merkle tree, but we don't
    /// have its contents in memory
    ForgottenSubtree {
        value: NodeValue<F>,
    },
    Leaf {
        value: NodeValue<F>,
        uid: u64,
        #[serde(with = "jf_utils::field_elem")]
        elem: F,
    },
}

impl<F> MerkleNode<F>
where
    F: RescueParameter,
{
    fn new_leaf(uid: u64, elem: F) -> Self {
        let value = hash(
            &NodeValue::empty_node_value(),
            &NodeValue::from(uid),
            &NodeValue::from_scalar(elem),
        );
        MerkleNode::Leaf { value, uid, elem }
    }

    fn new_branch(l: Box<Self>, m: Box<Self>, r: Box<Self>) -> Option<Self> {
        // Required to prevent tree extension attacks
        if l.value() == NodeValue::empty_node_value() {
            None
        } else {
            let value = hash(&l.value(), &m.value(), &r.value());
            let children = [l, m, r];
            Some(MerkleNode::Branch { value, children })
        }
    }

    fn is_empty_subtree(&self) -> bool {
        matches!(self, MerkleNode::EmptySubtree)
    }

    // Getter for the value of the MerkleNode
    fn value(&self) -> NodeValue<F> {
        match self {
            MerkleNode::EmptySubtree => NodeValue::empty_node_value(),
            MerkleNode::Branch { value, .. } => *value,
            MerkleNode::ForgottenSubtree { value } => *value,
            MerkleNode::Leaf { value, .. } => *value,
        }
    }

    fn insert_at_right(self, capacity: u64, ix: u64, elem: F) -> Self {
        if capacity <= 1 {
            assert!(self.is_empty_subtree());
            Self::new_leaf(ix, elem)
        } else {
            let next_capacity = capacity / 3;
            match self {
                MerkleNode::EmptySubtree => {
                    let child = (MerkleNode::EmptySubtree).insert_at_right(next_capacity, ix, elem);
                    Self::new_branch(
                        Box::new(child),
                        Box::new(MerkleNode::EmptySubtree),
                        Box::new(MerkleNode::EmptySubtree),
                    )
                    .unwrap() // `child` is not empty, so child.value() !=
                              // EMPTY_LEAF_VALUE
                },

                MerkleNode::Branch { children, .. } => {
                    let [mut l, mut m, mut r] = children;
                    match (ix / next_capacity) % 3 {
                        0 => {
                            l = Box::new(l.insert_at_right(next_capacity, ix, elem));
                        },
                        1 => {
                            m = Box::new(m.insert_at_right(next_capacity, ix, elem));
                        },
                        2 => {
                            r = Box::new(r.insert_at_right(next_capacity, ix, elem));
                        },
                        _ => {
                            unreachable!();
                        },
                    }
                    // `child` is not empty, so child.value() != EMPTY_LEAF_VALUE
                    Self::new_branch(l, m, r).unwrap()
                },

                _ => unreachable!(),
            }
        }
    }

    fn get_leaf(&self, capacity: u64, ix: u64) -> LookupResult<F, Vec<MerklePathNode<F>>> {
        if capacity <= 1 {
            match self {
                MerkleNode::Leaf { uid, elem, .. } => {
                    debug_assert_eq!(*uid, ix);
                    LookupResult::Ok(*elem, vec![])
                },
                MerkleNode::ForgottenSubtree { .. } => LookupResult::NotInMemory,
                MerkleNode::EmptySubtree => LookupResult::EmptyLeaf,
                _ => unreachable!(),
            }
        } else {
            let next_capacity = capacity / 3;
            match self {
                MerkleNode::EmptySubtree => LookupResult::EmptyLeaf,
                MerkleNode::ForgottenSubtree { .. } => LookupResult::NotInMemory,
                MerkleNode::Leaf { .. } => unreachable!(),

                MerkleNode::Branch { children, .. } => {
                    let [l, m, r] = children;
                    let (node, child) = match (ix / next_capacity) % 3 {
                        0 => (
                            MerklePathNode {
                                sibling1: m.value(),
                                sibling2: r.value(),
                                pos: NodePos::Left,
                            },
                            &l,
                        ),
                        1 => (
                            MerklePathNode {
                                sibling1: l.value(),
                                sibling2: r.value(),
                                pos: NodePos::Middle,
                            },
                            &m,
                        ),
                        2 => (
                            MerklePathNode {
                                sibling1: l.value(),
                                sibling2: m.value(),
                                pos: NodePos::Right,
                            },
                            &r,
                        ),
                        _ => unreachable!(),
                    };

                    // Add nodes to the end of the subtree's path (paths are leaf -> root)
                    child.get_leaf(next_capacity, ix).map(|x, mut path| {
                        path.push(node);
                        (x, path)
                    })
                },
            }
        }
    }

    fn rebuild_to_root(
        capacity: u64,
        branching: u64,
        path: &[MerklePathNode<F>],
        uid: u64,
        elem: &F,
    ) -> Option<Self> {
        // requires match between capacity and path length
        if capacity <= 1 {
            if path.is_empty() {
                Some(Self::new_leaf(uid, *elem))
            } else {
                None
            }
        } else if path.is_empty() {
            None
        } else {
            let next_capacity = capacity / 3;
            let next_branching = branching % next_capacity;
            let branching_pos = branching / next_capacity;
            let (this_piece, next_path) = path.split_last().unwrap();
            let MerklePathNode {
                sibling1,
                sibling2,
                pos,
            } = this_piece;
            let built_child =
                Self::rebuild_to_root(next_capacity, next_branching, next_path, uid, elem)?;
            let (l, m, r) = match (
                pos,
                branching_pos,
                *sibling1 == NodeValue::empty_node_value(),
                *sibling2 == NodeValue::empty_node_value(),
            ) {
                (NodePos::Left, 0, true, true) => {
                    (built_child, Self::EmptySubtree, Self::EmptySubtree)
                },
                (NodePos::Middle, 1, false, true) => (
                    Self::ForgottenSubtree { value: *sibling1 },
                    built_child,
                    Self::EmptySubtree,
                ),
                (NodePos::Right, 2, false, false) => (
                    Self::ForgottenSubtree { value: *sibling1 },
                    Self::ForgottenSubtree { value: *sibling2 },
                    built_child,
                ),
                _ => {
                    return None;
                },
            };
            Self::new_branch(Box::new(l), Box::new(m), Box::new(r))
        }
    }

    // `capacity` is the maximum number of leaves below this node (ie, 3^height)
    fn internal_forget(
        self,
        capacity: u64,
        ix: u64,
    ) -> (Self, LookupResult<F, Vec<MerklePathNode<F>>>) {
        if capacity <= 1 {
            match self {
                // Forgetting a leaf removes its `elem` from the tree
                MerkleNode::Leaf { value, uid, elem } => {
                    debug_assert_eq!(uid, ix);
                    (
                        MerkleNode::ForgottenSubtree { value },
                        LookupResult::Ok(elem, vec![]),
                    )
                },
                // The index is already forgotten
                MerkleNode::ForgottenSubtree { value } => (
                    MerkleNode::ForgottenSubtree { value },
                    LookupResult::NotInMemory,
                ),
                // The index is out of range
                MerkleNode::EmptySubtree => (MerkleNode::EmptySubtree, LookupResult::EmptyLeaf),
                // A branch in a leaf position
                MerkleNode::Branch { .. } => unreachable!(),
            }
        } else {
            let next_capacity = capacity / 3;
            match self {
                // The index is out of range
                MerkleNode::EmptySubtree => (MerkleNode::EmptySubtree, LookupResult::EmptyLeaf),
                // The index is already forgotten
                MerkleNode::ForgottenSubtree { value } => (
                    MerkleNode::ForgottenSubtree { value },
                    LookupResult::NotInMemory,
                ),
                // A leaf in a branch position
                MerkleNode::Leaf { .. } => unreachable!(),

                MerkleNode::Branch { value, children } => {
                    let [mut l, mut m, mut r] = children;

                    // Add nodes to the end of the subtree's path (paths are leaf -> root)
                    let res = match (ix / next_capacity) % 3 {
                        0 => {
                            let (new_l, res) = l.internal_forget(next_capacity, ix);
                            l = Box::new(new_l);
                            res.map(|t, mut path| {
                                path.push(MerklePathNode {
                                    sibling1: m.value(),
                                    sibling2: r.value(),
                                    pos: NodePos::Left,
                                });
                                (t, path)
                            })
                        },

                        1 => {
                            let (new_m, res) = m.internal_forget(next_capacity, ix);
                            m = Box::new(new_m);
                            res.map(|t, mut path| {
                                path.push(MerklePathNode {
                                    sibling1: l.value(),
                                    sibling2: r.value(),
                                    pos: NodePos::Middle,
                                });
                                (t, path)
                            })
                        },

                        2 => {
                            let (new_r, res) = r.internal_forget(next_capacity, ix);
                            r = Box::new(new_r);
                            res.map(|t, mut path| {
                                path.push(MerklePathNode {
                                    sibling1: l.value(),
                                    sibling2: m.value(),
                                    pos: NodePos::Right,
                                });
                                (t, path)
                            })
                        },

                        // (x%3) other than 0, 1, 2
                        _ => unreachable!(),
                    };

                    match (*l, *m, *r) {
                        // If every child has been forgotten, forget this node too
                        (
                            MerkleNode::ForgottenSubtree { .. },
                            MerkleNode::ForgottenSubtree { .. },
                            MerkleNode::ForgottenSubtree { .. },
                        ) => (MerkleNode::ForgottenSubtree { value }, res),
                        // Otherwise, some leaf below this branch is either live or empty, so we
                        // can't forget it.
                        (l, m, r) => {
                            debug_assert_eq!(
                                Self::new_branch(
                                    Box::new(l.clone()),
                                    Box::new(m.clone()),
                                    Box::new(r.clone())
                                )
                                .unwrap(),
                                MerkleNode::Branch {
                                    value,
                                    children: [
                                        Box::new(l.clone()),
                                        Box::new(m.clone()),
                                        Box::new(r.clone()),
                                    ]
                                }
                            );
                            (
                                MerkleNode::Branch {
                                    value,
                                    children: [Box::new(l), Box::new(m), Box::new(r)],
                                },
                                res,
                            )
                        },
                    }
                },
            }
        }
    }

    // `base_ix` is the leftmost leaf index in this subtree. When `path` is empty,
    // `base_ix` will equal the correct index for that leaf.
    #[allow(clippy::type_complexity)]
    fn internal_remember(
        self,
        base_ix: u64,
        elem: F,
        path: &[(NodeValue<F>, MerklePathNode<F>)],
    ) -> (Self, Result<(), Option<(usize, NodeValue<F>)>>) {
        match path.last() {
            None => {
                let new_leaf = Self::new_leaf(base_ix, elem);
                let self_val = self.value();
                if self_val != new_leaf.value() {
                    (self, Err(Some((0, self_val))))
                } else {
                    match self {
                        MerkleNode::Leaf {
                            uid, elem: lelem, ..
                        } => {
                            debug_assert_eq!(lelem, elem);
                            debug_assert_eq!(uid, base_ix);
                            (new_leaf, Ok(()))
                        },
                        MerkleNode::ForgottenSubtree { value: _ } => (new_leaf, Ok(())),
                        _ => unreachable!(),
                    }
                }
            },

            Some((child_val, last_node)) => {
                let child_val = *child_val;

                let this_val = self.value();
                match self {
                    MerkleNode::EmptySubtree => {
                        (MerkleNode::EmptySubtree, Err(Some((path.len(), this_val))))
                    },
                    MerkleNode::ForgottenSubtree { value } => {
                        let (l, m, r) = match last_node.pos {
                            NodePos::Left => (child_val, last_node.sibling1, last_node.sibling2),
                            NodePos::Middle => (last_node.sibling1, child_val, last_node.sibling2),
                            NodePos::Right => (last_node.sibling1, last_node.sibling2, child_val),
                        };

                        let new_node = Self::new_branch(
                            Box::new(MerkleNode::ForgottenSubtree { value: l }),
                            Box::new(MerkleNode::ForgottenSubtree { value: m }),
                            Box::new(MerkleNode::ForgottenSubtree { value: r }),
                        );
                        match new_node {
                            None => (self, Err(None)),
                            Some(new_node) => {
                                if new_node.value() != value {
                                    (self, Err(Some((path.len(), value))))
                                } else {
                                    new_node.internal_remember(base_ix, elem, path)
                                }
                            },
                        }
                    },
                    MerkleNode::Leaf { .. } => unreachable!(),

                    MerkleNode::Branch { value, children } => {
                        let [mut l, mut m, mut r] = children;

                        let (path_l, path_m, path_r) = match last_node.pos {
                            NodePos::Left => (child_val, last_node.sibling1, last_node.sibling2),
                            NodePos::Middle => (last_node.sibling1, child_val, last_node.sibling2),
                            NodePos::Right => (last_node.sibling1, last_node.sibling2, child_val),
                        };
                        if path_l != l.value() || path_m != m.value() || path_r != r.value() {
                            (
                                MerkleNode::Branch {
                                    value,
                                    children: [l, m, r],
                                },
                                Err(Some((path.len(), value))),
                            )
                        } else {
                            let res = match last_node.pos {
                                NodePos::Left => {
                                    let (new_l, res) = l.internal_remember(
                                        3 * base_ix,
                                        elem,
                                        &path[0..path.len() - 1],
                                    );
                                    l = Box::new(new_l);
                                    res
                                },
                                NodePos::Middle => {
                                    let (new_m, res) = m.internal_remember(
                                        3 * base_ix + 1,
                                        elem,
                                        &path[0..path.len() - 1],
                                    );
                                    m = Box::new(new_m);
                                    res
                                },
                                NodePos::Right => {
                                    let (new_r, res) = r.internal_remember(
                                        3 * base_ix + 2,
                                        elem,
                                        &path[0..path.len() - 1],
                                    );
                                    r = Box::new(new_r);
                                    res
                                },
                            };
                            debug_assert_eq!(
                                Self::new_branch(l.clone(), m.clone(), r.clone())
                                    .unwrap()
                                    .value(),
                                value
                            );
                            (
                                MerkleNode::Branch {
                                    value,
                                    children: [l, m, r],
                                },
                                res,
                            )
                        }
                    },
                }
            },
        }
    }
}

/// A wrapper of the merkle root, together with the tree information.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerkleCommitment<F>
where
    F: PrimeField,
{
    /// Root of the tree.
    pub root_value: NodeValue<F>,
    /// Height of the tree.
    pub height: u8,
    /// #leaves of the tree.
    pub num_leaves: u64,
}

/// Data struct for a merkle leaf.
#[tagged_blob("LEAF")]
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Default, CanonicalSerialize, CanonicalDeserialize, Copy,
)]
pub struct MerkleLeaf<F: Field>(pub F);

/// Inclusive proof of a merkle leaf.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Default,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct MerkleLeafProof<F: PrimeField> {
    /// The leaf node.
    pub leaf: MerkleLeaf<F>,
    /// The path.
    pub path: MerklePath<F>,
}

impl<F> MerkleLeafProof<F>
where
    F: PrimeField,
{
    /// Input a leaf and the path, build a proof.
    pub fn new(leaf: F, path: MerklePath<F>) -> MerkleLeafProof<F> {
        MerkleLeafProof {
            leaf: MerkleLeaf(leaf),
            path,
        }
    }
}

/// A wrapper of the merkle membership proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum MerkleFrontier<F>
where
    F: PrimeField,
{
    /// Without proof.
    Empty {
        /// Height of the tree.
        height: u8,
    },
    /// With proof.
    Proof(MerkleLeafProof<F>),
}

impl<F> MerkleFrontier<F>
where
    F: PrimeField,
{
    /// If the merkle frontier is empty or not.
    pub fn non_empty(&self) -> Option<&MerkleLeafProof<F>> {
        match self {
            MerkleFrontier::Proof(lap) => Some(lap),
            _ => None,
        }
    }
}

/// Data struct of a merkle tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MerkleTree<F>
where
    F: PrimeField,
{
    root: MerkleNode<F>,
    height: u8,
    capacity: u64,
    num_leaves: u64, // the index of the first unoccupied leaf
}

impl<F> MerkleTree<F>
where
    F: RescueParameter,
{
    /// Create a new Merkle with a specific height
    /// * `height` - height of the tree (number of hops from the root to a
    ///   leaf).
    /// Returns `None` if the capacity of the tree overflows a u64
    pub fn new(height: u8) -> Option<Self> {
        let root = MerkleNode::EmptySubtree;
        let capacity = (3_u64).checked_pow(height as u32)?;
        Some(MerkleTree {
            root,
            height,
            capacity,
            num_leaves: 0,
        })
    }

    /// Recreates a pruned Merkle from the rightmost leaf and proof to the root.
    /// Returns `None` if the capacity of the tree overflows a u64
    pub fn restore_from_frontier(
        commitment: MerkleCommitment<F>,
        proof: &MerkleFrontier<F>,
    ) -> Option<Self> {
        match proof {
            MerkleFrontier::Empty { height } => {
                if commitment.num_leaves == 0
                    && commitment.height == *height
                    && commitment.root_value == NodeValue::empty_node_value()
                {
                    Self::new(commitment.height)
                } else {
                    None
                }
            },
            MerkleFrontier::Proof(MerkleLeafProof { leaf, path }) => {
                if commitment.height as usize != path.nodes.len() || commitment.num_leaves == 0 {
                    None
                } else {
                    let capacity = (3_u64).checked_pow(commitment.height as u32)?;
                    let num_leaves = commitment.num_leaves;
                    let uid = num_leaves - 1;
                    let root =
                        MerkleNode::rebuild_to_root(capacity, uid, &path.nodes, uid, &leaf.0)?;
                    if root.value() == commitment.root_value {
                        Some(MerkleTree {
                            root,
                            height: commitment.height,
                            capacity,
                            num_leaves,
                        })
                    } else {
                        None
                    }
                }
            },
        }
    }

    /// get the collected commitment
    pub fn commitment(&self) -> MerkleCommitment<F> {
        MerkleCommitment {
            root_value: self.root.value(),
            height: self.height,
            num_leaves: self.num_leaves,
        }
    }
    /// get the frontier
    pub fn frontier(&self) -> MerkleFrontier<F> {
        if self.num_leaves > 0 {
            MerkleFrontier::Proof(self.get_leaf(self.num_leaves - 1).expect_ok().unwrap().1)
        } else {
            MerkleFrontier::Empty {
                height: self.height,
            }
        }
    }

    /// get the height
    pub fn height(&self) -> u8 {
        self.height
    }

    /// Get the number of leaves
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    /// Insert a new value at the leftmost available slot
    /// * `elem` - element to insert in the tree
    pub fn push(&mut self, elem: F) {
        let pos = self.num_leaves;
        let root = core::mem::replace(&mut self.root, MerkleNode::EmptySubtree);
        self.root = root.insert_at_right(self.capacity, pos, elem);

        self.num_leaves += 1;
    }

    /// Returns the leaf value given a position
    /// * `pos` - leaf position
    /// * `returns` - Leaf value at the position. LookupResult::EmptyLeaf if the
    ///   leaf position is empty or invalid, None if the leaf position has been
    ///   forgotten.
    pub fn get_leaf(&self, pos: u64) -> LookupResult<(), MerkleLeafProof<F>> {
        if pos >= self.capacity {
            LookupResult::EmptyLeaf
        } else {
            self.root
                .get_leaf(self.capacity, pos)
                .map(|elem, nodes| ((), MerkleLeafProof::new(elem, MerklePath { nodes })))
        }
    }

    /// Verify an element is a leaf of a Merkle tree given the root of the tree
    /// an a path
    /// * `root_value` - value of the root of the tree
    /// * `pos` - zero-based index of the leaf in the tree
    /// * `proof` - element from which the leaf value is computed and list of
    ///   node siblings/positions from the leaf to the root
    /// * `returns` - Ok(()) if the verification succeeds, Err(computed_root)
    ///   otherwise
    pub fn check_proof(
        root_value: NodeValue<F>,
        pos: u64,
        proof: &MerkleLeafProof<F>,
    ) -> Result<(), Option<NodeValue<F>>> {
        let mut current_val = MerkleNode::new_leaf(pos, proof.leaf.0).value();
        for mt_node in proof.path.nodes.iter() {
            let pos = mt_node.pos;
            let sibling1_value = mt_node.sibling1;
            let sibling2_value = mt_node.sibling2;

            let (l, m, r) = match pos {
                NodePos::Left => (current_val, sibling1_value, sibling2_value),
                NodePos::Middle => (sibling1_value, current_val, sibling2_value),
                NodePos::Right => (sibling1_value, sibling2_value, current_val),
            };

            current_val = MerkleNode::<F>::new_branch(
                Box::new(MerkleNode::ForgottenSubtree { value: l }),
                Box::new(MerkleNode::ForgottenSubtree { value: m }),
                Box::new(MerkleNode::ForgottenSubtree { value: r }),
            )
            .ok_or(None)?
            .value()
        }

        if root_value == current_val {
            Ok(())
        } else {
            Err(Some(current_val))
        }
    }

    /// Trim the leaf at position `i` from memory, if present.
    /// Will not trim if position `i` is the last inserted leaf position.
    /// Return is identical to result if `get_leaf(pos)` were called before this
    /// call.
    pub fn forget(&mut self, pos: u64) -> LookupResult<(), MerkleLeafProof<F>> {
        if pos == self.num_leaves - 1 {
            self.get_leaf(pos)
        } else {
            let root = core::mem::replace(&mut self.root, MerkleNode::EmptySubtree);
            let (root, pf) = root.internal_forget(self.capacity, pos);
            self.root = root;
            pf.map(|elem, nodes| ((), MerkleLeafProof::new(elem, MerklePath { nodes })))
        }
    }

    /// "Re-insert" a leaf into the tree using its proof.
    /// Returns Ok(()) if insertion is successful, or Err((ix,val)) if the
    /// proof disagrees with the correct node value `val` at position `ix`
    /// in the proof.
    pub fn remember(
        &mut self,
        pos: u64,
        proof: &MerkleLeafProof<F>,
    ) -> Result<(), Option<(usize, NodeValue<F>)>> {
        let root = core::mem::replace(&mut self.root, MerkleNode::EmptySubtree);
        let path = {
            let mut path = vec![];
            let mut val = MerkleNode::new_leaf(pos, proof.leaf.0).value();
            for mt_node in proof.path.nodes.iter() {
                path.push((val, mt_node.clone()));
                let pos = mt_node.pos;
                let sibling1_value = mt_node.sibling1;
                let sibling2_value = mt_node.sibling2;

                let (l, m, r) = match pos {
                    NodePos::Left => (val, sibling1_value, sibling2_value),
                    NodePos::Middle => (sibling1_value, val, sibling2_value),
                    NodePos::Right => (sibling1_value, sibling2_value, val),
                };

                val = MerkleNode::<F>::new_branch(
                    Box::new(MerkleNode::ForgottenSubtree { value: l }),
                    Box::new(MerkleNode::ForgottenSubtree { value: m }),
                    Box::new(MerkleNode::ForgottenSubtree { value: r }),
                )
                .ok_or(None)?
                .value()
            }
            path
        };
        let (root, res) = root.internal_remember(0, proof.leaf.0, &path);
        self.root = root;
        res
    }
}

pub struct FilledMTBuilder<F: RescueParameter> {
    peaks: Vec<(MerkleNode<F>, MerkleNode<F>)>,
    filled_root: Option<MerkleNode<F>>,
    height: u8,
    capacity: u64,
    num_leaves: u64,
}

impl<F: RescueParameter> FilledMTBuilder<F> {
    pub fn new(height: u8) -> Option<Self> {
        let capacity = (3_u64).checked_pow(height as u32)?;
        let peak_positions = height as usize;
        let mut peaks = Vec::with_capacity(peak_positions);
        peaks.resize(
            peak_positions,
            (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
        );

        Some(FilledMTBuilder {
            peaks,
            filled_root: None,
            height,
            capacity,
            num_leaves: 0,
        })
    }

    // consumes an existing tree, claiming ownership of the frontier peaks, and will
    // build the new tree from there after batch updates
    pub fn from_existing(tree: MerkleTree<F>) -> Option<Self> {
        let height = tree.height;
        let peak_positions = height as usize;
        let capacity = tree.capacity;
        let num_leaves = tree.num_leaves;
        let mut peaks = Vec::with_capacity(peak_positions);
        peaks.resize(
            peak_positions,
            (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
        );
        if num_leaves == 0 {
            Some(FilledMTBuilder {
                peaks,
                filled_root: None,
                height,
                capacity,
                num_leaves,
            })
        } else if num_leaves == capacity {
            Some(FilledMTBuilder {
                peaks,
                filled_root: Some(tree.root),
                height,
                capacity,
                num_leaves,
            })
        } else if let MerkleNode::Branch { children, .. } = tree.root {
            if Self::take_frontiers(children, &mut peaks, num_leaves, capacity) {
                Some(FilledMTBuilder {
                    peaks,
                    filled_root: None,
                    height,
                    capacity,
                    num_leaves,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    // starts with a commitment and frontier, extends tree forward for batch updates
    pub fn from_frontier(
        commitment: &MerkleCommitment<F>,
        frontier: &MerkleFrontier<F>,
    ) -> Option<Self> {
        match frontier {
            MerkleFrontier::Empty { height } => {
                if commitment.num_leaves == 0
                    && commitment.height == *height
                    && commitment.root_value == NodeValue::empty_node_value()
                {
                    return Self::new(commitment.height);
                }
            },
            MerkleFrontier::Proof(MerkleLeafProof { leaf, path }) => {
                let num_leaves = commitment.num_leaves;
                if num_leaves == 0 {
                    debug_assert!(num_leaves != 0);
                    return None;
                }
                let height = commitment.height;
                let capacity = (3_u64).checked_pow(height as u32)?;
                let uid = num_leaves - 1;
                let root = MerkleNode::rebuild_to_root(capacity, uid, &path.nodes, uid, &leaf.0)?;
                if root.value() == commitment.root_value {
                    if let MerkleNode::Branch { children, .. } = root {
                        let peak_positions = height as usize;
                        let mut peaks = Vec::with_capacity(peak_positions);
                        peaks.resize(
                            peak_positions,
                            (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
                        );
                        if Self::take_frontiers(children, &mut peaks, num_leaves, capacity) {
                            return Some(FilledMTBuilder {
                                peaks,
                                filled_root: None,
                                height,
                                capacity,
                                num_leaves,
                            });
                        }
                    }
                }
            },
        };
        None
    }

    fn take_frontiers(
        children: [Box<MerkleNode<F>>; 3],
        level_array: &mut [(MerkleNode<F>, MerkleNode<F>)],
        contained_leaves: u64,
        level_capacity: u64,
    ) -> bool {
        if contained_leaves == 0 || level_array.is_empty() {
            false
        } else {
            let (siblings, lower_levels) = level_array.split_last_mut().unwrap();
            let node_capacity = level_capacity / 3;
            let [child0, child1, child2] = children;
            let (remainder, branch_node) = match contained_leaves / node_capacity {
                0 => (contained_leaves, *child0),
                1 => {
                    siblings.0 = *child0;
                    (contained_leaves - node_capacity, *child1)
                },
                2 => {
                    siblings.0 = *child0;
                    siblings.1 = *child1;
                    (contained_leaves - (2 * node_capacity), *child2)
                },
                _ => unreachable!(),
            };

            if remainder > 0 {
                match branch_node {
                    MerkleNode::Branch { children, .. } => {
                        Self::take_frontiers(children, lower_levels, remainder, node_capacity)
                    },
                    _ => unreachable!(),
                }
            } else {
                true
            }
        }
    }

    // internal because this should only be used when forgetting all children is
    // implicitly okay
    fn prune_node(node_in: MerkleNode<F>) -> MerkleNode<F> {
        match node_in {
            MerkleNode::Leaf { value, .. } => MerkleNode::ForgottenSubtree { value },
            MerkleNode::Branch { value, .. } => MerkleNode::ForgottenSubtree { value },
            node => node, // empty and forgotten are unchanged
        }
    }

    // creates the nodes upward to whatever peak is now filled above the newly added
    // leaf. While still below the peak, creates a new filled branch for each
    // level, consuming the previously created left and middle (0, 1) siblings
    // into the new branch. When the peak is reached, inserts the newly-filled
    // `node` at `level_index`
    fn roll_up(
        peaks_from_level: &mut [(MerkleNode<F>, MerkleNode<F>)],
        filled_root: &mut Option<MerkleNode<F>>,
        node: MerkleNode<F>,
        level_index: u64,
    ) {
        if peaks_from_level.is_empty() {
            if filled_root.is_none() {
                *filled_root = Some(node);
            }
            return;
        }
        match level_index % 3 {
            0 => peaks_from_level[0].0 = node,
            1 => peaks_from_level[0].1 = node,
            2 => {
                let (level_peaks, higher_peaks) = peaks_from_level.split_first_mut().unwrap();
                let level_peaks = mem::replace(
                    level_peaks,
                    (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
                );
                Self::roll_up(
                    higher_peaks,
                    filled_root,
                    MerkleNode::new_branch(
                        Box::new(level_peaks.0),
                        Box::new(level_peaks.1),
                        Box::new(node),
                    )
                    .unwrap(),
                    level_index / 3,
                );
            },
            _ => unreachable!(),
        }
    }

    // creates the non-filled branch nodes from the array of filled peaks, up to the
    // root
    fn build_up(
        level_array: &mut [(MerkleNode<F>, MerkleNode<F>)],
        contained_leaves: u64,
        level_capacity: u64,
        prune: bool,
    ) -> MerkleNode<F> {
        if contained_leaves == 0 {
            MerkleNode::EmptySubtree
        } else {
            if level_array.is_empty() {
                return MerkleNode::EmptySubtree;
            }
            let (siblings, lower_levels) = level_array.split_last_mut().unwrap();
            let siblings = mem::replace(
                siblings,
                (MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
            );
            let node_capacity = level_capacity / 3;
            let new_contained_leaves = contained_leaves % node_capacity;
            let new_node = Self::build_up(lower_levels, new_contained_leaves, node_capacity, prune);
            let has_empty_child = matches!(new_node, MerkleNode::EmptySubtree);
            let (l, m, r) = match contained_leaves / node_capacity {
                0 => (new_node, MerkleNode::EmptySubtree, MerkleNode::EmptySubtree),
                1 => {
                    if prune && !has_empty_child {
                        (
                            Self::prune_node(siblings.0),
                            new_node,
                            MerkleNode::EmptySubtree,
                        )
                    } else {
                        (siblings.0, new_node, MerkleNode::EmptySubtree)
                    }
                },
                2 => {
                    if prune {
                        if has_empty_child {
                            (Self::prune_node(siblings.0), siblings.1, new_node)
                        } else {
                            (
                                Self::prune_node(siblings.0),
                                Self::prune_node(siblings.1),
                                new_node,
                            )
                        }
                    } else {
                        (siblings.0, siblings.1, new_node)
                    }
                },
                _ => unreachable!(),
            };
            MerkleNode::new_branch(Box::new(l), Box::new(m), Box::new(r))
                .unwrap_or(MerkleNode::EmptySubtree)
        }
    }

    pub fn push(&mut self, elem: F) {
        if self.num_leaves == self.capacity {
            return;
        }

        let leaf_node = MerkleNode::new_leaf(self.num_leaves, elem);
        Self::roll_up(
            &mut self.peaks,
            &mut self.filled_root,
            leaf_node,
            self.num_leaves,
        );
        self.num_leaves += 1;
    }

    pub fn build(mut self) -> MerkleTree<F> {
        let root = if let Some(filled_root) = self.filled_root {
            filled_root
        } else {
            Self::build_up(&mut self.peaks, self.num_leaves, self.capacity, false)
        };
        MerkleTree {
            root,
            height: self.height,
            capacity: self.capacity,
            num_leaves: self.num_leaves,
        }
    }

    pub fn build_pruned(mut self) -> MerkleTree<F> {
        let root = if let Some(filled_root) = self.filled_root {
            filled_root
        } else {
            Self::build_up(&mut self.peaks, self.num_leaves, self.capacity, true)
        };
        MerkleTree {
            root,
            height: self.height,
            capacity: self.capacity,
            num_leaves: self.num_leaves,
        }
    }

    pub fn into_frontier_and_commitment(self) -> (MerkleFrontier<F>, MerkleCommitment<F>) {
        // TODO: more efficient implementation
        let mt = self.build();
        (mt.frontier(), mt.commitment())
    }
}

impl<F: RescueParameter> From<FilledMTBuilder<F>> for MerkleTree<F> {
    fn from(builder: FilledMTBuilder<F>) -> Self {
        builder.build()
    }
}

/// The proof of membership in an accumulator (Merkle tree) for an element
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
#[serde(bound = "")]
pub struct AccMemberWitness<F: PrimeField> {
    pub merkle_path: MerklePath<F>,
    pub root: NodeValue<F>,
    pub uid: u64,
}

impl<F: RescueParameter> AccMemberWitness<F> {
    /// Create a fake proof/witness for a dummy element
    pub fn dummy(tree_depth: u8) -> Self {
        let mut witness = Self::default();
        let path = vec![MerklePathNode::default(); tree_depth as usize];
        witness.merkle_path = MerklePath::new(path);
        witness
    }

    /// Create a proof/witness for an accumulated ARC in the Merkle tree with
    /// leaf position `uid`
    pub fn lookup_from_tree(mt: &MerkleTree<F>, uid: u64) -> LookupResult<F, Self> {
        mt.get_leaf(uid).map(|_, MerkleLeafProof { leaf, path }| {
            (
                leaf.0,
                Self {
                    merkle_path: path,
                    uid,
                    root: mt.root.value(),
                },
            )
        })
    }
}

#[cfg(test)]
mod mt_tests {

    use crate::merkle_tree::*;
    use ark_ed_on_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_381::Fq as Fq381;
    use ark_ed_on_bn254::Fq as Fq254;
    use ark_ff::field_new;
    use quickcheck::{Gen, QuickCheck};

    #[derive(Clone, Debug)]
    enum ArrayOp {
        Push(u64),      // Append a value
        Swap(u16),      // "move" an index to the other array
        Challenge(u16), // check that all arrays are consistent at that index
    }

    impl quickcheck::Arbitrary for ArrayOp {
        fn arbitrary(g: &mut Gen) -> Self {
            use ArrayOp::*;
            let choices = [
                Push(<_>::arbitrary(g)),
                Swap(<_>::arbitrary(g)),
                Challenge(<_>::arbitrary(g)),
            ];
            g.choose(&choices).unwrap().clone()
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            use ArrayOp::*;
            match self {
                Push(x) => Box::new(x.shrink().map(Push)),
                Swap(ix) => Box::new(core::iter::once(Challenge(*ix)).chain(ix.shrink().map(Swap))),
                Challenge(ix) => Box::new(ix.shrink().map(Challenge)),
            }
        }
    }

    #[test]
    fn quickcheck_mt_test_against_array() {
        QuickCheck::new()
            .tests(10)
            .quickcheck(mt_test_against_array_helper::<Fq254> as fn(_, Vec<_>) -> ());

        QuickCheck::new()
            .tests(10)
            .quickcheck(mt_test_against_array_helper::<Fq377> as fn(_, Vec<_>) -> ());

        QuickCheck::new()
            .tests(10)
            .quickcheck(mt_test_against_array_helper::<Fq381> as fn(_, Vec<_>) -> ());
    }

    #[test]
    fn mt_test_against_array_regressions() {
        use ArrayOp::*;

        mt_test_against_array_helper::<Fq254>(0, vec![Push(18446744073709551615), Challenge(0)]);
        mt_test_against_array_helper::<Fq377>(0, vec![Push(18446744073709551615), Challenge(0)]);
        mt_test_against_array_helper::<Fq381>(0, vec![Push(18446744073709551615), Challenge(0)]);
    }

    fn mt_test_against_array_helper<F: RescueParameter>(height: u8, ops: Vec<ArrayOp>) {
        let height = height / 13 + 1; // cap it to ~20
        let mut full = MerkleTree::<F>::new(height).unwrap();
        let mut full_vec = vec![];
        let mut sparse_l = MerkleTree::<F>::new(height).unwrap();
        let mut sparse_l_vec = vec![];
        let mut sparse_r = MerkleTree::<F>::new(height).unwrap();
        let mut sparse_r_vec = vec![];
        let mut pruned = MerkleTree::<F>::new(height).unwrap();
        let mut pruned_vec = vec![];

        for op in ops {
            assert_eq!(full.root.value(), sparse_l.root.value());
            assert_eq!(full.root.value(), sparse_r.root.value());
            assert_eq!(full.num_leaves(), sparse_l.num_leaves());
            assert_eq!(full.num_leaves(), sparse_r.num_leaves());

            match op {
                ArrayOp::Push(val) => {
                    if full.num_leaves == full.capacity {
                        continue;
                    }
                    let val_v = F::from(val);
                    full.push(val_v);
                    full_vec.push(Some(val_v));
                    sparse_l.push(val_v);
                    sparse_l_vec.push(Some(val_v));
                    sparse_r.push(val_v);
                    sparse_r_vec.push(Some(val_v));
                    pruned.push(val_v);
                    pruned_vec.push(Some(val_v));
                    let ix = sparse_r.num_leaves() - 1;

                    let forgotten_r = sparse_r.forget(ix);
                    let forgotten_f = pruned.forget(ix);
                    let (_, proof_r) = forgotten_r.clone().expect_ok().unwrap();
                    let (_, proof_f) = forgotten_f.clone().expect_ok().unwrap();
                    if ix > 0 {
                        let _ = sparse_r.forget(ix - 1).expect_ok().unwrap();
                        let _ = pruned.forget(ix - 1).expect_ok().unwrap();
                    }
                    sparse_r_vec[ix as usize] = None;
                    pruned_vec[ix as usize] = None;
                    assert_eq!(proof_r.leaf.0, val_v);
                    assert_eq!(proof_f.leaf.0, val_v);

                    MerkleTree::check_proof(full.root.value(), ix, &proof_r).unwrap();
                    MerkleTree::check_proof(full.root.value(), ix, &proof_f).unwrap();

                    assert_eq!(sparse_r.get_leaf(ix), forgotten_r);
                    assert_eq!(pruned.get_leaf(ix), forgotten_f);
                    if ix > 0 {
                        assert!(matches!(
                            sparse_r.get_leaf(ix - 1),
                            LookupResult::NotInMemory
                        ));
                        assert!(matches!(pruned.get_leaf(ix - 1), LookupResult::NotInMemory));
                    }

                    assert_eq!(full.get_leaf(ix), sparse_l.get_leaf(ix));
                    assert_eq!(full.get_leaf(ix), sparse_r.get_leaf(ix));
                    assert_eq!(full.get_leaf(ix), pruned.get_leaf(ix));
                    assert_eq!(full.get_leaf(ix).expect_ok().unwrap().1.leaf.0, val_v);

                    // from frontier commitment
                    let commitment = pruned.commitment();
                    let frontier = pruned.frontier();

                    let built_fr =
                        MerkleTree::restore_from_frontier(commitment, &frontier).unwrap();
                    assert_eq!(pruned.get_leaf(ix), built_fr.get_leaf(ix));
                    assert_eq!(pruned.root.value(), built_fr.root.value());
                },

                ArrayOp::Swap(ix) => {
                    if full.num_leaves() <= 1 {
                        continue;
                    }
                    // constrained to not include the rightmost leaf, because that won't be
                    // forgotten.
                    let ix = (ix as u64) % (full.num_leaves() - 1);
                    if let Some(val) = sparse_l_vec.get(ix as usize).unwrap() {
                        assert!(matches!(sparse_r.get_leaf(ix), LookupResult::NotInMemory));
                        let (_, proof) = sparse_l.forget(ix).expect_ok().unwrap();
                        assert_eq!(proof.leaf.0, *val);
                        sparse_r.remember(ix, &proof).unwrap();
                        assert_eq!(((), proof), sparse_r.get_leaf(ix).expect_ok().unwrap());
                        assert!(matches!(sparse_l.get_leaf(ix), LookupResult::NotInMemory));
                        sparse_r_vec[ix as usize] = Some(*val);
                        sparse_l_vec[ix as usize] = None;
                    } else {
                        let val = sparse_r_vec.get(ix as usize).unwrap().unwrap();
                        assert!(matches!(sparse_l.get_leaf(ix), LookupResult::NotInMemory));
                        let (_, proof) = sparse_r.forget(ix).expect_ok().unwrap();
                        assert_eq!(proof.leaf.0, val);
                        sparse_l.remember(ix, &proof).unwrap();
                        assert_eq!(((), proof), sparse_l.get_leaf(ix).expect_ok().unwrap());
                        assert!(matches!(sparse_r.get_leaf(ix), LookupResult::NotInMemory));
                        sparse_l_vec[ix as usize] = Some(val);
                        sparse_r_vec[ix as usize] = None;
                    }
                },

                ArrayOp::Challenge(ix) => {
                    let ix = ix as u64;
                    assert_eq!(
                        <Option<Option<_>>>::from(full.get_leaf(ix)),
                        <Option<Option<_>>>::from(sparse_l.get_leaf(ix)).or_else(|| <Option<
                            Option<_>,
                        >>::from(
                            sparse_r.get_leaf(ix)
                        ))
                    );

                    let res = <Option<Option<_>>>::from(full.get_leaf(ix)).unwrap();
                    assert_eq!(
                        res.clone().map(|(_, x)| x.leaf.0),
                        full_vec.get(ix as usize).map(|x| x.unwrap())
                    );
                    assert_eq!(
                        res.clone().map(|(_, x)| x.leaf.0),
                        sparse_l_vec.get(ix as usize).map(|x| x
                            .or_else(|| *sparse_r_vec.get(ix as usize).unwrap())
                            .unwrap())
                    );

                    if let Some((_, proof)) = res {
                        let v_bad = proof.leaf.0 + F::one();
                        MerkleTree::check_proof(full.root.value(), ix, &proof).unwrap();
                        MerkleTree::check_proof(
                            full.root.value(),
                            ix,
                            &MerkleLeafProof::new(v_bad, proof.path.clone()),
                        )
                        .unwrap_err();
                    }

                    // check against full tree restored from builder
                    let mut full_builder = FilledMTBuilder::<F>::new(height).unwrap();
                    for leaf in full_vec.iter() {
                        full_builder.push(leaf.unwrap());
                    }

                    let built_fl = full_builder.build();
                    assert_eq!(full.root.value(), built_fl.root.value());
                    assert_eq!(full.get_leaf(ix), built_fl.get_leaf(ix));
                    if ix > 0 {
                        // edge case: leftmost
                        assert_eq!(full.get_leaf(0), built_fl.get_leaf(0));
                    }
                    if ix > 2 {
                        // edge case: first right leaf
                        assert_eq!(full.get_leaf(2), built_fl.get_leaf(2));
                    }
                    if ix > 3 {
                        // edge case: second set, first leaf
                        assert_eq!(full.get_leaf(3), built_fl.get_leaf(3));
                    }
                },
            }
        }
    }

    #[test]
    fn merkle_node_compute_root() {
        let expected_root_value_381 = field_new!(
            Fq381,
            "28060348101480746486466845250410777863418043544962993781101495414750775052182"
        );

        let expected_root_value_377 = field_new!(
            Fq377,
            "3089370986346100704056767742198887648870182507861918679460753971557351190474"
        );

        merkle_node_compute_root_helper::<Fq377>(expected_root_value_377);
        merkle_node_compute_root_helper::<Fq381>(expected_root_value_381);
    }
    fn merkle_node_compute_root_helper<F: RescueParameter>(root: F) {
        const HEIGHT: u8 = 3;
        {
            let mut mt = MerkleTree::<F>::new(HEIGHT).unwrap();
            mt.push(F::from(2u64));
            mt.push(F::from(4u64));
            mt.push(F::from(6u64));

            let root_value = mt.root.value();
            assert_eq!(root_value.0, root);
        }
    }

    #[test]
    fn mt_gen() {
        mt_gen_helper::<Fq254>();
        mt_gen_helper::<Fq377>();
        mt_gen_helper::<Fq381>();
    }
    fn mt_gen_helper<F: RescueParameter>() {
        const HEIGHT: u8 = 5;
        let mt = MerkleTree::<F>::new(HEIGHT).unwrap();
        assert_eq!(mt.height, HEIGHT);
        assert_eq!(mt.root.value(), NodeValue::empty_node_value());
        assert_eq!(mt.num_leaves, 0);
    }

    fn check_insert<F>(
        expected_num_leaves: u64,
        expected_root_value: F,
        elem: F,
        mt_state: &mut MerkleTree<F>,
    ) where
        F: RescueParameter,
    {
        mt_state.push(elem);
        assert_eq!(expected_num_leaves, mt_state.num_leaves);
        assert_eq!(expected_root_value, mt_state.root.value().0);
    }

    #[test]
    fn mt_insert() {
        mt_insert_377();
        mt_insert_381();
    }
    fn mt_insert_377() {
        let mut mt_state = MerkleTree::<Fq377>::new(3).unwrap();

        let expected_root_value = field_new!(
            Fq377,
            "6315802240857098026471408427875093424014875175276849904481286814739245367585"
        );

        check_insert(1, expected_root_value, Fq377::from(14u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq377,
            "5667892118047049739799520263316921516906768781979656516556299791745277441924"
        );

        check_insert(2, expected_root_value, Fq377::from(1u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq377,
            "6647035245650485645973868479866915331877247637739179578040373840151756330269"
        );

        check_insert(3, expected_root_value, Fq377::from(3u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq377,
            "8118751992167130154473837652124407028702774033612167776964560053443435356349"
        );

        check_insert(4, expected_root_value, Fq377::from(5u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq377,
            "1206473552337297350582613502814851495338920004803208938535072547977097566382"
        );

        check_insert(5, expected_root_value, Fq377::from(9u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq377,
            "2920147224190455791027037134100604018887322602008672374231496857119372658207"
        );

        check_insert(6, expected_root_value, Fq377::from(5u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq377,
            "210322276709335655995543096332051934652998856107004204533316622140744532303"
        );

        check_insert(7, expected_root_value, Fq377::from(3u64), &mut mt_state);
    }

    fn mt_insert_381() {
        let mut mt_state = MerkleTree::<Fq381>::new(3).unwrap();

        let expected_root_value = field_new!(
            Fq381,
            "7081746562927615832554718398136664278839060637885555651210011123028338406517"
        );
        check_insert(1, expected_root_value, Fq381::from(14u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq381,
            "18953992772659389170207216511756697948140968060778451061047576615653376873195"
        );
        check_insert(2, expected_root_value, Fq381::from(1u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq381,
            "48837637449461760066242782416226916390320337952762913310014866629892409771893"
        );
        check_insert(3, expected_root_value, Fq381::from(3u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq381,
            "52067967291723322908553827930013847265114075700290837834627105117605186185206"
        );
        check_insert(4, expected_root_value, Fq381::from(5u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq381,
            "46694038687200106981630417704049332460846970884710385420102061857311492462382"
        );
        check_insert(5, expected_root_value, Fq381::from(9u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq381,
            "46972149924452771097664193486415717147949569921437059075599195504242552479824"
        );
        check_insert(6, expected_root_value, Fq381::from(5u64), &mut mt_state);

        let expected_root_value = field_new!(
            Fq381,
            "19765563469931108618505653127604511343263393959241748271595767956528328819849"
        );
        check_insert(7, expected_root_value, Fq381::from(3u64), &mut mt_state);
    }

    fn check_proof<F>(
        mt_state: &MerkleTree<F>,
        pos: u64,
        elem: F,
        root_value: Option<NodeValue<F>>,
        expected_res: bool,
    ) where
        F: RescueParameter,
    {
        let proof = mt_state.get_leaf(pos).expect_ok().unwrap().1;
        let rt = root_value.unwrap_or_else(|| mt_state.root.value());
        let new_proof = MerkleLeafProof::new(elem, proof.path.clone());
        assert_eq!(
            MerkleTree::check_proof(rt, pos, &new_proof).is_ok(),
            expected_res
        );
    }

    #[test]
    fn mt_get_leaf_value() {
        mt_get_leaf_value_helper::<Fq254>();
        mt_get_leaf_value_helper::<Fq377>();
        mt_get_leaf_value_helper::<Fq381>();
    }

    fn mt_get_leaf_value_helper<F: RescueParameter>() {
        const HEIGHT: u8 = 3;
        let mut mt = MerkleTree::<F>::new(HEIGHT).unwrap();

        let elem1 = F::from(2u64);
        mt.push(elem1);

        let elem2 = F::from(4u64);
        mt.push(elem2);

        let expected_leaf_value1 = mt.get_leaf(0).expect_ok().unwrap().1.leaf.0;
        assert_eq!(expected_leaf_value1, elem1);

        let expected_leaf_value2 = mt.get_leaf(1).expect_ok().unwrap().1.leaf.0;
        assert_eq!(expected_leaf_value2, elem2);

        let invalid_leaf_value = mt.get_leaf(2);
        assert!(matches!(invalid_leaf_value, LookupResult::EmptyLeaf));
    }

    #[test]
    fn mt_get_num_leaves() {
        mt_get_num_leaves_helper::<Fq254>();
        mt_get_num_leaves_helper::<Fq377>();
        mt_get_num_leaves_helper::<Fq381>();
    }

    fn mt_get_num_leaves_helper<F: RescueParameter>() {
        const HEIGHT: u8 = 3;
        let mut mt = MerkleTree::<F>::new(HEIGHT).unwrap();
        assert_eq!(mt.num_leaves(), 0);

        mt.push(F::from(2u64));
        assert_eq!(mt.num_leaves(), 1);

        mt.push(F::from(4u64));
        assert_eq!(mt.num_leaves(), 2);
    }

    #[test]
    fn mt_prove_and_verify() {
        mt_prove_and_verify_helper::<Fq254>();
        mt_prove_and_verify_helper::<Fq377>();
        mt_prove_and_verify_helper::<Fq381>();
    }

    fn mt_prove_and_verify_helper<F: RescueParameter>() {
        let mut mt_state = MerkleTree::<F>::new(3).unwrap();
        let elem0 = F::from(4u64);
        mt_state.push(elem0);

        let elem1 = F::from(7u64);
        mt_state.push(elem1);

        let elem2 = F::from(20u64);
        mt_state.push(elem2);

        let elem3 = F::from(16u64);
        mt_state.push(elem3);

        check_proof(&mt_state, 0, elem0, None, true);
        check_proof(&mt_state, 1, elem1, None, true);
        check_proof(&mt_state, 2, elem2, None, true);
        check_proof(&mt_state, 3, elem3, None, true);

        check_proof(&mt_state, 0, elem3, None, false);
        check_proof(&mt_state, 3, elem0, None, false);

        let wrong_root_value = NodeValue::from(1111_u64);
        check_proof(&mt_state, 0, elem0, Some(wrong_root_value), false);
    }

    #[test]
    fn test_sparse_proof_update() {
        test_sparse_proof_update_helper::<Fq254>();
        test_sparse_proof_update_helper::<Fq377>();
        test_sparse_proof_update_helper::<Fq381>();
    }
    fn test_sparse_proof_update_helper<F: RescueParameter>() {
        let mut mt = MerkleTree::<F>::new(3).unwrap();
        mt.push(F::from(50u64));
        mt.push(F::from(100u64));
        let mut mt_sparse = mt.clone();
        mt_sparse.forget(1);
        mt.push(F::from(500u64));
        mt_sparse.push(F::from(500u64));
        mt_sparse.forget(2);
        // `proof` is relative to the tree with [50,100,500]
        let proof = mt_sparse.get_leaf(0).expect_ok().unwrap().1;
        assert_eq!(proof.leaf.0, F::from(50u64));
        MerkleTree::check_proof(mt.root.value(), 0, &proof).unwrap()
    }

    #[test]
    fn test_tree_extension_attack() {
        test_tree_extension_attack_helper::<Fq254>();
        test_tree_extension_attack_helper::<Fq377>();
        test_tree_extension_attack_helper::<Fq381>();
    }

    fn test_tree_extension_attack_helper<F: RescueParameter>() {
        let mut rng = ark_std::test_rng();
        let evil_val = F::rand(&mut rng);
        let evil_subtree = MerkleNode::new_branch(
            Box::new(MerkleNode::new_leaf(5000, evil_val)),
            Box::new(MerkleNode::new_leaf(25, evil_val)),
            Box::new(MerkleNode::new_leaf(26, evil_val)),
        )
        .unwrap();

        let good_val = F::rand(&mut rng);
        let mut mt = MerkleTree::<F>::new(1).unwrap();
        mt.push(good_val);
        mt.push(good_val);
        mt.push(evil_subtree.value().to_scalar());

        let proof = mt.get_leaf(2).expect_ok().unwrap().1;

        let evil_proof_node = MerklePathNode {
            sibling1: NodeValue::empty_node_value(),
            sibling2: NodeValue::from(2),
            pos: NodePos::Right,
        };

        if let MerkleNode::Branch { value: _, children } = evil_subtree {
            let evil_leaf_node1 = MerklePathNode {
                sibling1: children[0].value(),
                sibling2: children[2].value(),
                pos: NodePos::Middle,
            };

            let evil_leaf_node2 = MerklePathNode {
                sibling1: children[0].value(),
                sibling2: children[1].value(),
                pos: NodePos::Right,
            };

            let evil_proof1 = MerkleLeafProof::new(
                evil_val,
                MerklePath {
                    nodes: vec![evil_leaf_node1, evil_proof_node.clone()]
                        .into_iter()
                        .chain(proof.path.nodes.iter().cloned())
                        .collect(),
                },
            );
            let evil_proof2 = MerkleLeafProof::new(
                evil_val,
                MerklePath {
                    nodes: vec![evil_leaf_node2, evil_proof_node.clone()]
                        .into_iter()
                        .chain(proof.path.nodes.iter().cloned())
                        .collect(),
                },
            );

            MerkleTree::check_proof(mt.root.value(), 25, &evil_proof1).unwrap_err();
            MerkleTree::check_proof(mt.root.value(), 26, &evil_proof2).unwrap_err();
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_mt_restore_from_frontier() {
        test_mt_restore_from_frontier_helper::<Fq254>(39, 59);
        test_mt_restore_from_frontier_helper::<Fq377>(39, 59);
        test_mt_restore_from_frontier_helper::<Fq381>(39, 59);

        test_mt_restore_from_frontier_helper::<Fq254>(1, 1);
        test_mt_restore_from_frontier_helper::<Fq377>(1, 1);
        test_mt_restore_from_frontier_helper::<Fq381>(1, 1);

        test_mt_restore_from_frontier_empty::<Fq254>();
        test_mt_restore_from_frontier_empty::<Fq377>();
        test_mt_restore_from_frontier_empty::<Fq381>();
    }
    fn test_mt_restore_from_frontier_helper<F: RescueParameter>(height: u8, count: u64) {
        let height = height / 13 + 1; // cap it to ~20
        let capacity = (3_u64).checked_pow(height as u32).unwrap();
        let count = count % capacity;
        let mut full_tree = MerkleTree::<F>::new(height).unwrap();
        let mut pruned_tree = MerkleTree::<F>::new(height).unwrap();
        let mut rng = ark_std::test_rng();
        for idx in 0..count {
            let val = F::rand(&mut rng);
            full_tree.push(val);
            pruned_tree.push(val);
            if idx > 0 {
                pruned_tree.forget(idx - 1);
            }
        }

        let full_comm = full_tree.commitment();
        let full_proof = full_tree.frontier();
        let pruned_comm = pruned_tree.commitment();
        let pruned_proof = pruned_tree.frontier();
        let restored_full = MerkleTree::<F>::restore_from_frontier(full_comm, &full_proof).unwrap();
        let restored_pruned =
            MerkleTree::<F>::restore_from_frontier(pruned_comm, &pruned_proof).unwrap();
        assert_eq!(full_tree.root.value(), restored_full.root.value());
        assert_eq!(pruned_tree.root.value(), restored_pruned.root.value());
    }
    fn test_mt_restore_from_frontier_empty<F: RescueParameter>() {
        let mut pruned_tree_h3 = MerkleTree::<F>::new(3).unwrap();
        let mut pruned_tree_h4 = MerkleTree::<F>::new(4).unwrap();
        let empty_commitment_h3 = pruned_tree_h3.commitment();
        let empty_commitment_h4 = pruned_tree_h4.commitment();
        let empty_frontier_h3 = pruned_tree_h3.frontier();
        let empty_frontier_h4 = pruned_tree_h4.frontier();
        let mut rng = ark_std::test_rng();
        for idx in 0..7 {
            let val = F::rand(&mut rng);
            pruned_tree_h3.push(val);
            pruned_tree_h4.push(val);
            if idx > 0 {
                pruned_tree_h3.forget(idx - 1);
                pruned_tree_h4.forget(idx - 1);
            }
        }
        let commitment_h3 = pruned_tree_h3.commitment();
        let commitment_h4 = pruned_tree_h4.commitment();
        let frontier_h3 = pruned_tree_h3.frontier();
        let frontier_h4 = pruned_tree_h4.frontier();

        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h3, &empty_frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h4, &empty_frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h3, &frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(commitment_h3, &empty_frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h4, &frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(commitment_h4, &empty_frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h3, &frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(commitment_h3, &empty_frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h4, &frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(commitment_h4, &empty_frontier_h3),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(commitment_h3, &frontier_h4),
            None
        );
        assert_eq!(
            MerkleTree::<F>::restore_from_frontier(commitment_h4, &frontier_h3),
            None
        );

        let empty_restore_3 =
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h3, &empty_frontier_h3)
                .unwrap();
        assert_eq!(empty_restore_3.num_leaves(), 0);
        let empty_restore_4 =
            MerkleTree::<F>::restore_from_frontier(empty_commitment_h4, &empty_frontier_h4)
                .unwrap();
        assert_eq!(empty_restore_4.num_leaves(), 0);
    }

    #[test]
    fn test_mt_restore_from_leafs() {
        test_mt_restore_from_leafs_helper::<Fq254>(39, 59);
        test_mt_restore_from_leafs_helper::<Fq377>(39, 59);
        test_mt_restore_from_leafs_helper::<Fq381>(39, 59);

        test_mt_restore_from_leafs_helper::<Fq254>(0, 1);
        test_mt_restore_from_leafs_helper::<Fq377>(0, 1);
        test_mt_restore_from_leafs_helper::<Fq381>(0, 1);
    }
    fn test_mt_restore_from_leafs_helper<F: RescueParameter>(height: u8, count: u64) {
        let height = height / 13 + 1; // cap it to ~20
        let capacity = (3_u64).checked_pow(height as u32).unwrap();
        let count = count % capacity;
        let mut full_tree = MerkleTree::<F>::new(height).unwrap();
        let mut full_array = Vec::new();
        let mut rng = ark_std::test_rng();
        for _ in 0..count {
            let val = F::rand(&mut rng);
            full_tree.push(val);
            full_array.push(val);
        }
        let idx = full_array.len() as u64 - 1;
        let mut builder = FilledMTBuilder::new(height).unwrap();
        for leaf in &full_array {
            builder.push(*leaf);
        }
        let built_full = builder.build();
        assert_eq!(full_tree.get_leaf(idx), built_full.get_leaf(idx));
        assert_eq!(full_tree.root.value(), built_full.root.value());
    }

    #[test]
    fn test_mt_batch_insertion() {
        test_mt_batch_insertion_helper::<Fq254>(52, 59, 25);
        test_mt_batch_insertion_helper::<Fq377>(52, 59, 25);
        test_mt_batch_insertion_helper::<Fq381>(52, 59, 25);
    }
    fn test_mt_batch_insertion_helper<F: RescueParameter>(
        height: u8,
        initial_count: u64,
        batch_count: u64,
    ) {
        let height = height / 13 + 1; // cap it to ~20
        let capacity = (3_u64).checked_pow(height as u32).unwrap();
        let initial_count = initial_count % capacity;
        let mut full_tree = MerkleTree::<F>::new(height).unwrap();
        let mut rng = ark_std::test_rng();
        for _ in 0..initial_count {
            let val = F::rand(&mut rng);
            full_tree.push(val);
        }

        let frontier = full_tree.frontier();
        let commitment = full_tree.commitment();

        let mut sparse_tree = MerkleTree::restore_from_frontier(commitment, &frontier).unwrap();
        let full_to_take = full_tree.clone();
        let sparse_to_take = sparse_tree.clone();

        let mut builder_from_full = FilledMTBuilder::from_existing(full_to_take).unwrap();
        let mut builder_from_sparse = FilledMTBuilder::from_existing(sparse_to_take).unwrap();
        let mut builder_from_frontier =
            FilledMTBuilder::from_frontier(&commitment, &frontier).unwrap();

        for ix in initial_count..initial_count + batch_count {
            let val = F::rand(&mut rng);
            full_tree.push(val);
            sparse_tree.push(val);
            if ix > 0 {
                sparse_tree.forget(ix - 1);
            }
            builder_from_full.push(val);
            builder_from_sparse.push(val);
            builder_from_frontier.push(val);
        }
        let built_full = builder_from_full.build();
        let built_sparse = builder_from_sparse.build_pruned();
        let (frontier_out, commitment_out) = builder_from_frontier.into_frontier_and_commitment();
        let num_leaves = initial_count + batch_count;
        let idx = num_leaves - 1;

        assert_eq!(num_leaves, full_tree.num_leaves());
        assert_eq!(num_leaves, sparse_tree.num_leaves());
        assert_eq!(num_leaves, built_full.num_leaves());
        assert_eq!(num_leaves, built_sparse.num_leaves());
        assert_eq!(num_leaves, commitment_out.num_leaves);

        let full_leaf_proof = full_tree.get_leaf(idx);
        assert_eq!(full_leaf_proof, sparse_tree.get_leaf(idx));
        assert_eq!(full_leaf_proof, built_full.get_leaf(idx));
        assert_eq!(full_leaf_proof, built_sparse.get_leaf(idx));

        let root_value = full_tree.root.value();
        assert_eq!(root_value, built_full.root.value());
        assert_eq!(root_value, sparse_tree.root.value());
        assert_eq!(root_value, built_sparse.root.value());

        let full_tree_frontier = full_tree.frontier();
        let sparse_tree_frontier = sparse_tree.frontier();
        let built_full_frontier = built_full.frontier();
        let built_sparse_frontier = built_sparse.frontier();

        assert_eq!(full_tree_frontier, sparse_tree_frontier);
        assert_eq!(full_tree_frontier, built_full_frontier);
        assert_eq!(full_tree_frontier, built_sparse_frontier);
        assert_eq!(full_tree_frontier, frontier_out);

        let full_tree_commitment = full_tree.commitment();
        let sparse_tree_commitment = sparse_tree.commitment();
        let built_full_commitment = built_full.commitment();
        let built_sparse_commitment = built_sparse.commitment();

        assert_eq!(full_tree_commitment, sparse_tree_commitment);
        assert_eq!(full_tree_commitment, built_full_commitment);
        assert_eq!(full_tree_commitment, built_sparse_commitment);
        assert_eq!(full_tree_commitment, commitment_out);
    }
}
