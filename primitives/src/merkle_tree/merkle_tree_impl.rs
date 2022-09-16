// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.
use super::{ElementType, Hasher, LookupResult, MerkleTree};
use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::{borrow::Borrow, boxed::Box, marker::PhantomData, string::ToString, vec, vec::Vec};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleTreeImpl<E, H, LeafArity, TreeArity, F>
where
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    root: Box<MerkleNode<E, F>>,
    height: usize,
    capacity: u64,
    num_leaves: u64,

    _phantom_h: PhantomData<H>,
    _phantom_la: PhantomData<LeafArity>,
    _phantom_ta: PhantomData<TreeArity>,
}

impl<E, H, LeafArity, TreeArity, F> MerkleTree<F> for MerkleTreeImpl<E, H, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: Hasher<F>,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    type ElementType = E;
    type Hasher = H;
    type LeafArity = LeafArity;
    type TreeArity = TreeArity;
    type Proof = MerkleProof<E, F>;
    type BatchProof = MerkleNode<E, F>;

    fn build(
        height: usize,
        data: impl Iterator<Item = Self::ElementType>,
    ) -> Result<Self, PrimitivesError> {
        let capacity = Self::calculate_capacity(height);
        let (root, num_leaves) = Self::build_tree_internal(height, capacity, data)?;
        Ok(MerkleTreeImpl {
            root,
            height,
            capacity,
            num_leaves,
            _phantom_h: PhantomData,
            _phantom_la: PhantomData,
            _phantom_ta: PhantomData,
        })
    }

    fn height(&self) -> usize {
        self.height
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    fn value(&self) -> F {
        self.root.value()
    }

    fn lookup(&self, pos: u64) -> LookupResult<(), Self::Proof> {
        let mut mpos = pos;
        if mpos >= self.num_leaves {
            return LookupResult::EmptyLeaf;
        }
        let mut subtree_size = self.capacity / TreeArity::to_u64();
        let mut path = vec![];
        let mut proof: Vec<MerkleNode<E, F>> = vec![];
        let mut cur = self.root.borrow();
        for _ in 1..self.height {
            match cur {
                MerkleNode::Leaf {
                    value: _,
                    children: _,
                } => {
                    path.push(mpos as usize);
                    proof.push(cur.clone());
                },
                MerkleNode::Branch { value: _, children } => {
                    let branch = (mpos / subtree_size) as usize;
                    path.push(branch);
                    proof.push(MerkleNode::Branch {
                        value: F::zero(),
                        children: children
                            .iter()
                            .map(|node| {
                                Box::new(MerkleNode::ForgettenSubtree {
                                    value: node.value(),
                                })
                            })
                            .collect_vec(),
                    });
                    cur = &children[branch];
                    mpos %= TreeArity::to_u64();
                    subtree_size /= TreeArity::to_u64();
                },
                MerkleNode::EmptySubtree => return LookupResult::EmptyLeaf,
                MerkleNode::ForgettenSubtree { value: _ } => return LookupResult::NotInMemory,
            }
        }
        LookupResult::Ok((), MerkleProof { pos, path, proof })
    }

    fn verify(&self, _pos: u64, proof: impl Borrow<Self::Proof>) -> Result<bool, PrimitivesError> {
        let proof = proof.borrow();
        let computed_root_value = proof.path.iter().zip(proof.proof.iter()).rev().fold(
            Ok(F::zero()),
            |result, (branch, node)| -> Result<F, PrimitivesError> {
                match result {
                    Ok(val) => match node {
                        MerkleNode::Leaf { value: _, children } => Ok(Self::digest_leaf(children)),
                        MerkleNode::Branch { value: _, children } => {
                            let mut data = children.iter().map(|node| node.value()).collect_vec();
                            data[*branch] = val;
                            Ok(H::digest(&data))
                        },
                        _ => Err(PrimitivesError::ParameterError("Invalid proof".to_string())),
                    },
                    Err(e) => Err(e),
                }
            },
        )?;
        Ok(computed_root_value == self.root.value())
    }
}

impl<E, H, LeafArity, TreeArity, F> MerkleTreeImpl<E, H, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: Hasher<F>,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    /// Helper function to calculate the tree capacity
    fn calculate_capacity(height: usize) -> u64 {
        let mut capacity = LeafArity::to_u64();
        for _i in 1..height {
            capacity *= TreeArity::to_u64();
        }
        capacity
    }

    fn build_tree_internal<I>(
        height: usize,
        capacity: u64,
        iter: I,
    ) -> Result<(Box<MerkleNode<E, F>>, u64), PrimitivesError>
    where
        I: Iterator<Item = E>,
    {
        let leaves: Vec<_> = iter.collect();
        let num_leaves = leaves.len() as u64;

        if num_leaves > capacity {
            Err(PrimitivesError::ParameterError(
                "Too many data for merkle tree".to_string(),
            ))
        } else if num_leaves > 0 {
            let mut cur_nodes = leaves
                .into_iter()
                .chunks(LeafArity::to_usize())
                .into_iter()
                .map(|chunk| {
                    let children = chunk
                        .map(|node| Box::new(node))
                        .pad_using(LeafArity::to_usize(), |_| Box::new(E::default()))
                        .collect_vec();
                    Box::new(MerkleNode::<E, F>::Leaf {
                        value: Self::digest_leaf(children.as_slice()),
                        children,
                    })
                })
                .collect_vec();
            for _ in 1..height {
                cur_nodes = cur_nodes
                    .into_iter()
                    .chunks(TreeArity::to_usize())
                    .into_iter()
                    .map(|chunk| {
                        let children = chunk
                            .pad_using(TreeArity::to_usize(), |_| {
                                Box::new(MerkleNode::<E, F>::EmptySubtree)
                            })
                            .collect_vec();
                        Box::new(MerkleNode::<E, F>::Branch {
                            value: Self::digest_branch(&children),
                            children,
                        })
                    })
                    .collect_vec();
            }
            Ok((cur_nodes[0].clone(), num_leaves))
        } else {
            Ok((Box::new(MerkleNode::<E, F>::EmptySubtree), 0))
        }
    }

    fn digest_leaf(data: &[Box<E>]) -> F {
        let data = data
            .iter()
            .map(|elem| -> &[F] { elem.as_slice_ref() })
            .collect_vec()
            .concat();
        H::digest(&data)
    }

    fn digest_branch(data: &[Box<MerkleNode<E, F>>]) -> F {
        let data = data.iter().map(|node| node.value()).collect_vec();
        H::digest(&data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MerkleNode<E, F: Field> {
    EmptySubtree,
    Branch {
        value: F,
        children: Vec<Box<MerkleNode<E, F>>>,
    },
    Leaf {
        value: F,
        children: Vec<Box<E>>,
    },
    ForgettenSubtree {
        value: F,
    },
}

impl<E, F: Field> MerkleNode<E, F> {
    /// Returns the value of this [`MerkleNode`].
    #[inline]
    pub(crate) fn value(&self) -> F {
        match self {
            Self::EmptySubtree => F::zero(),
            Self::Branch { value, children: _ } => *value,
            Self::Leaf { value, children: _ } => *value,
            Self::ForgettenSubtree { value } => *value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleProof<E, F: Field> {
    /// Proof of inclusion for element at index `pos`
    pub pos: u64,
    /// Branch index
    pub path: Vec<usize>,
    /// root of proof path
    pub proof: Vec<MerkleNode<E, F>>,
}
