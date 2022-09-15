// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{ElementType, Hasher, LookupResult, MerkleTree};
use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::{borrow::Borrow, boxed::Box, marker::PhantomData, string::ToString, vec::Vec};
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
    height: u8,
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
    type Proof = MerkleNode<E, F>;
    type BatchProof = MerkleNode<E, F>;

    fn build(
        height: u8,
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

    fn height(&self) -> u8 {
        self.height
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn num_leaves(&self) -> u64 {
        self.num_leaves
    }

    fn value(&self) -> F {
        F::zero()
    }

    fn lookup(&self, _pos: usize) -> LookupResult<(), Self::Proof> {
        todo!()
    }

    fn verify(&self, _pos: usize, _proof: impl Borrow<Self::Proof>) -> Result<(), Option<F>> {
        todo!()
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
    fn calculate_capacity(height: u8) -> u64 {
        let mut capacity = LeafArity::to_u64();
        for _i in 1..height {
            capacity *= TreeArity::to_u64();
        }
        capacity
    }

    fn build_tree_internal<I>(
        height: u8,
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
                                Box::new(MerkleNode::<E, F>::EmptySubtree { value: F::zero() })
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
            Ok((
                Box::new(MerkleNode::<E, F>::EmptySubtree { value: F::zero() }),
                0,
            ))
        }
    }

    fn digest_leaf(_data: &[Box<E>]) -> F {
        todo!()
    }

    fn digest_branch(data: &[Box<MerkleNode<E, F>>]) -> F {
        let data = data.iter().map(|node| node.value()).collect_vec();
        H::digest(&data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MerkleNode<E, F: Field> {
    EmptySubtree {
        value: F,
    },
    Branch {
        value: F,
        children: Vec<Box<MerkleNode<E, F>>>,
    },
    Leaf {
        value: F,
        children: Vec<Box<E>>,
    },
}

impl<E, F: Field> MerkleNode<E, F> {
    /// Returns the value of this [`MerkleNode`].
    pub(crate) fn value(&self) -> F {
        match self {
            Self::Branch { value, children: _ } => *value,
            Self::Leaf { value, children: _ } => *value,
            Self::EmptySubtree { value } => *value,
        }
    }
}
