// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

use super::{
    AppendableMerkleTree, ElementType, Hasher, IndexType, LookupResult, MerkleTree,
    UpdatableMerkleTree,
};
use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::{borrow::Borrow, boxed::Box, marker::PhantomData, string::ToString, vec, vec::Vec};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: Hasher<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    root: Box<MerkleNode<E, F>>,
    height: usize,
    capacity: I,
    num_leaves: I,

    _phantom_h: PhantomData<H>,
    _phantom_la: PhantomData<LeafArity>,
    _phantom_ta: PhantomData<TreeArity>,
}

impl<E, H, I, LeafArity, TreeArity, F> MerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: Hasher<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    type ElementType = E;
    type Hasher = H;
    type IndexType = I;
    type LeafArity = LeafArity;
    type TreeArity = TreeArity;
    type Proof = MerkleProof<E, F, I>;
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

    fn capacity(&self) -> Self::IndexType {
        self.capacity
    }

    fn num_leaves(&self) -> Self::IndexType {
        self.num_leaves
    }

    fn value(&self) -> F {
        self.root.value()
    }

    fn lookup(&self, pos: Self::IndexType) -> LookupResult<Self::ElementType, Self::Proof> {
        if pos >= self.num_leaves {
            return LookupResult::EmptyLeaf;
        }

        let mut proof: Vec<MerkleNode<E, F>> = vec![];
        let mut cur = self.root.borrow();
        let mut branches = Self::index_to_branches(pos, self.height);
        branches.reverse();
        let mut leaf_value = Self::ElementType::default();
        for depth in 0..self.height {
            match cur {
                MerkleNode::Leaf { value: _, children } => {
                    proof.push(cur.clone());
                    leaf_value = *children[branches[depth]];
                },
                MerkleNode::Branch { value: _, children } => {
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
                    cur = &children[branches[depth]];
                },
                MerkleNode::EmptySubtree => return LookupResult::EmptyLeaf,
                MerkleNode::ForgettenSubtree { value: _ } => return LookupResult::NotInMemory,
            }
        }
        LookupResult::Ok(leaf_value, MerkleProof { pos, proof })
    }

    fn verify(
        &self,
        _pos: Self::IndexType,
        proof: impl Borrow<Self::Proof>,
    ) -> Result<bool, PrimitivesError> {
        let proof = proof.borrow();
        let computed_root_value = Self::index_to_branches(proof.pos, self.height)
            .iter()
            .zip(proof.proof.iter().rev())
            .fold(
                Ok(F::zero()),
                |result, (branch, node)| -> Result<F, PrimitivesError> {
                    match result {
                        Ok(val) => match node {
                            MerkleNode::Leaf { value: _, children } => {
                                Ok(Self::digest_leaf(children))
                            },
                            MerkleNode::Branch { value: _, children } => {
                                let mut data =
                                    children.iter().map(|node| node.value()).collect_vec();
                                data[*branch] = val;
                                Ok(H::digest(&data))
                            },
                            _ => Err(PrimitivesError::ParameterError(
                                "Incompatible proof for this merkle tree".to_string(),
                            )),
                        },
                        Err(e) => Err(e),
                    }
                },
            )?;
        Ok(computed_root_value == self.root.value())
    }
}

impl<E, H, I, LeafArity, TreeArity, F> AppendableMerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: Hasher<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    fn push(&mut self, elem: &Self::ElementType) -> Result<(), PrimitivesError> {
        if self.num_leaves == self.capacity {
            return Err(PrimitivesError::InternalError(
                "Merkle tree full".to_string(),
            ));
        }
        self.update_internal(self.num_leaves, elem)?;
        self.num_leaves += 1;
        Ok(())
    }

    fn extend(
        &mut self,
        elems: impl Iterator<Item = Self::ElementType>,
    ) -> Result<(), PrimitivesError> {
        // TODO(Chengyu): efficient batch insert
        for elem in elems {
            self.push(&elem)?;
        }
        Ok(())
    }
}

impl<E, H, I, LeafArity, TreeArity, F> UpdatableMerkleTree<F>
    for MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: Hasher<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    fn update(
        &mut self,
        pos: Self::IndexType,
        elem: &Self::ElementType,
    ) -> Result<(), PrimitivesError> {
        self.num_leaves = self.num_leaves.max(pos);
        self.update_internal(pos, elem)
    }
}

impl<E, H, I, LeafArity, TreeArity, F> MerkleTreeImpl<E, H, I, LeafArity, TreeArity, F>
where
    E: ElementType<F>,
    H: Hasher<F>,
    I: IndexType,
    LeafArity: Unsigned,
    TreeArity: Unsigned,
    F: Field,
{
    /// Helper function to calculate the tree capacity
    fn calculate_capacity(height: usize) -> I {
        let mut capacity = I::from(LeafArity::to_u64());
        for _i in 1..height {
            capacity *= TreeArity::to_u64();
        }
        capacity
    }

    /// Return a vector of branching index from leaf to root for a given index
    fn index_to_branches(pos: I, height: usize) -> Vec<usize> {
        let mut pos = pos;
        let mut ret = vec![(pos % LeafArity::to_u64()).as_()];
        pos /= LeafArity::to_u64();
        for _i in 1..height {
            ret.push((pos % TreeArity::to_u64()).as_());
            pos /= TreeArity::to_u64();
        }
        ret
    }

    fn build_tree_internal<Iter>(
        height: usize,
        capacity: I,
        iter: Iter,
    ) -> Result<(Box<MerkleNode<E, F>>, I), PrimitivesError>
    where
        Iter: Iterator<Item = E>,
    {
        let leaves: Vec<_> = iter.collect();
        let num_leaves = I::from(leaves.len() as u64);

        if num_leaves > capacity {
            Err(PrimitivesError::ParameterError(
                "Too many data for merkle tree".to_string(),
            ))
        } else if num_leaves > I::zero() {
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
            Ok((Box::new(MerkleNode::<E, F>::EmptySubtree), I::zero()))
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

    fn update_internal(&mut self, pos: I, elem: &E) -> Result<(), PrimitivesError> {
        let branches = Self::index_to_branches(pos, self.height);
        Self::update_node_internal(&mut self.root, self.height, &branches, elem)
    }

    fn update_node_internal(
        node: &mut Box<MerkleNode<E, F>>,
        depth: usize,
        branches: &[usize],
        elem: &E,
    ) -> Result<(), PrimitivesError> {
        if depth == 1 {
            if let MerkleNode::Leaf {
                ref mut value,
                ref mut children,
            } = **node
            {
                *children[branches[depth - 1]] = *elem;
                *value = Self::digest_leaf(children);
            } else {
                return Err(PrimitivesError::InternalError(
                    "Inconsistent merkle tree".to_string(),
                ));
            }
        } else if let MerkleNode::<E, F>::Branch {
            value: _,
            ref mut children,
        } = **node
        {
            let child = &mut children[branches[depth - 1]];
            match **child {
                MerkleNode::<E, F>::Branch {
                    value: _,
                    children: _,
                } => Self::update_node_internal(child, depth - 1, branches, elem)?,
                MerkleNode::<E, F>::Leaf {
                    value: _,
                    children: _,
                } => Self::update_node_internal(child, depth - 1, branches, elem)?,

                MerkleNode::<E, F>::ForgettenSubtree { value: _ } => {
                    return Err(PrimitivesError::InternalError(
                        "Couldn't update the given position: merkle tree data not in memory"
                            .to_string(),
                    ))
                },

                MerkleNode::<E, F>::EmptySubtree => {
                    **child = if depth == 2 {
                        let mut children = vec![Box::new(E::default()); LeafArity::to_usize()];
                        *children[branches[depth - 1]] = *elem;
                        MerkleNode::<E, F>::Leaf {
                            value: Self::digest_leaf(&children),
                            children,
                        }
                    } else {
                        let mut children =
                            vec![Box::new(MerkleNode::EmptySubtree); TreeArity::to_usize()];
                        Self::update_node_internal(
                            &mut children[branches[depth - 1]],
                            depth - 1,
                            branches,
                            elem,
                        )?;
                        MerkleNode::<E, F>::Branch {
                            value: Self::digest_branch(&children),
                            children,
                        }
                    }
                },
            }
        } else {
            return Err(PrimitivesError::InternalError(
                "Inconsistent merkle tree".to_string(),
            ));
        }
        Ok(())
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
pub struct MerkleProof<E, F: Field, I: IndexType> {
    /// Proof of inclusion for element at index `pos`
    pub pos: I,
    /// Nodes of proof path, from root to leaf
    pub proof: Vec<MerkleNode<E, F>>,
}

// TODO(Chengyu): unit tests
// #[cfg(test)]
// mod mt_tests {
//     use crate::{merkle_tree::*, rescue::RescueParameter};
//     use ark_ed_on_bls12_377::Fq as Fq377;
//     use ark_ed_on_bls12_381::Fq as Fq381;
//     use ark_ed_on_bn254::Fq as Fq254;

//     #[test]
//     fn test_empty_tree() {
//         test_empty_tree_helper::<Fq254>();
//         test_empty_tree_helper::<Fq377>();
//         test_empty_tree_helper::<Fq381>();
//     }

//     fn test_empty_tree_helper<F: RescueParameter>() {
//         let merkle_tree = MerkleTree::build(10, &[].iter());
//     }
// }
