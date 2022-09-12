use ark_ff::Field;
use ark_std::{boxed::Box, vec::Vec};

pub struct MerkleTreeImpl {}

enum MerkleNode<E, F: Field> {
    EmptySubtree,
    Branch {
        value: F,
        children: Vec<Box<MerkleNode<E, F>>>,
    },
    Leaf {
        value: F,
        elem: E,
    },
}
