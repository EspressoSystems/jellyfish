use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::borrow::Borrow;
use typenum::Unsigned;

pub trait MerkleTree<F: Field> {
    type ElementType: Default + CanonicalDeserialize + CanonicalSerialize;
    type HashAlgorithm;
    type LeafArity: Unsigned;
    type TreeArity: Unsigned;
    type Proof;
    type BatchProof;

    fn new(height: usize, data: &[Self::ElementType]) -> Result<(), PrimitivesError>;

    fn capacity(&self) -> usize;
    fn num_leaves(&self) -> usize;

    fn value(&self) -> F;

    fn gen_proof(&self, idx: usize) -> Result<Self::Proof, PrimitivesError>;
    fn verify(&self, idx: usize, proof: impl Borrow<Self::Proof>) -> Result<(), PrimitivesError>;

    fn batch_proof(&self, idx: &[usize]) -> Result<Self::BatchProof, PrimitivesError>;
    fn batch_verify(
        &self,
        idx: &[usize],
        proof: impl Borrow<Self::BatchProof>,
    ) -> Result<(), PrimitivesError>;
}

pub trait AppendableMerkleTree<F: Field>: MerkleTree<F> {
    fn append(&mut self, element: &Self::ElementType) -> Result<(), PrimitivesError>;
}

pub trait UpdatableMerkleTree<F: Field>: MerkleTree<F> {
    fn update(&mut self, idx: usize, element: &Self::ElementType) -> Result<(), PrimitivesError>;
}

pub trait ForgetableMerkleTree<F: Field>: MerkleTree<F> {
    fn forget(&mut self, idx: usize) -> Result<(), PrimitivesError>;
    fn remember(
        &mut self,
        idx: usize,
        element: &Self::ElementType,
        proof: Self::Proof,
    ) -> Result<(), PrimitivesError>;
}
