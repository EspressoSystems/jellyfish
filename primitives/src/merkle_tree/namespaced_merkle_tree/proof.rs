use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{string::ToString, vec::Vec};
use core::{fmt::Debug, marker::PhantomData};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use typenum::Unsigned;

use crate::{
    errors::{PrimitivesError, VerificationResult},
    merkle_tree::{internal::MerkleProof, DigestAlgorithm, MerkleTreeScheme, NodeValue},
};

use super::{
    hash::NamespacedHash, BindNamespace, Element, InnerTree, Namespace, NamespaceProof, Namespaced,
};

/// Indicates whether the namespace proof represents a populated set or an empty
/// set
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum NamespaceProofType {
    Presence,
    Absence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "E: CanonicalSerialize + CanonicalDeserialize,
                 T: CanonicalSerialize + CanonicalDeserialize,")]
/// Namespace Proof
pub struct NaiveNamespaceProof<E, T, Arity, N, H>
where
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    N: Namespace,
    Arity: Unsigned,
{
    pub(crate) proof_type: NamespaceProofType,
    // TODO(#140) Switch to a batch proof
    pub(crate) proofs: Vec<MerkleProof<E, u64, NamespacedHash<T, N>, Arity>>,
    pub(crate) left_boundary_proof: Option<MerkleProof<E, u64, NamespacedHash<T, N>, Arity>>,
    pub(crate) right_boundary_proof: Option<MerkleProof<E, u64, NamespacedHash<T, N>, Arity>>,
    pub(crate) first_index: u64,
    pub(crate) phantom: PhantomData<H>,
}
impl<E, T, Arity, N, H> NamespaceProof for NaiveNamespaceProof<E, T, Arity, N, H>
where
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    N: Namespace,
    Arity: Unsigned,
{
    type Leaf = E;
    type Node = T;
    type Namespace = N;

    fn get_namespace_leaves(&self) -> Vec<&Self::Leaf> {
        let num_leaves = match self.proof_type {
            NamespaceProofType::Presence => self.proofs.len(),
            NamespaceProofType::Absence => 0,
        };
        self.proofs
            .iter()
            // This unwrap is safe assuming that the proof is valid
            .map(|proof| proof.elem().unwrap())
            .take(num_leaves)
            .collect_vec()
    }

    fn verify(
        &self,
        root: &NamespacedHash<T, N>,
        namespace: N,
    ) -> Result<VerificationResult, PrimitivesError> {
        match self.proof_type {
            NamespaceProofType::Presence => self.verify_presence_proof(root, namespace),
            NamespaceProofType::Absence => self.verify_absence_proof(root, namespace),
        }
    }
}

impl<E, T, Arity, N, H> NaiveNamespaceProof<E, T, Arity, N, H>
where
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    N: Namespace,
    Arity: Unsigned,
{
    fn verify_left_namespace_boundary(
        &self,
        root: &NamespacedHash<T, N>,
        namespace: N,
    ) -> Result<VerificationResult, PrimitivesError> {
        if let Some(boundary_proof) = self.left_boundary_proof.as_ref() {
            // If there is a leaf to the left of the namespace range, check that it is less
            // than the target namespace
            if boundary_proof
                .elem()
                .ok_or(PrimitivesError::InconsistentStructureError(
                    "Boundary proof does not contain an element".into(),
                ))?
                .get_namespace()
                >= namespace
                || *boundary_proof.index() != self.first_index - 1
            {
                return Ok(Err(()));
            }
            // Verify the boundary proof
            if <InnerTree<E, H, T, N, Arity>>::verify(root, boundary_proof.index(), boundary_proof)?
                .is_err()
            {
                return Ok(Err(()));
            }
        } else {
            // If there is no left boundary, ensure that target namespace is the tree's
            // minimum namespace
            if root.min_namespace != namespace {
                return Ok(Err(()));
            }
        }
        Ok(Ok(()))
    }

    fn verify_right_namespace_boundary(
        &self,
        root: &NamespacedHash<T, N>,
        namespace: N,
    ) -> Result<VerificationResult, PrimitivesError> {
        if let Some(boundary_proof) = self.right_boundary_proof.as_ref() {
            // If there is a leaf to the left of the namespace range, check that it is less
            // than the target namespace
            if boundary_proof
                .elem()
                .ok_or(PrimitivesError::InconsistentStructureError(
                    "Boundary proof does not contain an element".to_string(),
                ))?
                .get_namespace()
                <= namespace
                || *boundary_proof.index() != self.first_index + self.proofs.len() as u64
            {
                return Ok(Err(()));
            }
            // Verify the boundary proof
            if <InnerTree<E, H, T, N, Arity>>::verify(root, boundary_proof.index(), boundary_proof)?
                .is_err()
            {
                return Ok(Err(()));
            }
        } else {
            // If there is no left boundary, ensure that target namespace is the tree's
            // minimum namespace
            if root.max_namespace != namespace {
                return Ok(Err(()));
            }
        }
        Ok(Ok(()))
    }

    fn verify_absence_proof(
        &self,
        root: &NamespacedHash<T, N>,
        namespace: N,
    ) -> Result<VerificationResult, PrimitivesError> {
        if namespace < root.min_namespace || namespace > root.max_namespace {
            // Easy case where the namespace isn't covered by the range of the tree root
            return Ok(Ok(()));
        } else {
            // Harder case: Find an element whose namespace is greater than our
            // target and show that the namespace to the left is less than our
            // target
            let left_proof = &self.left_boundary_proof.as_ref().cloned().ok_or(
                PrimitivesError::InconsistentStructureError(
                    "Left Boundary proof must be present".into(),
                ),
            )?;
            let right_proof = &self.right_boundary_proof.as_ref().cloned().ok_or(
                PrimitivesError::InconsistentStructureError(
                    "Right boundary proof must be present".into(),
                ),
            )?;
            let left_index = left_proof.index();
            let left_ns = left_proof
                .elem()
                .ok_or(PrimitivesError::InconsistentStructureError(
                    "The left boundary proof is missing an element".into(),
                ))?
                .get_namespace();
            let right_index = right_proof.index();
            let right_ns = right_proof
                .elem()
                .ok_or(PrimitivesError::InconsistentStructureError(
                    "The left boundary proof is missing an element".into(),
                ))?
                .get_namespace();
            // Ensure that leaves are adjacent
            if *right_index != left_index + 1 {
                return Ok(Err(()));
            }
            // And that our target namespace is in between the leaves'
            // namespaces
            if namespace <= left_ns || namespace >= right_ns {
                return Ok(Err(()));
            }
            // Verify the boundary proofs
            if <InnerTree<E, H, T, N, Arity>>::verify(root, left_proof.index(), left_proof)?
                .is_err()
            {
                return Ok(Err(()));
            }
            if <InnerTree<E, H, T, N, Arity>>::verify(root, right_proof.index(), right_proof)?
                .is_err()
            {
                return Ok(Err(()));
            }
        }

        Ok(Ok(()))
    }

    fn verify_presence_proof(
        &self,
        root: &NamespacedHash<T, N>,
        namespace: N,
    ) -> Result<VerificationResult, PrimitivesError> {
        let mut last_idx: Option<u64> = None;
        for (idx, proof) in self.proofs.iter().enumerate() {
            let leaf_index = self.first_index + idx as u64;
            if <InnerTree<E, H, T, N, Arity>>::verify(root, leaf_index, proof)?.is_err() {
                return Ok(Err(()));
            }
            if proof
                .elem()
                .ok_or(PrimitivesError::InconsistentStructureError(
                    "Missing namespace element".into(),
                ))?
                .get_namespace()
                != namespace
            {
                return Ok(Err(()));
            }
            // Indices must be sequential, this checks that there are no gaps in the
            // namespace
            if let Some(prev_index) = last_idx {
                if leaf_index != prev_index + 1 {
                    return Ok(Err(()));
                }
                last_idx = Some(leaf_index);
            }
        }
        // Verify that the proof contains the left boundary of the namespace
        if self
            .verify_left_namespace_boundary(root, namespace)
            .is_err()
        {
            return Ok(Err(()));
        }

        // Verify that the proof contains the right boundary of the namespace
        if self
            .verify_right_namespace_boundary(root, namespace)
            .is_err()
        {
            return Ok(Err(()));
        }

        Ok(Ok(()))
    }
}
