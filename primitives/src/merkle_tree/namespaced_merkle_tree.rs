// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a Namespaced Merkle Tree.
use alloc::vec;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{string::ToString, vec::Vec};
use core::{borrow::Borrow, fmt::Debug, hash::Hash, marker::PhantomData, ops::Range};
use hashbrown::{hash_map::Entry, HashMap};
use itertools::Itertools;
use typenum::Unsigned;

use crate::errors::{PrimitivesError, VerificationResult};

use super::{
    append_only::MerkleTree, internal::MerkleProof, AppendableMerkleTreeScheme, DigestAlgorithm,
    Element, Index, LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue,
};

/// Namespaced Merkle Tree where leaves are sorted by a namespace identifier.
/// The data structure supports namespace inclusion proofs.
pub trait NamespacedMerkleTreeScheme: AppendableMerkleTreeScheme
where
    Self::Element: Namespaced,
{
    /// Namespace proof type
    type NamespaceProof: NamespaceProof;
    /// Namespace type
    type NamespaceId: Namespace;

    /// Returns the entire set of leaves corresponding to a given namespace and
    /// a completeness proof.
    fn get_namespace_proof(&self, namespace: Self::NamespaceId) -> Self::NamespaceProof;

    /// Verifies the completeness proof for a given set of leaves and a
    /// namespace.
    fn verify_namespace_proof(
        &self,
        proof: &Self::NamespaceProof,
        namespace: Self::NamespaceId,
    ) -> Result<VerificationResult, PrimitivesError>;
}

/// NamespacedHasher wraps a standard hash function (implementer of
/// DigestAlgorithm), turning it into a hash function that tags internal nodes
/// with namespace ranges.
#[derive(Debug, Clone)]
pub struct NamespacedHasher<H, E, I, T, N>
where
    H: DigestAlgorithm<E, I, T>,
    E: Element + Namespaced<Namespace = N>,
    N: Namespace,
    I: Index,
    T: NodeValue,
{
    phantom1: PhantomData<H>,
    phantom2: PhantomData<E>,
    phantom3: PhantomData<I>,
    phantom4: PhantomData<T>,
    phantom5: PhantomData<N>,
}

/// Completeness proof for a namespace
pub trait NamespaceProof {
    /// Namespace type
    type Namespace: Namespace;
    /// Namespaced leaf
    type Leaf: Element + Namespaced<Namespace = Self::Namespace>;
    /// Internal node value
    type Node: NodeValue;

    /// Return the set of leaves associated with this Namespace proof
    fn get_namespace_leaves(&self) -> Vec<&Self::Leaf>;

    /// Verify a namespace proof
    fn verify(
        &self,
        root: &NamespacedHash<Self::Node, Self::Namespace>,
        namespace: Self::Namespace,
    ) -> Result<VerificationResult, PrimitivesError>;
}

/// Trait indicating that a leaf has a namespace.
pub trait Namespaced {
    /// Namespace type
    type Namespace: Namespace;
    /// Returns the namespace of the leaf
    fn get_namespace(&self) -> Self::Namespace;
}

/// Trait indicating that a digest algorithm can commit to
/// a namespace range.
pub trait BindNamespace<E, I, T, N>: DigestAlgorithm<E, I, T>
where
    E: Element,
    N: Namespace,
    T: NodeValue,
    I: Index,
{
    /// Generate a commitment that binds a node to a namespace range
    fn generate_namespaced_commitment(namespaced_hash: NamespacedHash<T, N>) -> T;
}

/// Trait indiciating that a struct can act as an orderable namespace
pub trait Namespace:
    Debug + Clone + CanonicalDeserialize + CanonicalSerialize + Default + Copy + Hash + Ord
{
    /// Returns the minimum possible namespace
    fn min() -> Self;
    /// Returns the maximum possible namespace
    fn max() -> Self;
}

impl Namespace for u64 {
    fn min() -> u64 {
        u64::MIN
    }
    fn max() -> u64 {
        u64::MAX
    }
}

#[derive(
    CanonicalSerialize,
    CanonicalDeserialize,
    Hash,
    Copy,
    Clone,
    Debug,
    Default,
    Ord,
    Eq,
    PartialEq,
    PartialOrd,
)]
/// Represents a namespaced internal tree node
pub struct NamespacedHash<T, N>
where
    N: Namespace,
    T: NodeValue,
{
    min_namespace: N,
    max_namespace: N,
    hash: T,
}

impl<T, N> NamespacedHash<T, N>
where
    N: Namespace,
    T: NodeValue,
{
    /// Constructs a new NamespacedHash
    pub fn new(min_namespace: N, max_namespace: N, hash: T) -> Self {
        Self {
            min_namespace,
            max_namespace,
            hash,
        }
    }
}

impl<E, H, T, I, N> DigestAlgorithm<E, I, NamespacedHash<T, N>> for NamespacedHasher<H, E, I, T, N>
where
    E: Element + Namespaced<Namespace = N>,
    I: Index,
    N: Namespace,
    T: NodeValue,
    H: DigestAlgorithm<E, I, T> + BindNamespace<E, I, T, N>,
{
    // Assumes that data is sorted by namespace, will be enforced by "append"
    fn digest(data: &[NamespacedHash<T, N>]) -> Result<NamespacedHash<T, N>, PrimitivesError> {
        if data.is_empty() {
            return Ok(NamespacedHash::default());
        }
        let first_node = data[0];
        let min_namespace = first_node.min_namespace;
        let mut max_namespace = first_node.max_namespace;
        let mut nodes = vec![H::generate_namespaced_commitment(first_node)];
        for node in &data[1..] {
            if node == &NamespacedHash::default() {
                continue;
            }
            // Ensure that namespaced nodes are sorted
            if node.min_namespace < max_namespace {
                return Err(PrimitivesError::InternalError(
                    "Namespace Merkle tree leaves are out of order".to_string(),
                ));
            }
            max_namespace = node.max_namespace;
            nodes.push(H::generate_namespaced_commitment(*node));
        }

        let inner_hash = H::digest(&nodes)?;

        Ok(NamespacedHash::new(
            min_namespace,
            max_namespace,
            inner_hash,
        ))
    }

    fn digest_leaf(pos: &I, elem: &E) -> Result<NamespacedHash<T, N>, PrimitivesError> {
        let namespace = elem.get_namespace();
        let hash = H::digest_leaf(pos, elem)?;
        Ok(NamespacedHash::new(namespace, namespace, hash))
    }
}

type InnerTree<E, H, T, N, Arity> =
    MerkleTree<E, NamespacedHasher<H, E, u64, T, N>, u64, Arity, NamespacedHash<T, N>>;

#[derive(Debug, Clone)]
/// NMT
pub struct NMT<E, H, Arity, N, T>
where
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    N: Namespace,
    Arity: Unsigned,
{
    namespace_ranges: HashMap<N, Range<u64>>,
    inner: InnerTree<E, H, T, N, Arity>,
}

impl<E, H, Arity, N, T> MerkleTreeScheme for NMT<E, H, Arity, N, T>
where
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    N: Namespace,
    Arity: Unsigned,
{
    type Element = E;
    type Index = u64;
    type NodeValue = NamespacedHash<T, N>;
    type MembershipProof = <InnerTree<E, H, T, N, Arity> as MerkleTreeScheme>::MembershipProof;
    type BatchMembershipProof =
        <InnerTree<E, H, T, N, Arity> as MerkleTreeScheme>::BatchMembershipProof;
    const ARITY: usize = <InnerTree<E, H, T, N, Arity> as MerkleTreeScheme>::ARITY;
    type Commitment = <InnerTree<E, H, T, N, Arity> as MerkleTreeScheme>::Commitment;

    fn from_elems(
        height: usize,
        elems: impl IntoIterator<Item = impl core::borrow::Borrow<Self::Element>>,
    ) -> Result<Self, PrimitivesError> {
        let mut namespace_ranges: HashMap<N, Range<u64>> = HashMap::new();
        let mut max_namespace = <N as Namespace>::min();
        let mut leaves = Vec::new();
        for (idx, elem) in elems.into_iter().enumerate() {
            let ns = elem.borrow().get_namespace();
            let idx: u64 = idx.try_into().unwrap();
            if ns < max_namespace {
                return Err(PrimitivesError::InconsistentStructureError(
                    "Namespace leaves must be pushed in sorted order".into(),
                ));
            }
            match namespace_ranges.entry(ns) {
                Entry::Occupied(entry) => {
                    entry.into_mut().end = idx + 1;
                },
                Entry::Vacant(entry) => {
                    entry.insert(idx..idx + 1);
                },
            }
            max_namespace = ns;
            leaves.push(elem);
        }
        let inner = <InnerTree<E, H, T, N, Arity> as MerkleTreeScheme>::from_elems(height, leaves)?;
        Ok(NMT {
            inner,
            namespace_ranges,
        })
    }

    fn height(&self) -> usize {
        self.inner.height()
    }

    fn capacity(&self) -> num_bigint::BigUint {
        self.inner.capacity()
    }

    fn num_leaves(&self) -> u64 {
        self.inner.num_leaves()
    }

    fn commitment(&self) -> Self::Commitment {
        self.inner.commitment()
    }

    fn lookup(
        &self,
        pos: impl Borrow<Self::Index>,
    ) -> super::LookupResult<Self::Element, Self::MembershipProof, ()> {
        self.inner.lookup(pos)
    }

    fn verify(
        root: impl Borrow<Self::NodeValue>,
        pos: impl Borrow<Self::Index>,
        proof: impl Borrow<Self::MembershipProof>,
    ) -> Result<VerificationResult, PrimitivesError> {
        <InnerTree<E, H, T, N, Arity> as MerkleTreeScheme>::verify(root, pos, proof)
    }
}

impl<E, H, Arity, N, T> AppendableMerkleTreeScheme for NMT<E, H, Arity, N, T>
where
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    N: Namespace,
    Arity: Unsigned,
{
    fn extend(
        &mut self,
        elems: impl IntoIterator<Item = impl core::borrow::Borrow<Self::Element>>,
    ) -> Result<(), PrimitivesError> {
        // TODO(#314): update namespace metadata
        self.inner.extend(elems)
    }

    fn push(
        &mut self,
        elem: impl core::borrow::Borrow<Self::Element>,
    ) -> Result<(), PrimitivesError> {
        // TODO(#314): update namespace metadata
        self.inner.push(elem)
    }
}

/// Indicates whether the namespace proof represents a populated set or an empty
/// set
#[derive(Clone, Debug)]
enum NamespaceProofType {
    Presence,
    Absence,
}

#[derive(Clone, Debug)]
/// Namespace Proof
pub struct NaiveNamespaceProof<E, T, Arity, N, H>
where
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    N: Namespace,
    Arity: Unsigned,
{
    proof_type: NamespaceProofType,
    // TODO(#140) Switch to a batch proof
    proofs: Vec<MerkleProof<E, u64, NamespacedHash<T, N>, Arity>>,
    left_boundary_proof: Option<MerkleProof<E, u64, NamespacedHash<T, N>, Arity>>,
    right_boundary_proof: Option<MerkleProof<E, u64, NamespacedHash<T, N>, Arity>>,
    first_index: u64,
    phantom: PhantomData<H>,
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

impl<E, H, Arity, N, T> NamespacedMerkleTreeScheme for NMT<E, H, Arity, N, T>
where
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N> + Clone,
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    N: Namespace,
    Arity: Unsigned,
{
    type NamespaceId = N;
    type NamespaceProof = NaiveNamespaceProof<E, T, Arity, N, H>;

    fn get_namespace_proof(&self, namespace: Self::NamespaceId) -> Self::NamespaceProof {
        let ns_range = self.namespace_ranges.get(&namespace);
        let mut proofs = Vec::new();
        let mut left_boundary_proof = None;
        let mut right_boundary_proof = None;
        let proof_type;
        let mut first_index = None;
        if let Some(ns_range) = ns_range {
            proof_type = NamespaceProofType::Presence;
            for i in ns_range.clone() {
                if first_index.is_none() {
                    first_index = Some(i);
                }
                if let LookupResult::Ok(_, proof) = self.inner.lookup(i) {
                    proofs.push(proof);
                } else {
                    // The NMT is malformed, we cannot recover
                    panic!()
                }
            }
            let left_index = first_index.unwrap_or(0);
            let right_index = left_index + proofs.len() as u64;
            if left_index > 0 {
                if let LookupResult::Ok(_, proof) = self.inner.lookup(left_index - 1) {
                    left_boundary_proof = Some(proof);
                } else {
                    // The NMT is malformed, we cannot recover
                    panic!()
                }
            }
            if right_index < self.num_leaves() - 1 {
                if let LookupResult::Ok(_, proof) = self.inner.lookup(right_index + 1) {
                    right_boundary_proof = Some(proof);
                } else {
                    // The NMT is malformed, we cannot recover
                    panic!()
                }
            }
        } else {
            proof_type = NamespaceProofType::Absence
            // TODO: This only handles the simple absence proof case where the
            // namespace is outside of the root's namespace range
        }
        NaiveNamespaceProof {
            proof_type,
            proofs,
            left_boundary_proof,
            right_boundary_proof,
            first_index: first_index.unwrap_or(0),
            phantom: PhantomData,
        }
    }

    fn verify_namespace_proof(
        &self,
        proof: &Self::NamespaceProof,
        namespace: Self::NamespaceId,
    ) -> Result<VerificationResult, PrimitivesError> {
        proof.verify(&self.commitment().digest(), namespace)
    }
}

#[cfg(test)]
mod nmt_tests {
    use digest::Digest;
    use sha3::Sha3_256;
    use typenum::U2;

    use super::*;
    use crate::merkle_tree::examples::{Sha3Digest, Sha3Node};

    type NamespaceId = u64;
    type Hasher = NamespacedHasher<Sha3Digest, Leaf, NamespaceId, Sha3Node, u64>;

    #[derive(
        Default,
        Eq,
        PartialEq,
        Hash,
        Ord,
        PartialOrd,
        Copy,
        Clone,
        Debug,
        CanonicalSerialize,
        CanonicalDeserialize,
    )]
    struct Leaf {
        namespace: NamespaceId,
    }

    impl Leaf {
        pub fn new(namespace: NamespaceId) -> Self {
            Leaf { namespace }
        }
    }

    impl Namespaced for Leaf {
        type Namespace = NamespaceId;
        fn get_namespace(&self) -> NamespaceId {
            self.namespace
        }
    }

    type TestNMT = NMT<Leaf, Sha3Digest, U2, NamespaceId, Sha3Node>;

    impl<E, I, N> BindNamespace<E, I, Sha3Node, N> for Sha3Digest
    where
        E: Element + CanonicalSerialize,
        I: Index,
        N: Namespace,
    {
        // TODO ensure the hashing of (min,max,hash) is collision resistant
        fn generate_namespaced_commitment(
            namespaced_hash: NamespacedHash<Sha3Node, N>,
        ) -> Sha3Node {
            let mut hasher = Sha3_256::new();
            let mut writer = Vec::new();
            namespaced_hash
                .min_namespace
                .serialize_compressed(&mut writer)
                .unwrap();
            namespaced_hash
                .max_namespace
                .serialize_compressed(&mut writer)
                .unwrap();
            namespaced_hash
                .hash
                .serialize_compressed(&mut writer)
                .unwrap();
            hasher.update(&mut writer);
            Sha3Node(hasher.finalize().into())
        }
    }

    #[test]
    fn test_namespaced_hash() {
        let num_leaves = 5;
        let leaves: Vec<Leaf> = (0..num_leaves).map(Leaf::new).collect();

        // Ensure that leaves are digested correctly
        let mut hashes = leaves
            .iter()
            .enumerate()
            .map(|(idx, leaf)| Hasher::digest_leaf(&(idx as u64), leaf))
            .collect::<Result<Vec<_>, PrimitivesError>>()
            .unwrap();
        assert_eq!((hashes[0].min_namespace, hashes[0].max_namespace), (0, 0));

        // Ensure that sorted internal nodes are digested correctly
        let hash = Hasher::digest(&hashes).unwrap();
        assert_eq!(
            (hash.min_namespace, hash.max_namespace),
            (0, num_leaves - 1)
        );

        // Ensure that digest errors when internal nodes are not sorted by namespace
        hashes[0] = hashes[hashes.len() - 1];
        assert!(Hasher::digest(&hashes).is_err());
    }

    #[test]
    fn test_nmt() {
        let namespaces = [1, 2, 2, 2, 3, 3, 3, 4];
        let first_ns = namespaces[0];
        let last_ns = namespaces[namespaces.len() - 1];
        let internal_ns = namespaces[1];
        let leaves: Vec<Leaf> = namespaces.iter().map(|i| Leaf::new(*i)).collect();
        let tree = TestNMT::from_elems(3, leaves.clone()).unwrap();
        let left_proof = tree.get_namespace_proof(first_ns);
        let right_proof = tree.get_namespace_proof(last_ns);
        let mut internal_proof = tree.get_namespace_proof(internal_ns);

        // Check namespace proof on the left boundary
        assert!(tree
            .verify_namespace_proof(&left_proof, first_ns)
            .unwrap()
            .is_ok());

        // Check namespace proof on the right boundary
        assert!(tree
            .verify_namespace_proof(&right_proof, last_ns)
            .unwrap()
            .is_ok());

        // Check namespace proof for some internal namespace
        assert!(tree
            .verify_namespace_proof(&internal_proof, internal_ns)
            .unwrap()
            .is_ok());

        // Assert that namespace proof fails for a different namespace
        assert!(tree
            .verify_namespace_proof(&left_proof, 2)
            .unwrap()
            .is_err());

        // Sanity check that the leaves returned by the proof are correct
        let internal_leaves: Vec<Leaf> = internal_proof
            .get_namespace_leaves()
            .into_iter()
            .copied()
            .collect();
        let raw_leaves_for_ns = &leaves[1..4];
        assert_eq!(raw_leaves_for_ns, internal_leaves);

        // Check that a namespace proof fails if one of the leaves is removed
        internal_proof.proofs.remove(1);
        assert!(tree
            .verify_namespace_proof(&internal_proof, internal_ns)
            .unwrap()
            .is_err());

        // Check the simple absence proof case when the namespace falls outside of the
        // tree range
        let absence_proof = tree.get_namespace_proof(last_ns + 1);
        let leaves: Vec<Leaf> = absence_proof
            .get_namespace_leaves()
            .into_iter()
            .cloned()
            .collect();
        assert!(tree
            .verify_namespace_proof(&absence_proof, last_ns + 1)
            .unwrap()
            .is_ok());
        assert_eq!(leaves, []);
    }
}
