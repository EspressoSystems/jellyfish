// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a Namespaced Merkle Tree.
use alloc::collections::{btree_map::Entry, BTreeMap};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use core::{borrow::Borrow, fmt::Debug, hash::Hash, marker::PhantomData, ops::Range};
use typenum::Unsigned;

use crate::errors::{PrimitivesError, VerificationResult};

use self::{
    hash::{NamespacedHash, NamespacedHasher},
    proof::{NaiveNamespaceProof, NamespaceProofType},
};

use super::{
    append_only::MerkleTree, internal::MerkleProof, AppendableMerkleTreeScheme, DigestAlgorithm,
    Element, Index, LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue,
};

mod hash;
mod proof;

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
    namespace_ranges: BTreeMap<N, Range<u64>>,
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
        elems: impl IntoIterator<Item = impl Borrow<Self::Element>>,
    ) -> Result<Self, PrimitivesError> {
        let mut namespace_ranges: BTreeMap<N, Range<u64>> = BTreeMap::new();
        let mut max_namespace = <N as Namespace>::min();
        let mut leaves = Vec::new();
        for (idx, elem) in elems.into_iter().enumerate() {
            let ns = elem.borrow().get_namespace();
            let idx = idx as u64;
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

impl<E, H, Arity, N, T> NMT<E, H, Arity, N, T>
where
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N> + Clone,
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    N: Namespace,
    Arity: Unsigned,
{
    // Helper function to lookup a proof that should be in the tree because of NMT
    // invariants
    fn lookup_proof(&self, idx: u64) -> MerkleProof<E, u64, NamespacedHash<T, N>, Arity> {
        if let LookupResult::Ok(_, proof) = self.inner.lookup(idx) {
            proof
        } else {
            // The NMT is malformed, we cannot recover
            panic!()
        }
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
                proofs.push(self.lookup_proof(i));
            }
            let left_index = first_index.unwrap_or(0);
            let right_index = left_index + proofs.len() as u64;
            if left_index > 0 {
                left_boundary_proof = Some(self.lookup_proof(left_index - 1));
            }
            if right_index < self.num_leaves() - 1 {
                right_boundary_proof = Some(self.lookup_proof(right_index + 1));
            }
        } else {
            proof_type = NamespaceProofType::Absence;
            // If there is a namespace in the tree greater than our target
            // namespace at some index i, prove that the
            // target namespace is empty by providing proofs of leaves at index i and
            // i - 1
            if let Some((_, range)) = self.namespace_ranges.range(namespace..).next() {
                let i = range.start;
                // If i == 0, the target namespace is less than the tree's minimum namespace
                if i > 0 {
                    left_boundary_proof = Some(self.lookup_proof(i - 1));
                    right_boundary_proof = Some(self.lookup_proof(i));
                }
            }
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
        let namespaces = [1, 2, 2, 2, 4, 4, 4, 5];
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
        // tree range (namespace > root.max_namespace)
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

        // Check the simple absence proof case when the namespace falls outside of the
        // tree range (namespace < root.min_namespace)
        let absence_proof = tree.get_namespace_proof(first_ns - 1);
        let leaves: Vec<Leaf> = absence_proof
            .get_namespace_leaves()
            .into_iter()
            .cloned()
            .collect();
        assert!(tree
            .verify_namespace_proof(&absence_proof, first_ns - 1)
            .unwrap()
            .is_ok());
        assert_eq!(leaves, []);

        // Check absence proof case when the namespace falls inside of the tree range
        let absence_proof = tree.get_namespace_proof(3);
        let leaves: Vec<Leaf> = absence_proof
            .get_namespace_leaves()
            .into_iter()
            .cloned()
            .collect();
        assert!(tree
            .verify_namespace_proof(&absence_proof, 3)
            .unwrap()
            .is_ok());
        assert_eq!(leaves, []);

        // Ensure that the absence proof fails when the boundaries are not provided
        let mut malformed_proof = absence_proof.clone();
        malformed_proof.left_boundary_proof = None;
        assert!(tree.verify_namespace_proof(&malformed_proof, 3).is_err());
        let mut malformed_proof = absence_proof.clone();
        malformed_proof.right_boundary_proof = None;
        assert!(tree.verify_namespace_proof(&malformed_proof, 3).is_err());

        // Ensure that the absence proof returns a verification error when one of the
        // boundary proofs is incorrect
        let mut malicious_proof = absence_proof.clone();
        malicious_proof.right_boundary_proof = malicious_proof.left_boundary_proof.clone();
        assert!(tree
            .verify_namespace_proof(&malicious_proof, 3)
            .unwrap()
            .is_err());
    }
}
