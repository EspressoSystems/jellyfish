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
use typenum::Unsigned;

use crate::errors::{PrimitivesError, VerificationResult};

use super::{
    append_only::MerkleTree, AppendableMerkleTreeScheme, DigestAlgorithm, Element, Index,
    LookupResult, MerkleCommitment, MerkleTreeScheme, NodeValue,
};

/// Namespaced Merkle Tree where leaves are sorted by a namespace identifier.
/// The data structure supports namespace inclusion proofs.
pub trait NamespacedMerkleTreeScheme: AppendableMerkleTreeScheme
where
    Self::Element: Namespaced,
{
    /// Namespace proof type
    type NamespaceProof: Clone;
    /// Namespace type
    type NamespaceId: Namespace;

    /// Returns the entire set of leaves corresponding to a given namespace and
    /// a completeness proof.
    fn get_namespace_proof(&self, namespace: Self::NamespaceId) -> Self::NamespaceProof;

    /// Verifies the completeness proof for a given set of leaves and a
    /// namespace.
    fn verify_namespace_proof(
        &self,
        proof: Self::NamespaceProof,
        namespace: Self::NamespaceId,
    ) -> Result<(), PrimitivesError>;
}

/// NamespacedHasher wraps a standard hash function (implementer of
/// DigestAlgorithm), turning it into a hash function that tags internal nodes
/// with namespace ranges.
#[derive(Debug)]
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

#[derive(Debug)]
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
        // TODO: update namespace metadata
        self.inner.extend(elems)
    }

    fn push(
        &mut self,
        elem: impl core::borrow::Borrow<Self::Element>,
    ) -> Result<(), PrimitivesError> {
        // TODO: update namespace metadata
        self.inner.push(elem)
    }
}

impl<E, H, Arity, N, T> NamespacedMerkleTreeScheme for NMT<E, H, Arity, N, T>
where
    H: DigestAlgorithm<E, u64, T> + BindNamespace<E, u64, T, N>,
    E: Element + Namespaced<Namespace = N>,
    T: NodeValue,
    N: Namespace,
    Arity: Unsigned,
{
    type NamespaceId = N;
    type NamespaceProof = Vec<(E, <Self as MerkleTreeScheme>::MembershipProof, u64)>;

    fn get_namespace_proof(&self, namespace: Self::NamespaceId) -> Self::NamespaceProof {
        let ns_range = self.namespace_ranges.get(&namespace);
        let mut ns_proof = Vec::new();
        if let Some(ns_range) = ns_range {
            for i in ns_range.clone() {
                if let LookupResult::Ok(elem, proof) = self.inner.lookup(i) {
                    ns_proof.push((elem, proof, i));
                }
            }
        }
        ns_proof
    }

    fn verify_namespace_proof(
        &self,
        proof: Self::NamespaceProof,
        namespace: Self::NamespaceId,
    ) -> Result<(), PrimitivesError> {
        for (elem, elem_proof, i) in proof {
            // This just verifies each merkle leaf, placeholder until completeness is
            // actually checked
            if Self::verify(self.commitment().digest(), i, elem_proof.clone())?.is_err() {
                return Err(PrimitivesError::VerificationError(
                    "Leaf verification error".into(),
                ));
            }
            if &elem != elem_proof.elem().unwrap() {
                return Err(PrimitivesError::VerificationError(
                    "Element does not match the proven value".into(),
                ));
            }
            if elem.get_namespace() != namespace {
                return Err(PrimitivesError::VerificationError(
                    "Namespace invalid".into(),
                ));
            }
        }
        Ok(())
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
        let num_leaves = 5;
        let leaves: Vec<Leaf> = (0..num_leaves).map(|i| Leaf::new(i)).collect();
        let tree = TestNMT::from_elems(3, leaves).unwrap();
        let proof = tree.get_namespace_proof(0);
        assert!(tree.verify_namespace_proof(proof.clone(), 0).is_ok());
        assert!(tree.verify_namespace_proof(proof, 1).is_err());
    }
}
