// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of a Namespaced Merkle Tree.
use alloc::vec;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

use crate::errors::PrimitivesError;

use super::{AppendableMerkleTreeScheme, DigestAlgorithm, Element, Index, NodeValue};

/// Namespaced Merkle Tree where leaves are sorted by a namespace identifier.
pub trait NamespacedMerkleTreeScheme: AppendableMerkleTreeScheme
where
    Self::Element: Namespaced<Self::NamespaceId>,
{
    /// Namespace proof type
    type NamespaceProof: Clone;
    /// Namespace type
    type NamespaceId: Namespace;

    /// Returns the entire set of leaves corresponding to a given namespace and
    /// a completeness proof
    fn get_namespace_leaves_and_proof(
        &self,
        namespace: Self::NamespaceId,
    ) -> (Vec<Self::Element>, Self::NamespaceProof);

    /// Verifies the completeness proof for a given set of leaves and a
    /// namespace
    fn verify_namespace_proof(
        leaves: &[Self::Element],
        proof: Self::NamespaceProof,
        namespace: Self::NamespaceId,
    ) -> Result<(), PrimitivesError>;
}

/// NamespacedHasher wraps a standard hash function (implementer of
/// DigestAlgorithm), turning it into a hash function that tags internal nodes
/// with namespace ranges
pub struct NamespacedHasher<H, E, I, T, N>
where
    H: DigestAlgorithm<E, I, T>,
    E: Element + Namespaced<N>,
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

/// Trait indicating that a leaf has a namespace
pub trait Namespaced<N: Namespace> {
    /// Returns the namespace of the leaf
    fn get_namespace(&self) -> N;
}

/// Trait indicating that a digest algorithm can bind namespaces
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

impl<T, N> Default for NamespacedHash<T, N>
where
    N: Namespace,
    T: NodeValue,
{
    fn default() -> Self {
        Self {
            hash: T::default(),
            max_namespace: <N as Namespace>::min(),
            min_namespace: <N as Namespace>::max(),
        }
    }
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
    E: Element + Namespaced<N>,
    I: Index,
    N: Namespace,
    T: NodeValue,
    H: DigestAlgorithm<E, I, T> + BindNamespace<E, I, T, N>,
{
    fn digest(data: &[NamespacedHash<T, N>]) -> NamespacedHash<T, N> {
        if data.is_empty() {
            return NamespacedHash::default();
        }
        let first_node = data[0];
        let min_namespace = first_node.min_namespace;
        let mut max_namespace = first_node.max_namespace;
        let mut nodes = vec![H::generate_namespaced_commitment(first_node)];
        for node in data {
            // Ensure that namespaced nodes are sorted
            if node.min_namespace < max_namespace {
                panic!("leaves are out of order")
            }
            max_namespace = node.max_namespace;
            nodes.push(H::generate_namespaced_commitment(*node));
        }

        let inner_hash = H::digest(&nodes);

        NamespacedHash::new(min_namespace, max_namespace, inner_hash)
    }

    fn digest_leaf(pos: &I, elem: &E) -> NamespacedHash<T, N> {
        let namespace = elem.get_namespace();
        let hash = H::digest_leaf(pos, elem);
        NamespacedHash::new(namespace, namespace, hash)
    }
}

#[cfg(test)]
mod nmt_tests {
    use digest::Digest;
    use sha3::Sha3_256;

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

    impl Namespaced<NamespaceId> for Leaf {
        fn get_namespace(&self) -> NamespaceId {
            self.namespace
        }
    }

    impl<E, I, N> BindNamespace<E, I, Sha3Node, N> for Sha3Digest
    where
        E: Element + CanonicalSerialize,
        I: Index,
        N: Namespace,
    {
        fn generate_namespaced_commitment(
            namespaced_hash: NamespacedHash<Sha3Node, N>,
        ) -> Sha3Node {
            let hasher = Sha3_256::new();
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
            Sha3Node(hasher.finalize().into())
        }
    }

    #[test]
    fn test_namespaced_hash() {
        // Ensure that hashing with a default namespaced hash does not affect the
        // namespace range Ensure that leaves are digested correctly
        // Ensure that sorted internal nodes are digested correctly
        // Ensure that unsorted internal nodes error when digested
        let leaf1 = Leaf { namespace: 0 };
        let leaf2 = Leaf { namespace: 52 };
        let h1 = Hasher::digest_leaf(&1, &leaf1);
        let h2 = Hasher::digest_leaf(&1, &leaf2);
        let node = Hasher::digest(&[h1, h2]);
        assert_eq!(node.min_namespace, 0);
        assert_eq!(node.max_namespace, 52);
    }
}
