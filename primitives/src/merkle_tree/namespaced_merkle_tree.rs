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
    fn get_namespace_leaves_and_proof(
        &self,
        namespace: Self::NamespaceId,
    ) -> (Vec<Self::Element>, Self::NamespaceProof);

    /// Verifies the completeness proof for a given set of leaves and a
    /// namespace.
    fn verify_namespace_proof(
        leaves: &[Self::Element],
        proof: Self::NamespaceProof,
        namespace: Self::NamespaceId,
    ) -> Result<(), PrimitivesError>;
}

/// NamespacedHasher wraps a standard hash function (implementer of
/// DigestAlgorithm), turning it into a hash function that tags internal nodes
/// with namespace ranges.
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
    fn digest(data: &[NamespacedHash<T, N>]) -> NamespacedHash<T, N> {
        if data.is_empty() {
            return NamespacedHash::default();
        }
        let first_node = data[0];
        let min_namespace = first_node.min_namespace;
        let mut max_namespace = first_node.max_namespace;
        let mut nodes = vec![H::generate_namespaced_commitment(first_node)];
        for node in &data[1..] {
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
    use std::panic::catch_unwind;

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
        let leaves: Vec<Leaf> = (0..num_leaves).map(|i| Leaf::new(i)).collect();

        // Ensure that leaves are digested correctly
        let mut hashes: Vec<NamespacedHash<Sha3Node, u64>> = leaves
            .iter()
            .enumerate()
            .map(|(idx, leaf)| Hasher::digest_leaf(&(idx as u64), leaf))
            .collect();
        assert_eq!((hashes[0].min_namespace, hashes[0].max_namespace), (0, 0));

        // Ensure that sorted internal nodes are digested correctly
        let hash = Hasher::digest(&hashes);
        assert_eq!(
            (hash.min_namespace, hash.max_namespace),
            (0, num_leaves - 1)
        );

        // Ensure that digest errors when internal nodes are not sorted by namespace
        // digest will turn a result when https://github.com/EspressoSystems/jellyfish/issues/275 is addressed
        hashes[0] = hashes[hashes.len() - 1];
        let res = catch_unwind(|| Hasher::digest(&hashes));
        assert!(res.is_err());
    }
}
