use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use core::{
    cmp::{max, min},
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
};

use super::{
    examples::{Sha3Digest, Sha3Node},
    AppendableMerkleTreeScheme, DigestAlgorithm, Element, Index, NodeValue,
};

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

pub trait Namespaced<N: Namespace> {
    fn get_namespace(&self) -> N;
}

pub trait Namespace:
    Debug + Clone + CanonicalDeserialize + CanonicalSerialize + Default + Copy + Hash + Ord
{
    fn min() -> Self;
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
    H: DigestAlgorithm<E, I, T>,
{
    fn digest(data: &[NamespacedHash<T, N>]) -> NamespacedHash<T, N> {
        // generalize to N internal nodes?
        let (left_node, right_node) = (data[0], data[1]);

        let NamespacedHash {
            min_namespace: left_min_ns,
            max_namespace: left_max_ns,
            hash: left_hash,
        } = left_node;

        let NamespacedHash {
            min_namespace: right_min_ns,
            max_namespace: right_max_ns,
            hash: right_hash,
        } = right_node;

        if left_max_ns > right_min_ns {
            panic!("leaves are out of order")
        }

        let min_ns = min(right_min_ns, left_min_ns);
        let max_ns = max(right_max_ns, left_max_ns);
        // Hash the entire node
        let inner_hash = H::digest(&[left_hash, right_hash]);

        NamespacedHash::new(min_ns, max_ns, inner_hash)
    }

    fn digest_leaf(pos: &I, elem: &E) -> NamespacedHash<T, N> {
        let namespace = elem.get_namespace();
        let hash = H::digest_leaf(pos, elem);
        NamespacedHash::new(namespace, namespace, hash)
    }
}

type NamespaceId = u64;

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
pub struct Leaf {
    namespace: NamespaceId,
}

impl Namespaced<NamespaceId> for Leaf {
    fn get_namespace(&self) -> NamespaceId {
        self.namespace
    }
}

#[allow(dead_code)]
pub type NamespacedSha3Hasher = NamespacedHasher<Sha3Digest, Leaf, NamespaceId, Sha3Node, u64>;

/// Namespaced Merkle Tree where leaves are sorted by a namespace identifier.
/// The tree supports batch namespace inclusion and abscence proofs.
pub trait NamespacedMerkleTreeScheme: AppendableMerkleTreeScheme
where
    Self::Element: Namespaced<Self::NamespaceId>,
{
    type NamespaceProof: Clone;
    type NamespaceId: Namespace;

    fn get_namespace_leaves_and_proof(
        &self,
        namespace: NamespaceId,
    ) -> (Vec<Self::Element>, Self::NamespaceProof);

    fn verify_namespace_proof(
        leaves: &[Self::Element],
        proof: Self::NamespaceProof,
        namespace: NamespaceId,
    ) -> Result<(), ()>;
}
// pub type Tree =
//     MerkleTree<Leaf, NamespacedSha3Hasher, u64, U2, NamespacedHash<Sha3Node,
// NamespaceId>>;

// pub struct NMT {
//     inner: Tree,
//     namespace_ranges: HashMap<NamespaceId, Range<usize>>,
//     max_namespace: NamespaceId,
// }

// impl NamespacedMerkleTreeScheme for NMT {
//     type NamespaceId = NamespaceId;
//     type NamespaceProof = ();
//     fn get_namespace_leaves_and_proof(
//         &self,
//         namespace: NamespaceId,
//     ) -> (Vec<Self::Element>, Self::NamespaceProof) {
//         // For exclusion proof: one subpath, if leaves are siblings, check
// the neighbor, else check         // the uncle
//         // inclusion proof: check boundary of the start and end leaves in the
// merkle proof         unimplemented!()
//     }
// –
//     fn verify_namespace_proof(
//         leaves: &[Self::Element],
//         proof: Self::NamespaceProof,
//         namespace: NamespaceId,
//     ) -> Result<(), ()> {
//         unimplemented!()
//     }
// }

#[cfg(test)]
mod tests {

    use crate::merkle_tree::{append_only::MerkleTree, MerkleCommitment, MerkleTreeScheme};

    use super::*;
    #[test]
    fn test_namespaced_hash() {
        type Hasher = NamespacedSha3Hasher;
        let leaf1 = Leaf { namespace: 0 };
        let leaf2 = Leaf { namespace: 52 };
        let h1 = Hasher::digest_leaf(&1, &leaf1);
        let h2 = Hasher::digest_leaf(&1, &leaf2);
        let node = Hasher::digest(&[h1, h2]);
        assert_eq!(node.min_namespace, 0);
        assert_eq!(node.max_namespace, 52);
    }

    #[test]
    fn test_merkle_tree() {
        let leaf1 = Leaf { namespace: 1 };
        let leaf2 = Leaf { namespace: 54 };
        let leaf4 = Leaf { namespace: 112 };
        let elems = &[leaf1, leaf2, leaf4];
        let tree = Tree::from_elems(2, elems).unwrap();
        let root = tree.commitment().digest();
        let (leaves, proof) = tree.get_namespace_leaves_and_proof(1);
        assert_eq!(root.min_namespace, 1);
        assert_eq!(root.max_namespace, 112);
    }
}
