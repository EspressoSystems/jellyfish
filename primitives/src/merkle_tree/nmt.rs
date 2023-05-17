use core::{
    cmp::{max, min},
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

use super::{
    examples::{Sha3Digest, Sha3Node},
    DigestAlgorithm, Element, Index, NodeValue,
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
}

impl<T> Namespace for T where
    T: Debug + Clone + CanonicalDeserialize + CanonicalSerialize + Default + Copy + Hash + Ord
{
}

#[derive(
    CanonicalSerialize,
    Default,
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
struct NamespacedHash<T, N>
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
        // TODO generalize to N internal nodes?
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
        let inner_hash = H::digest(&[left_hash, right_hash]);

        NamespacedHash::new(min_ns, max_ns, inner_hash)
    }

    fn digest_leaf(pos: &I, elem: &E) -> NamespacedHash<T, N> {
        let namespace = elem.get_namespace();
        let hash = H::digest_leaf(pos, elem);
        NamespacedHash::new(namespace, namespace, hash)
    }
}

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
    namespace: u64,
}

impl Namespaced<u64> for Leaf {
    fn get_namespace(&self) -> u64 {
        self.namespace
    }
}

#[allow(dead_code)]
pub type NamespacedSha3Hasher = NamespacedHasher<Sha3Digest, Leaf, u64, Sha3Node, u64>;

#[cfg(test)]
mod tests {
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
}
