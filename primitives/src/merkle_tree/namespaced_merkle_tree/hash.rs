use alloc::vec;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{string::ToString, vec::Vec};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};

use crate::errors::PrimitivesError;

use super::{BindNamespace, DigestAlgorithm, Element, Index, Namespace, Namespaced, NodeValue};

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
    pub(crate) min_namespace: N,
    pub(crate) max_namespace: N,
    pub(crate) hash: T,
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
