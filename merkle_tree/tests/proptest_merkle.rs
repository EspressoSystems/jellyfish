use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use ark_std::{
    rand::{rngs::StdRng, seq::SliceRandom, SeedableRng},
    Zero,
};
use jf_merkle_tree::{
    prelude::*, universal_merkle_tree::UniversalMerkleTree, ForgetableUniversalMerkleTreeScheme,
    LookupResult, MerkleTreeScheme, UniversalMerkleTreeScheme,
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use proptest::prelude::*;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
enum CorruptionType {
    PositionIncrement,
    ValueCorruption,
    LengthReduction,
    NodeSwap,
    NodeInjection,
    EmptyProof,
    PositionOverflow,
    ZeroFields,
    MaxFields,
    BranchWithChildren,
    InconsistentLeaf,
    LeafPositionMismatch,
    DuplicateNodes,
    ReverseOrder,
    ReplaceWithEmpty,
    ReplaceWithLeaves,
    MixNodeTypes,
    PrependForgotten,
    InterleaveEmpty,
    BranchOnlyProof,
    ShuffleNodes { seed: u64 },
    ForgottenOnly,
    PositionWrappedAround,
    UnbalancedStructure,
}

impl Arbitrary for CorruptionType {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(CorruptionType::PositionIncrement),
            Just(CorruptionType::ValueCorruption),
            Just(CorruptionType::LengthReduction),
            Just(CorruptionType::NodeSwap),
            Just(CorruptionType::NodeInjection),
            Just(CorruptionType::EmptyProof),
            Just(CorruptionType::PositionOverflow),
            Just(CorruptionType::ZeroFields),
            Just(CorruptionType::MaxFields),
            Just(CorruptionType::BranchWithChildren),
            Just(CorruptionType::InconsistentLeaf),
            Just(CorruptionType::LeafPositionMismatch),
            Just(CorruptionType::DuplicateNodes),
            Just(CorruptionType::ReverseOrder),
            Just(CorruptionType::ReplaceWithEmpty),
            Just(CorruptionType::ReplaceWithLeaves),
            Just(CorruptionType::MixNodeTypes),
            Just(CorruptionType::PrependForgotten),
            Just(CorruptionType::InterleaveEmpty),
            Just(CorruptionType::BranchOnlyProof),
            any::<u64>().prop_map(|seed| CorruptionType::ShuffleNodes { seed }),
            Just(CorruptionType::ForgottenOnly),
            Just(CorruptionType::PositionWrappedAround),
            Just(CorruptionType::UnbalancedStructure),
        ]
        .boxed()
    }
}

// Generic type alias for any arity
type TestUniversalMerkleTree<const ARITY: usize> =
    UniversalMerkleTree<BigUint, Sha3Digest, u64, ARITY, Sha3Node>;

// Wrapper for ergonomic Sha3Node creation in tests
struct Node;

impl Node {
    fn from(bytes: [u8; 32]) -> Sha3Node {
        Sha3Node::deserialize_with_mode(&bytes[..], Compress::No, Validate::No).unwrap()
    }

    fn zero() -> Sha3Node {
        Self::from([0u8; 32])
    }
}

fn arbitrary_element() -> impl Strategy<Value = BigUint> {
    prop_oneof![
        1 => Just(BigUint::zero()),
        1 => Just(BigUint::from(1u64)),
        10 => (0u64..1000).prop_map(BigUint::from),
        5 => (0u64..100000).prop_map(BigUint::from),
    ]
}

fn arbitrary_kv_pairs_u64(max_size: usize) -> impl Strategy<Value = Vec<(u64, BigUint)>> {
    prop::collection::vec((0u64..1000, arbitrary_element()), 0..=max_size)
}

fn arbitrary_tree_height() -> impl Strategy<Value = usize> {
    prop_oneof![
        1 => Just(1),
        1 => Just(2),
        5 => 3usize..10,
        1 => Just(32),
    ]
}

fn arbitrary_sparse_tree<const ARITY: usize>(
) -> impl Strategy<Value = (TestUniversalMerkleTree<ARITY>, Vec<(u64, BigUint)>)> {
    (arbitrary_tree_height(), arbitrary_kv_pairs_u64(10)).prop_map(|(height, kvs)| {
        let tree = TestUniversalMerkleTree::<ARITY>::from_kv_set(height, &kvs).unwrap();
        (tree, kvs)
    })
}

fn corrupt_proof<const ARITY: usize>(
    mut proof: <TestUniversalMerkleTree<ARITY> as MerkleTreeScheme>::MembershipProof,
    corruption_type: CorruptionType,
) -> <TestUniversalMerkleTree<ARITY> as MerkleTreeScheme>::MembershipProof {
    match corruption_type {
        CorruptionType::PositionIncrement => {
            proof.pos = proof.pos.wrapping_add(1);
            proof
        },
        CorruptionType::ValueCorruption => {
            if !proof.proof.is_empty() {
                let idx = 0; // Just corrupt first element for simplicity
                if let MerkleNode::Leaf { value, elem, .. } = &proof.proof[idx] {
                    let mut corrupted_bytes = [0u8; 32];
                    corrupted_bytes.copy_from_slice(value.as_ref());
                    corrupted_bytes[0] = corrupted_bytes[0].wrapping_add(1);
                    let corrupted_value = Node::from(corrupted_bytes);
                    let corrupted_elem = elem.clone() + BigUint::from(1u64);
                    proof.proof[idx] = MerkleNode::Leaf {
                        value: corrupted_value,
                        pos: 0u64,
                        elem: corrupted_elem,
                    };
                }
            }
            proof
        },
        CorruptionType::LengthReduction => {
            if proof.proof.len() > 1 {
                proof.proof.pop();
            }
            proof
        },
        CorruptionType::NodeSwap => {
            if proof.proof.len() > 2 {
                proof.proof.swap(0, 1);
            }
            proof
        },
        CorruptionType::NodeInjection => {
            proof.proof.push(MerkleNode::Empty);
            proof
        },
        CorruptionType::EmptyProof => {
            proof.proof = vec![];
            proof
        },
        CorruptionType::PositionOverflow => {
            proof.pos = u64::MAX;
            proof
        },
        CorruptionType::ZeroFields => {
            for node in &mut proof.proof {
                match node {
                    MerkleNode::Leaf { value, elem, .. } => {
                        *value = Node::zero();
                        *elem = BigUint::zero();
                    },
                    MerkleNode::Branch { value, .. } => {
                        *value = Node::zero();
                    },
                    MerkleNode::ForgettenSubtree { value } => {
                        *value = Node::zero();
                    },
                    _ => {},
                }
            }
            proof
        },
        CorruptionType::MaxFields => {
            let max_val = Node::from([0xFFu8; 32]);
            let max_elem = BigUint::from(u64::MAX);
            for node in &mut proof.proof {
                match node {
                    MerkleNode::Leaf { value, elem, .. } => {
                        *value = max_val;
                        *elem = max_elem.clone();
                    },
                    MerkleNode::Branch { value, .. } => {
                        *value = max_val;
                    },
                    MerkleNode::ForgettenSubtree { value } => {
                        *value = max_val;
                    },
                    _ => {},
                }
            }
            proof
        },
        CorruptionType::BranchWithChildren => {
            for node in &mut proof.proof {
                if let MerkleNode::Branch { children, value } = node {
                    if children.is_empty() {
                        children.extend(vec![
                            Arc::new(MerkleNode::Empty),
                            Arc::new(MerkleNode::ForgettenSubtree { value: *value }),
                            Arc::new(MerkleNode::Branch {
                                value: Node::zero(),
                                children: vec![],
                            }),
                        ]);
                    } else {
                        children.clear();
                    }
                }
            }
            proof
        },
        CorruptionType::InconsistentLeaf => {
            for node in &mut proof.proof {
                if let MerkleNode::Leaf {
                    value,
                    elem: _,
                    pos,
                } = node
                {
                    let mut corrupted_bytes = [0u8; 32];
                    corrupted_bytes.copy_from_slice(value.as_ref());
                    corrupted_bytes[31] = corrupted_bytes[31].wrapping_add(1);
                    *value = Node::from(corrupted_bytes);
                    *pos = *pos ^ 0xFFu64;
                }
            }
            proof
        },
        CorruptionType::LeafPositionMismatch => {
            for (i, node) in proof.proof.iter_mut().enumerate() {
                if let MerkleNode::Leaf { pos, .. } = node {
                    *pos = (i as u64).wrapping_mul(12345).wrapping_add(999);
                }
            }
            proof
        },
        CorruptionType::DuplicateNodes => {
            let original = proof.proof.clone();
            proof.proof.extend(original);
            proof
        },
        CorruptionType::ReverseOrder => {
            proof.proof.reverse();
            proof
        },
        CorruptionType::ReplaceWithEmpty => {
            let len = proof.proof.len();
            proof.proof = vec![MerkleNode::Empty; len];
            proof
        },
        CorruptionType::ReplaceWithLeaves => {
            let len = proof.proof.len();
            proof.proof = (0..len)
                .map(|i| MerkleNode::Leaf {
                    value: Node::from([(i * 7) as u8; 32]),
                    pos: (i * 13) as u64,
                    elem: BigUint::from((i * 17) as u64),
                })
                .collect();
            proof
        },
        CorruptionType::MixNodeTypes => {
            for (i, node) in proof.proof.iter_mut().enumerate() {
                *node = match i % 3 {
                    0 => MerkleNode::Empty,
                    1 => MerkleNode::Branch {
                        value: Node::from([i as u8; 32]),
                        children: vec![],
                    },
                    _ => MerkleNode::ForgettenSubtree {
                        value: Node::from([i as u8; 32]),
                    },
                };
            }
            proof
        },
        CorruptionType::PrependForgotten => {
            let mut new_proof = vec![
                MerkleNode::ForgettenSubtree {
                    value: Node::from([1u8; 32]),
                },
                MerkleNode::ForgettenSubtree {
                    value: Node::zero(),
                },
            ];
            new_proof.extend(proof.proof);
            proof.proof = new_proof;
            proof
        },
        CorruptionType::InterleaveEmpty => {
            let original = proof.proof.clone();
            proof.proof.clear();
            for node in original {
                proof.proof.push(MerkleNode::Empty);
                proof.proof.push(node);
            }
            proof
        },
        CorruptionType::BranchOnlyProof => {
            let len = proof.proof.len();
            proof.proof = (0..len)
                .map(|i| MerkleNode::Branch {
                    value: Node::from([(i + 1) as u8; 32]),
                    children: vec![],
                })
                .collect();
            proof
        },
        CorruptionType::ShuffleNodes { seed } => {
            let mut rng = StdRng::seed_from_u64(seed);
            proof.proof.shuffle(&mut rng);
            proof
        },
        CorruptionType::ForgottenOnly => {
            if proof.proof.is_empty() {
                proof.proof = vec![MerkleNode::ForgettenSubtree {
                    value: Node::zero(),
                }];
            } else {
                let len = proof.proof.len();
                proof.proof = (0..len)
                    .map(|i| MerkleNode::ForgettenSubtree {
                        value: Node::from([i as u8; 32]),
                    })
                    .collect();
            }
            proof
        },
        CorruptionType::PositionWrappedAround => {
            proof.pos = u64::MAX;
            proof
        },
        CorruptionType::UnbalancedStructure => {
            let base_size = proof.proof.len().max(2);
            let mut new_proof = Vec::with_capacity(base_size * 2);

            for i in 0..base_size {
                match i % 4 {
                    0 => new_proof.push(MerkleNode::Leaf {
                        value: Node::from([(i * 3) as u8; 32]),
                        pos: (i * 1000) as u64,
                        elem: BigUint::from((i * 7) as u64),
                    }),
                    1 => new_proof.push(MerkleNode::Branch {
                        value: Node::from([i as u8; 32]),
                        children: if i % 2 == 0 {
                            vec![]
                        } else {
                            vec![Arc::new(MerkleNode::Empty)]
                        },
                    }),
                    2 => new_proof.push(MerkleNode::Empty),
                    _ => new_proof.push(MerkleNode::ForgettenSubtree {
                        value: Node::from([(i * 42) as u8; 32]),
                    }),
                }
            }

            proof.proof = new_proof;
            proof
        },
    }
}

fn arbitrary_proof<const ARITY: usize>(
) -> impl Strategy<Value = <TestUniversalMerkleTree<ARITY> as MerkleTreeScheme>::MembershipProof> {
    (
        0u64..1000,
        prop::collection::vec(
            prop_oneof![
                1 => Just(MerkleNode::Empty),
                1 => (any::<[u8; 32]>(), arbitrary_element()).prop_map(|(bytes, elem)| MerkleNode::Leaf {
                    value: Node::from(bytes),
                    pos: 0u64,
                    elem,
                }),
                1 => any::<[u8; 32]>().prop_map(|bytes| MerkleNode::Branch {
                    value: Node::from(bytes),
                    children: vec![],
                }),
                1 => any::<[u8; 32]>().prop_map(|bytes| MerkleNode::ForgettenSubtree {
                    value: Node::from(bytes),
                }),
            ],
            0..10,
        ),
    )
        .prop_map(|(pos, proof)| MerkleProof { pos, proof })
}

fn test_verify_never_panics<const ARITY: usize>() {
    proptest!(|(
        (tree, _kvs) in arbitrary_sparse_tree::<ARITY>(),
        pos in 0u64..1000,
        proof in arbitrary_proof::<ARITY>(),
    )| {
        let _ = TestUniversalMerkleTree::<ARITY>::verify(tree.commitment(), &pos, &proof);
    });
}

fn test_non_membership_verify_never_panics<const ARITY: usize>() {
    proptest!(|(
        (tree, _) in arbitrary_sparse_tree::<ARITY>(),
        pos in 0u64..1000,
        proof in arbitrary_proof::<ARITY>(),
    )| {
        let _ = TestUniversalMerkleTree::<ARITY>::non_membership_verify(tree.commitment(), &pos, &proof);
    });
}

fn test_remember_never_panics<const ARITY: usize>() {
    proptest!(|(
        (mut tree, _kvs) in arbitrary_sparse_tree::<ARITY>(),
        pos in 0u64..1000,
        elem in arbitrary_element(),
        proof in arbitrary_proof::<ARITY>(),
    )| {
        let _ = tree.remember(&pos, &elem, &proof);
    });
}

fn test_non_membership_remember_never_panics<const ARITY: usize>() {
    proptest!(|(
        (mut tree, _) in arbitrary_sparse_tree::<ARITY>(),
        pos in 0u64..1000,
        proof in arbitrary_proof::<ARITY>(),
    )| {
        let _ = tree.non_membership_remember(pos, &proof);
    });
}

fn test_corrupted_membership_proofs_handled_safely<const ARITY: usize>() {
    proptest!(|(
        (tree, kvs) in arbitrary_sparse_tree::<ARITY>(),
        corruption_type in any::<CorruptionType>(),
    )| {
        // Skip test if tree is empty
        prop_assume!(!kvs.is_empty());

        let commitment = tree.commitment();

        let (key, _) = &kvs[0];
        match tree.universal_lookup(key) {
            LookupResult::Ok(_, proof) => {
                let corrupted_proof = corrupt_proof::<ARITY>(proof, corruption_type);
                let _ = TestUniversalMerkleTree::<ARITY>::verify(commitment, key, &corrupted_proof);
            }
            _ => unreachable!()
        }
    });
}

fn test_corrupted_non_membership_proofs_handled_safely<const ARITY: usize>() {
    proptest!(|(
        (tree, _kvs) in arbitrary_sparse_tree::<ARITY>(),
        corruption_type in any::<CorruptionType>(),
    )| {
        let search_limit = tree.capacity().min(1000u64.into()).to_u64().unwrap();

        let mut found_non_member = false;
        for i in 0..search_limit {
            let candidate = i;
            match tree.universal_lookup(&candidate) {
                LookupResult::NotFound(proof) => {
                    let corrupted_proof = corrupt_proof::<ARITY>(proof, corruption_type);
                    let _ = TestUniversalMerkleTree::<ARITY>::non_membership_verify(tree.commitment(), &candidate, &corrupted_proof);
                    found_non_member = true;
                    break;
                }
                _ => continue,
            }
        }

        // Skip test if we couldn't find any non-member
        prop_assume!(found_non_member);
    });
}

macro_rules! generate_arity_tests {
    ($arity:literal) => {
        paste::paste! {
            #[test]
            fn [<universal_verify_never_panics_arity_ $arity>]() {
                test_verify_never_panics::<$arity>();
            }

            #[test]
            fn [<universal_non_membership_verify_never_panics_arity_ $arity>]() {
                test_non_membership_verify_never_panics::<$arity>();
            }

            #[test]
            fn [<universal_remember_never_panics_arity_ $arity>]() {
                test_remember_never_panics::<$arity>();
            }

            #[test]
            fn [<universal_non_membership_remember_never_panics_arity_ $arity>]() {
                test_non_membership_remember_never_panics::<$arity>();
            }

            #[test]
            fn [<universal_corrupted_membership_proofs_handled_safely_arity_ $arity>]() {
                test_corrupted_membership_proofs_handled_safely::<$arity>();
            }

            #[test]
            fn [<universal_corrupted_non_membership_proofs_handled_safely_arity_ $arity>]() {
                test_corrupted_non_membership_proofs_handled_safely::<$arity>();
            }
        }
    };
}

generate_arity_tests!(2);
generate_arity_tests!(3);
generate_arity_tests!(256);
