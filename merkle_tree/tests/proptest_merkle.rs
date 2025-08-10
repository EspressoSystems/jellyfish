use ark_bn254::Fr as Fr254;
use ark_ff::PrimeField;
use ark_std::rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use jf_merkle_tree::{
    prelude::*, ForgetableUniversalMerkleTreeScheme, LookupResult, MerkleTreeScheme,
    UniversalMerkleTreeScheme,
};
use jf_rescue::RescueParameter;
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

type TestUniversalMerkleTree<F> = RescueSparseMerkleTree<BigUint, F>;

fn arbitrary_field_element<F: PrimeField>() -> impl Strategy<Value = F> {
    any::<[u8; 32]>().prop_map(|bytes| F::from_random_bytes(&bytes).unwrap_or(F::zero()))
}

fn arbitrary_index() -> impl Strategy<Value = BigUint> {
    prop_oneof![
        1 => Just(BigUint::from(0u64)),
        1 => Just(BigUint::from(1u64)),
        1 => Just(BigUint::from(u64::MAX)),
        10 => (0u64..100).prop_map(BigUint::from),
        5 => (0u64..10000).prop_map(BigUint::from),
    ]
}

fn arbitrary_kv_pairs<F: PrimeField>(max_size: usize) -> impl Strategy<Value = Vec<(BigUint, F)>> {
    prop::collection::vec(
        (arbitrary_index(), arbitrary_field_element::<F>()),
        0..=max_size,
    )
}

fn arbitrary_tree_height() -> impl Strategy<Value = usize> {
    prop_oneof![
        1 => Just(1),
        1 => Just(2),
        5 => 3usize..10,
        1 => Just(32),
    ]
}

fn arbitrary_sparse_tree<F: PrimeField + RescueParameter>(
) -> impl Strategy<Value = (TestUniversalMerkleTree<F>, Vec<(BigUint, F)>)> {
    (arbitrary_tree_height(), arbitrary_kv_pairs::<F>(10)).prop_map(|(height, kvs)| {
        let tree = TestUniversalMerkleTree::<F>::from_kv_set(height, &kvs).unwrap();
        (tree, kvs)
    })
}

fn corrupt_proof<F: PrimeField + RescueParameter>(
    mut proof: <TestUniversalMerkleTree<F> as MerkleTreeScheme>::MembershipProof,
    corruption_type: CorruptionType,
) -> <TestUniversalMerkleTree<F> as MerkleTreeScheme>::MembershipProof {
    match corruption_type {
        CorruptionType::PositionIncrement => {
            proof.pos = proof.pos + BigUint::from(1u64);
            proof
        },
        CorruptionType::ValueCorruption => {
            if !proof.proof.is_empty() {
                let idx = 0; // Just corrupt first element for simplicity
                if let MerkleNode::Leaf { value, .. } = &proof.proof[idx] {
                    let corrupted = value.clone() + F::one();
                    proof.proof[idx] = MerkleNode::Leaf {
                        value: corrupted.clone(),
                        pos: BigUint::from(0u64),
                        elem: corrupted,
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
            proof.pos = BigUint::from(2u64).pow(64) + BigUint::from(1u64);
            proof
        },
        CorruptionType::ZeroFields => {
            for node in &mut proof.proof {
                match node {
                    MerkleNode::Leaf { value, elem, .. } => {
                        *value = F::zero();
                        *elem = F::zero();
                    },
                    MerkleNode::Branch { value, .. } => {
                        *value = F::zero();
                    },
                    MerkleNode::ForgettenSubtree { value } => {
                        *value = F::zero();
                    },
                    _ => {},
                }
            }
            proof
        },
        CorruptionType::MaxFields => {
            let max_val = -F::one();
            for node in &mut proof.proof {
                match node {
                    MerkleNode::Leaf { value, elem, .. } => {
                        *value = max_val;
                        *elem = max_val;
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
                                value: F::zero(),
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
                if let MerkleNode::Leaf { value, elem, pos } = node {
                    *value = elem.clone() + F::one();
                    *pos = pos.clone() ^ BigUint::from(0xFFu64);
                }
            }
            proof
        },
        CorruptionType::LeafPositionMismatch => {
            for (i, node) in proof.proof.iter_mut().enumerate() {
                if let MerkleNode::Leaf { pos, .. } = node {
                    *pos = BigUint::from((i as u64).wrapping_mul(12345).wrapping_add(999));
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
                    value: F::from((i * 7) as u64),
                    pos: BigUint::from((i * 13) as u64),
                    elem: F::from((i * 17) as u64),
                })
                .collect();
            proof
        },
        CorruptionType::MixNodeTypes => {
            for (i, node) in proof.proof.iter_mut().enumerate() {
                *node = match i % 3 {
                    0 => MerkleNode::Empty,
                    1 => MerkleNode::Branch {
                        value: F::from(i as u64),
                        children: vec![],
                    },
                    _ => MerkleNode::ForgettenSubtree {
                        value: F::from(i as u64),
                    },
                };
            }
            proof
        },
        CorruptionType::PrependForgotten => {
            let mut new_proof = vec![
                MerkleNode::ForgettenSubtree { value: F::one() },
                MerkleNode::ForgettenSubtree { value: F::zero() },
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
                    value: F::from((i + 1) as u64),
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
                proof.proof = vec![MerkleNode::ForgettenSubtree { value: F::zero() }];
            } else {
                let len = proof.proof.len();
                proof.proof = (0..len)
                    .map(|i| MerkleNode::ForgettenSubtree {
                        value: F::from(i as u64),
                    })
                    .collect();
            }
            proof
        },
        CorruptionType::PositionWrappedAround => {
            proof.pos = BigUint::from(2u64).pow(256) - BigUint::from(1u64);
            proof
        },
        CorruptionType::UnbalancedStructure => {
            let base_size = proof.proof.len().max(2);
            let mut new_proof = Vec::with_capacity(base_size * 2);

            for i in 0..base_size {
                match i % 4 {
                    0 => new_proof.push(MerkleNode::Leaf {
                        value: F::from((i * 3) as u64),
                        pos: BigUint::from((i * 1000) as u64),
                        elem: F::from((i * 7) as u64),
                    }),
                    1 => new_proof.push(MerkleNode::Branch {
                        value: F::from(i as u64),
                        children: if i % 2 == 0 {
                            vec![]
                        } else {
                            vec![Arc::new(MerkleNode::Empty)]
                        },
                    }),
                    2 => new_proof.push(MerkleNode::Empty),
                    _ => new_proof.push(MerkleNode::ForgettenSubtree {
                        value: F::from((i * 42) as u64),
                    }),
                }
            }

            proof.proof = new_proof;
            proof
        },
    }
}

fn arbitrary_proof<F: PrimeField + RescueParameter>(
) -> impl Strategy<Value = <TestUniversalMerkleTree<F> as MerkleTreeScheme>::MembershipProof> {
    (
        arbitrary_index(),
        prop::collection::vec(
            prop_oneof![
                1 => Just(MerkleNode::Empty),
                1 => arbitrary_field_element::<F>().prop_map(|v| MerkleNode::Leaf {
                    value: v.clone(),
                    pos: BigUint::from(0u64),
                    elem: v,
                }),
                1 => arbitrary_field_element::<F>().prop_map(|v| MerkleNode::Branch {
                    value: v,
                    children: vec![],
                }),
                1 => arbitrary_field_element::<F>().prop_map(|v| MerkleNode::ForgettenSubtree {
                    value: v,
                }),
            ],
            0..10,
        ),
    )
        .prop_map(|(pos, proof)| MerkleProof { pos, proof })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn universal_verify_never_panics_fr254(
        (tree, _kvs) in arbitrary_sparse_tree::<Fr254>(),
        pos in arbitrary_index(),
        proof in arbitrary_proof::<Fr254>(),
    ) {
        let root = tree.commitment().digest();
        let _ = TestUniversalMerkleTree::<Fr254>::verify(&root, &pos, &proof);
    }

    #[test]
    fn universal_non_membership_verify_never_panics_fr254(
        (tree, _) in arbitrary_sparse_tree::<Fr254>(),
        pos in arbitrary_index(),
        proof in arbitrary_proof::<Fr254>(),
    ) {
        let _ = tree.non_membership_verify(&pos, &proof);
    }

    #[test]
    fn universal_remember_never_panics_fr254(
        (mut tree, _kvs) in arbitrary_sparse_tree::<Fr254>(),
        pos in arbitrary_index(),
        elem in arbitrary_field_element::<Fr254>(),
        proof in arbitrary_proof::<Fr254>(),
    ) {
        let _ = tree.remember(&pos, &elem, &proof);
    }

    #[test]
    fn universal_non_membership_remember_never_panics_fr254(
        (mut tree, _) in arbitrary_sparse_tree::<Fr254>(),
        pos in arbitrary_index(),
        proof in arbitrary_proof::<Fr254>(),
    ) {
        let _ = tree.non_membership_remember(pos, &proof);
    }

    #[test]
    fn universal_corrupted_membership_proofs_handled_safely_fr254(
        (tree, kvs) in arbitrary_sparse_tree::<Fr254>(),
        corruption_type in any::<CorruptionType>(),
    ) {
        // Skip test if tree is empty
        prop_assume!(!kvs.is_empty());

        let root = tree.commitment().digest();

        let (key, _) = &kvs[0];
        match tree.universal_lookup(key) {
            LookupResult::Ok(_, proof) => {
                let corrupted_proof = corrupt_proof::<Fr254>(proof, corruption_type);
                let _ = TestUniversalMerkleTree::<Fr254>::verify(&root, key, &corrupted_proof);
            }
            _ => unreachable!()
        }
    }

    #[test]
    fn universal_corrupted_non_membership_proofs_handled_safely_fr254(
        (tree, _kvs) in arbitrary_sparse_tree::<Fr254>(),
        corruption_type in any::<CorruptionType>(),
    ) {
        let search_limit = tree.capacity().min(1000u64.into()).to_u64().unwrap();

        let mut found_non_member = false;
        for i in 0..search_limit {
            let candidate = BigUint::from(i);
            match tree.universal_lookup(&candidate) {
                LookupResult::NotFound(proof) => {
                    let corrupted_proof = corrupt_proof::<Fr254>(proof, corruption_type);
                    let _ = tree.non_membership_verify(&candidate, &corrupted_proof);
                    found_non_member = true;
                    break;
                }
                _ => continue,
            }
        }

        // Skip test if we couldn't find any non-member
        prop_assume!(found_non_member);
    }
}
