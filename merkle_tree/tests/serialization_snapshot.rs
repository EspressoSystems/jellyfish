//! Serialization snapshot tests for merkle tree structures used in Espresso
//! network.
//!
//! Tests serialization/deserialization of commitments and proofs to detect
//! breaking changes. In espresso-network we depend on compatibility of
//! commitments and serialization of proofs. If any of the tests in this file
//! fail the change in jellyfish would break the application.
//!
//! Run tests with `cargo test`, then review snapshots with `cargo insta review`
//! if new snapshots are added or tests fail. See `cargo insta --help` for more.
//!
//! For manual workflow (without `cargo insta`)
//! - reject: `INSTA_UPDATE=no cargo test`
//! - accept: `INSTA_UPDATE=always cargo test`.

use insta::assert_json_snapshot;
use jf_merkle_tree::{
    prelude::{LightWeightSHA3MerkleTree, Sha3Digest, Sha3Node},
    universal_merkle_tree::UniversalMerkleTree,
    AppendableMerkleTreeScheme, MerkleTreeScheme, UniversalMerkleTreeScheme,
};

// These aren't the exact trees used in epresso-network but are
// matching kind of trees and have matching arity
type BlockTree = LightWeightSHA3MerkleTree<u64>;
type FeeTree = UniversalMerkleTree<u64, Sha3Digest, u64, 256, Sha3Node>;
type RewardsTree = UniversalMerkleTree<u64, Sha3Digest, u64, 2, Sha3Node>;

#[test]
fn test_fee_merkle_tree_serialization() {
    let mut tree = FeeTree::new(8);

    let fee_data = vec![
        (1u64, 100u64),
        (2u64, 250u64),
        (3u64, 500u64),
        (4u64, 1000u64),
        (5u64, 2000u64),
    ];
    for (tx_id, fee) in fee_data {
        tree.update(tx_id, fee).unwrap();
    }

    let commitment = tree.commitment();
    assert_json_snapshot!("fee_tree_commitment", commitment);

    let mut proofs = Vec::new();
    for tx_id in 1u64..=5u64 {
        if let jf_merkle_tree::LookupResult::Ok(elem, proof) = tree.universal_lookup(tx_id) {
            proofs.push((tx_id, elem, proof));
        }
    }

    assert_json_snapshot!("fee_membership_proofs", proofs);
}

#[test]
fn test_block_merkle_tree_serialization() {
    let mut tree = BlockTree::new(8);

    let block_data = vec![
        0x1234567890abcdefu64,
        0xfedcba0987654321u64,
        0x1111222233334444u64,
        0x5555666677778888u64,
        0x9999aaaabbbbccccu64,
        0xddddeeeeffff0000u64,
    ];

    for block in block_data {
        tree.push(block).unwrap();
    }

    let commitment = tree.commitment();
    assert_json_snapshot!("block_tree_commitment", commitment);

    let mut proofs = Vec::new();
    for i in 0..tree.num_leaves() {
        if let jf_merkle_tree::LookupResult::Ok(elem, proof) = tree.lookup(i) {
            proofs.push((i, elem, proof));
        }
    }

    assert_json_snapshot!("block_membership_proofs", proofs);
}

#[test]
fn test_rewards_tree_serialization() {
    let mut tree = RewardsTree::new(8);

    let rewards = vec![
        (10u64, 1000u64),
        (25u64, 2500u64),
        (50u64, 5000u64),
        (100u64, 10000u64),
    ];

    for &(account, reward) in &rewards {
        tree.update(account, reward).unwrap();
    }

    let commitment = tree.commitment();
    assert_json_snapshot!("rewards_tree_commitment", commitment);

    let mut proofs = Vec::new();
    for &(account, _reward) in &rewards {
        if let jf_merkle_tree::LookupResult::Ok(elem, proof) = tree.universal_lookup(account) {
            proofs.push((account, elem, proof));
        }
    }

    assert_json_snapshot!("rewards_membership_proofs", proofs);
}

#[test]
fn test_rewards_tree_non_membership_proofs() {
    let mut tree = RewardsTree::new(8);

    let rewards = vec![(10u64, 1000u64), (50u64, 5000u64), (100u64, 10000u64)];

    for &(account, reward) in &rewards {
        tree.update(account, reward).unwrap();
    }

    let non_member_accounts = vec![5u64, 15u64, 75u64, 200u64];
    let mut non_membership_proofs = Vec::new();

    for &account in &non_member_accounts {
        if let jf_merkle_tree::LookupResult::NotFound(proof) = tree.universal_lookup(account) {
            non_membership_proofs.push((account, proof));
        }
    }

    assert_json_snapshot!("rewards_non_membership_proofs", non_membership_proofs);
}

#[test]
fn test_fee_tree_non_membership_proofs() {
    let mut tree = FeeTree::new(8);

    let fees = vec![(1u64, 100u64), (5u64, 250u64), (10u64, 500u64)];

    for &(tx_id, fee) in &fees {
        tree.update(tx_id, fee).unwrap();
    }

    let non_member_txs = vec![2u64, 3u64, 7u64, 15u64];
    let mut non_membership_proofs = Vec::new();

    for &tx_id in &non_member_txs {
        if let jf_merkle_tree::LookupResult::NotFound(proof) = tree.universal_lookup(tx_id) {
            non_membership_proofs.push((tx_id, proof));
        }
    }

    assert_json_snapshot!("fee_non_membership_proofs", non_membership_proofs);
}

#[test]
fn test_empty_tree_serialization() {
    let tree = BlockTree::new(8);
    let commitment = tree.commitment();

    assert_json_snapshot!("empty_tree_commitment", commitment);
}

#[test]
fn test_single_element_tree_serialization() {
    let mut tree = BlockTree::new(4);
    tree.push(42u64).unwrap();

    let commitment = tree.commitment();
    assert_json_snapshot!("single_element_tree_commitment", commitment);

    if let jf_merkle_tree::LookupResult::Ok(elem, proof) = tree.lookup(0u64) {
        assert_json_snapshot!("single_element_proof", (0u64, elem, proof));
    }
}

#[test]
fn test_full_tree_serialization() {
    let mut tree = BlockTree::new(3);

    for i in 0..8 {
        tree.push(i * 10).unwrap();
    }

    let commitment = tree.commitment();
    assert_json_snapshot!("full_tree_commitment", commitment);
}
