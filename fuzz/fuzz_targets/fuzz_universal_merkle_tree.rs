#![no_main]

use ark_bls12_377::Fr as Fr377;
use ark_bls12_381::Fr as Fr381;
use ark_bn254::Fr as Fr254;
use hashbrown::HashMap;

use arbitrary::{Arbitrary, Unstructured};
use jf_merkle_tree::prelude::{RescueHash, UniversalMerkleTree};
use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;

#[derive(Arbitrary, Debug)]
struct MerkleTreeArbitraryInput {
    kv: Vec<u64>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    if let Ok(input) = MerkleTreeArbitraryInput::arbitrary(&mut unstructured) {
        let kv_pairs = input
            .kv
            .iter()
            .map(|k| (BigUint::from(*k), Fr377::from(*k)))
            .collect::<HashMap<BigUint, Fr377>>();
        let height = kv_pairs.len();
        let _ = UniversalMerkleTree::<Fr377, RescueHash<Fr377>, BigUint, 3, Fr377>::from_kv_set(
            height,
            kv_pairs.clone(),
        )
        .unwrap();

        let kv_pairs = input
            .kv
            .iter()
            .map(|k| (BigUint::from(*k), Fr381::from(*k)))
            .collect::<HashMap<BigUint, Fr381>>();
        let _ = UniversalMerkleTree::<Fr381, RescueHash<Fr381>, BigUint, 3, Fr381>::from_kv_set(
            height,
            kv_pairs.clone(),
        )
        .unwrap();

        let kv_pairs = input
            .kv
            .iter()
            .map(|k| (BigUint::from(*k), Fr254::from(*k)))
            .collect::<HashMap<BigUint, Fr254>>();
        let _ = UniversalMerkleTree::<Fr254, RescueHash<Fr254>, BigUint, 3, Fr254>::from_kv_set(
            height, kv_pairs,
        )
        .unwrap();
    }
});
