#![no_main]

use ark_bls12_377::Fr as Fr377;
use ark_bls12_381::Fr as Fr381;
use ark_bn254::Fr as Fr254;
use hashbrown::HashMap;

use arbitrary::{Arbitrary, Unstructured};
use jf_merkle_tree::prelude::{RescueHash, RescueLightWeightMerkleTree, RescueMerkleTree};
use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use jf_merkle_tree::MerkleTreeScheme;
use rand::seq::SliceRandom;
use rand::thread_rng;

#[derive(Arbitrary, Debug)]
struct MerkleTreeArbitraryInput {
    height: usize,
    elems: Vec<u64>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    if let Ok(input) = MerkleTreeArbitraryInput::arbitrary(&mut unstructured) {
       let elems: Vec<Fr254> = input.elems.iter().map(|x| Fr254::from(*x)).collect();
       if let Ok(mt) = RescueLightWeightMerkleTree::<Fr254>::from_elems(None, elems) {

        if let Some(random_lookup) = (0..input.elems.len())
            .into_iter()
            .collect::<Vec<_>>()
            .choose(&mut thread_rng())
            .cloned()
        {
            let commitment = mt.commitment();
            if let jf_merkle_tree::LookupResult::Ok(elem, proof) = mt.lookup(random_lookup as u64) {
                assert!(
                    RescueLightWeightMerkleTree::<Fr254>::verify(&commitment, random_lookup as u64, elem, &proof)
                        .unwrap()
                        .is_ok()
                );
            }            
        }
       }
    }
});
