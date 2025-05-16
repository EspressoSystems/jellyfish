#![no_main]

use ark_bn254::Fr as Fr254;
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use jf_rescue::crhf::RescueCRHF;
use jf_merkle_tree::MerkleTreeScheme;
use jf_merkle_tree::prelude::RescueLightWeightMerkleTree;
use rand::seq::SliceRandom;
use rand::thread_rng;
use jf_merkle_tree::LookupResult;

#[derive(Arbitrary, Debug)]
struct MerkleTreeArbitraryInput {
    height: usize,
    elems: Vec<u64>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = MerkleTreeArbitraryInput::arbitrary(&mut unstructured) {
        if input.elems.is_empty() {
            return;
        }

        let elems: Vec<Fr254> = input.elems.iter().map(|x| Fr254::from(*x)).collect();
        if let Ok(mt) = RescueLightWeightMerkleTree::<Fr254>::from_elems(None, elems) {
            let input_elems_len = input.elems.len();
            if let Some(random_lookup) = (0..input_elems_len)
                .into_iter()
                .collect::<Vec<_>>()
                .choose(&mut thread_rng())
                .cloned()
            {
            let commitment = mt.commitment();
            if let LookupResult::Ok(_, proof) = mt.lookup(random_lookup as u64) {
                assert_eq!(
                    mt,
                    bincode::deserialize(&bincode::serialize(&mt).unwrap()).unwrap()
                );
                assert_eq!(
                    proof,
                    bincode::deserialize(&bincode::serialize(&proof).unwrap()).unwrap()
                );
            }
        }}
    }
});
