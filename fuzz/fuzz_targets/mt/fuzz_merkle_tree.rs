#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use jf_merkle_tree::{
    hasher::HasherMerkleTree, universal_merkle_tree::UniversalMerkleTree, MerkleTreeScheme,
};
use libfuzzer_sys::fuzz_target;
use rand::seq::IndexedRandom;
use sha2::Sha256;

#[derive(Arbitrary, Debug)]
struct MerkleTreeArbitraryInput {
    // height: usize,
    elems: Vec<usize>,
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = MerkleTreeArbitraryInput::arbitrary(&mut unstructured) {
        let mt = HasherMerkleTree::<Sha256, usize>::from_elems(None, input.elems.clone()).unwrap();
        let input_elems_len = input.elems.len();
        if let Some(random_lookup) = (0..input_elems_len)
            .into_iter()
            .collect::<Vec<_>>()
            .choose(&mut rand::rng())
            .cloned()
        {
            let commitment = mt.commitment();
            let (val, proof) = mt.lookup(random_lookup as u64).expect_ok().unwrap();

            assert!(HasherMerkleTree::<Sha256, usize>::verify(
                commitment,
                random_lookup as u64,
                val,
                proof
            )
            .is_ok());
        }
    }
});
