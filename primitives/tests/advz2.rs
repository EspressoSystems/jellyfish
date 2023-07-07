use ark_bls12_381::Bls12_381;
use ark_std::{rand::RngCore, vec};
use jf_primitives::{
    pcs::{checked_fft_size, prelude::UnivariateKzgPCS, PolynomialCommitmentScheme},
    vid::{
        advz2::{AdvzParams, AdvzPayload},
        VidPayload,
    },
};
use sha2::Sha256;

#[test]
fn advz2_wip() {
    // play with these items
    let vid_sizes = [(5, 9)];
    let payload_tx_byte_lens = [[100, 150, 200, 250]];

    // more items as a function of the above
    let supported_degree = vid_sizes.iter().max_by_key(|v| v.0).unwrap().0;
    let mut rng = jf_utils::test_rng();
    let srs = UnivariateKzgPCS::<Bls12_381>::gen_srs_for_testing(
        &mut rng,
        checked_fft_size(supported_degree).unwrap(),
    )
    .unwrap();

    for (payload_chunk_size, num_storage_nodes) in vid_sizes {
        let params =
            AdvzParams::<Bls12_381>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap();

        for tx_byte_lens in payload_tx_byte_lens {
            let txs: Vec<Vec<u8>> = tx_byte_lens
                .into_iter()
                .map(|tx_byte_len| {
                    let mut bytes_random = vec![0u8; tx_byte_len];
                    rng.fill_bytes(&mut bytes_random);
                    bytes_random
                })
                .collect();

            let _payload = AdvzPayload::<Bls12_381, Sha256>::from_txs(params.clone(), txs);
        }
    }
}
