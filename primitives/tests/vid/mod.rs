use jf_primitives::vid::{VidError, VidResult, VidScheme};

use ark_std::{
    println,
    rand::{seq::SliceRandom, CryptoRng, RngCore},
    vec,
};

/// Correctness test generic over anything that impls [`VidScheme`]
///
/// `pub` visibility, but it's not part of this crate's public API
/// because it's in an integration test.
/// <https://doc.rust-lang.org/book/ch11-03-test-organization.html#submodules-in-integration-tests>
pub fn round_trip<V, R>(
    vid_factory: impl Fn(usize, usize) -> V,
    vid_sizes: &[(usize, usize)],
    payload_byte_lens: &[usize],
    rng: &mut R,
) where
    V: VidScheme,
    R: RngCore + CryptoRng,
{
    for &(payload_chunk_size, num_storage_nodes) in vid_sizes {
        let vid = vid_factory(payload_chunk_size, num_storage_nodes);

        for &len in payload_byte_lens {
            println!(
                "m: {} n: {} byte_len: {}",
                payload_chunk_size, num_storage_nodes, len
            );

            let mut bytes_random = vec![0u8; len];
            rng.fill_bytes(&mut bytes_random);

            let (mut shares, common) = vid.dispersal_data(&bytes_random).unwrap();
            assert_eq!(shares.len(), num_storage_nodes);

            for share in shares.iter() {
                vid.verify_share(share, &common).unwrap().unwrap();
            }

            // sample a random subset of shares with size payload_chunk_size
            shares.shuffle(rng);

            // give minimum number of shares for recovery
            let bytes_recovered = vid
                .recover_payload(&shares[..payload_chunk_size], &common)
                .unwrap();
            assert_eq!(bytes_recovered, bytes_random);

            // give an intermediate number of shares for recovery
            let intermediate_num_shares = (payload_chunk_size + num_storage_nodes) / 2;
            let bytes_recovered = vid
                .recover_payload(&shares[..intermediate_num_shares], &common)
                .unwrap();
            assert_eq!(bytes_recovered, bytes_random);

            // give all shares for recovery
            let bytes_recovered = vid.recover_payload(&shares, &common).unwrap();
            assert_eq!(bytes_recovered, bytes_random);

            // give insufficient shares for recovery
            assert_arg_err(
                vid.recover_payload(&shares[..payload_chunk_size - 1], &common),
                "insufficient shares should be arg error",
            );
        }
    }
}

/// Convenience wrapper to assert [`VidError::Argument`] return value.
///
/// TODO: copied code from unit tests---how to reuse unit test code in
/// integration tests?
pub fn assert_arg_err<T>(res: VidResult<T>, msg: &str) {
    assert!(matches!(res, Err(VidError::Argument(_))), "{}", msg);
}
