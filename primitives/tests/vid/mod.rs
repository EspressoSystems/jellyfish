use ark_std::{
    println,
    rand::{seq::SliceRandom, CryptoRng, RngCore},
    vec,
};
use core::iter::zip;
use jf_primitives::vid::{VidError, VidResult, VidScheme};

/// Correctness test generic over anything that impls [`VidScheme`]
///
/// `pub` visibility, but it's not part of this crate's public API
/// because it's in an integration test.
/// <https://doc.rust-lang.org/book/ch11-03-test-organization.html#submodules-in-integration-tests>
pub fn round_trip<V, R>(
    vid_factory: impl Fn(usize, usize, usize) -> V,
    vid_sizes: &[(usize, usize)],
    multiplicities: &[usize],
    payload_byte_lens: &[usize],
    rng: &mut R,
) where
    V: VidScheme,
    R: RngCore + CryptoRng,
{
    for (&mult, &(payload_chunk_size, num_storage_nodes)) in
        zip(multiplicities.iter().cycle(), vid_sizes)
    {
        let mut vid = vid_factory(payload_chunk_size, num_storage_nodes, mult);

        for &len in payload_byte_lens {
            println!(
                "m: {} n: {} mult: {} byte_len: {}",
                payload_chunk_size, num_storage_nodes, mult, len
            );

            let bytes_random = {
                let mut bytes_random = vec![0u8; len];
                rng.fill_bytes(&mut bytes_random);
                bytes_random
            };

            let disperse = vid.disperse(&bytes_random).unwrap();
            let (mut shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);
            assert_eq!(shares.len(), num_storage_nodes);
            assert_eq!(commit, vid.commit_only(&bytes_random).unwrap());
            assert_eq!(len, V::get_payload_byte_len(&common));
            assert_eq!(mult, V::get_multiplicity(&common));
            assert_eq!(num_storage_nodes, V::get_num_storage_nodes(&common));

            for share in shares.iter() {
                vid.verify_share(share, &common, &commit).unwrap().unwrap();
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
