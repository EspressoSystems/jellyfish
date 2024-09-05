use super::{VidError::Argument, *};
use ark_bn254::Bn254;
use ark_std::{
    rand::{CryptoRng, RngCore},
    vec,
};
use jf_pcs::{
    checked_fft_size,
    prelude::{Commitment, UnivariateUniversalParams},
};
use jf_utils::field_byte_len;
use sha2::Sha256;

#[ignore]
#[test]
fn disperse_timer() {
    // run with 'print-trace' feature to see timer output
    let (recovery_threshold, num_storage_nodes) = (256, 512);
    let mut rng = jf_utils::test_rng();
    let srs = init_srs(recovery_threshold as usize, &mut rng);
    #[cfg(feature = "gpu-vid")]
    let mut advz_gpu =
        AdvzGPU::<'_, Bn254, Sha256>::new(num_storage_nodes, recovery_threshold, &srs).unwrap();
    let mut advz = Advz::<Bn254, Sha256>::new(num_storage_nodes, recovery_threshold, srs).unwrap();

    let payload_random = init_random_payload(1 << 25, &mut rng);

    #[cfg(feature = "gpu-vid")]
    let _ = advz_gpu.disperse(payload_random.clone());
    let _ = advz.disperse(payload_random);
}

#[ignore]
#[test]
fn commit_only_timer() {
    // run with 'print-trace' feature to see timer output
    let (recovery_threshold, num_storage_nodes) = (256, 512);
    let mut rng = jf_utils::test_rng();
    let srs = init_srs(recovery_threshold as usize, &mut rng);
    #[cfg(feature = "gpu-vid")]
    let mut advz_gpu =
        AdvzGPU::<'_, Bn254, Sha256>::new(num_storage_nodes, recovery_threshold, &srs).unwrap();
    let mut advz = Advz::<Bn254, Sha256>::new(num_storage_nodes, recovery_threshold, srs).unwrap();

    let payload_random = init_random_payload(1 << 25, &mut rng);

    #[cfg(feature = "gpu-vid")]
    let _ = advz_gpu.commit_only(payload_random.clone());

    let _ = advz.commit_only(payload_random);
}

#[test]
fn sad_path_verify_share_corrupt_share() {
    let (mut advz, bytes_random) = advz_init();
    let disperse = advz.disperse(bytes_random).unwrap();
    let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);

    for (i, share) in shares.iter().enumerate() {
        // missing share eval
        {
            let mut share_missing_eval = share.clone();
            Share::<Bn254, Sha256>::extract_leaf_mut(&mut share_missing_eval.evals_proof)
                .unwrap()
                .pop();
            assert_arg_err(
                advz.verify_share(&share_missing_eval, &common, &commit),
                "1 missing share should be arg error",
            );
        }

        // corrupted share eval
        {
            let mut share_bad_eval = share.clone();
            Share::<Bn254, Sha256>::extract_leaf_mut(&mut share_bad_eval.evals_proof).unwrap()[0]
                .double_in_place();
            advz.verify_share(&share_bad_eval, &common, &commit)
                .unwrap()
                .expect_err("bad share value should fail verification");
        }

        // corrupted index, in bounds
        {
            let share_bad_index = Share {
                index: (share.index + 1) % advz.num_storage_nodes,
                ..share.clone()
            };
            advz.verify_share(&share_bad_index, &common, &commit)
                .unwrap()
                .expect_err("bad share index should fail verification");
        }

        // corrupted index, out of bounds
        {
            let share_bad_index = Share {
                index: share.index + advz.num_storage_nodes,
                ..share.clone()
            };
            advz.verify_share(&share_bad_index, &common, &commit)
                .unwrap()
                .expect_err("bad share index should fail verification");
        }

        // corrupt eval proof
        {
            // We have no way to corrupt a proof
            // (without also causing a deserialization failure).
            // So we use another share's proof instead.
            let share_bad_evals_proof = Share {
                evals_proof: shares[(i + 1) % shares.len()].evals_proof.clone(),
                ..share.clone()
            };
            advz.verify_share(&share_bad_evals_proof, &common, &commit)
                .unwrap()
                .expect_err("bad share evals proof should fail verification");
        }
    }
}

#[test]
fn sad_path_verify_share_corrupt_commit() {
    let (mut advz, bytes_random) = advz_init();
    let disperse = advz.disperse(bytes_random).unwrap();
    let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);

    // missing commit
    let common_missing_item = Common {
        poly_commits: common.poly_commits[1..].to_vec(),
        ..common.clone()
    };
    assert_arg_err(
        advz.verify_share(&shares[0], &common_missing_item, &commit),
        "1 missing commit should be arg error",
    );

    // 1 corrupt commit, poly_commit
    let common_1_poly_corruption = {
        let mut corrupted = common.clone();
        corrupted.poly_commits[0] = <Bn254 as Pairing>::G1Affine::zero().into();
        corrupted
    };
    assert_arg_err(
        advz.verify_share(&shares[0], &common_1_poly_corruption, &commit),
        "corrupted commit should be arg error",
    );

    // 1 corrupt commit, all_evals_digest
    let common_1_digest_corruption = {
        let mut corrupted = common;
        let mut digest_bytes = vec![0u8; corrupted.all_evals_digest.uncompressed_size()];
        corrupted
            .all_evals_digest
            .serialize_uncompressed(&mut digest_bytes)
            .expect("digest serialization should succeed");
        digest_bytes[0] += 1;
        corrupted.all_evals_digest = HasherNode::deserialize_uncompressed(digest_bytes.as_slice())
            .expect("digest deserialization should succeed");
        corrupted
    };
    advz.verify_share(&shares[0], &common_1_digest_corruption, &commit)
        .unwrap()
        .expect_err("1 corrupt all_evals_digest should fail verification");
}

#[test]
fn sad_path_verify_share_corrupt_share_and_commit() {
    let (mut advz, bytes_random) = advz_init();
    let disperse = advz.disperse(bytes_random).unwrap();
    let (mut shares, mut common, commit) = (disperse.shares, disperse.common, disperse.commit);

    common.poly_commits.pop();
    Share::<Bn254, Sha256>::extract_leaf_mut(&mut shares[0].evals_proof)
        .unwrap()
        .pop();

    // equal nonzero lengths for common, share
    assert_arg_err(
        advz.verify_share(&shares[0], &common, &commit),
        "common inconsistent with commit should be arg error",
    );

    common.poly_commits.clear();
    Share::<Bn254, Sha256>::extract_leaf_mut(&mut shares[0].evals_proof)
        .unwrap()
        .clear();

    // zero length for common, share
    assert_arg_err(
        advz.verify_share(&shares[0], &common, &commit),
        "expect arg error for common inconsistent with commit",
    );
}

#[test]
fn sad_path_recover_payload_corrupt_shares() {
    let (mut advz, bytes_random) = advz_init();
    let disperse = advz.disperse(&bytes_random).unwrap();
    let (shares, common) = (disperse.shares, disperse.common);

    {
        // unequal share eval lengths
        let mut shares_missing_evals = shares.clone();
        for i in 0..shares_missing_evals.len() - 1 {
            Share::<Bn254, Sha256>::extract_leaf_mut(&mut shares_missing_evals[i].evals_proof)
                .unwrap()
                .pop();
            assert_arg_err(
                advz.recover_payload(&shares_missing_evals, &common),
                format!("{} shares missing 1 eval should be arg error", i + 1).as_str(),
            );
        }

        // 1 eval missing from all shares
        Share::<Bn254, Sha256>::extract_leaf_mut(
            &mut shares_missing_evals.last_mut().unwrap().evals_proof,
        )
        .unwrap()
        .pop();
        assert_arg_err(
            advz.recover_payload(&shares_missing_evals, &common),
            format!("all shares missing 1 eval should be arg error").as_str(),
        );
    }

    // corrupted index, in bounds
    {
        let mut shares_bad_indices = shares.clone();

        // permute indices to avoid duplicates and keep them in bounds
        for share in &mut shares_bad_indices {
            share.index = (share.index + 1) % advz.num_storage_nodes;
        }

        let bytes_recovered = advz
            .recover_payload(&shares_bad_indices, &common)
            .expect("recover_payload should succeed when indices are in bounds");
        assert_ne!(bytes_recovered, bytes_random);
    }

    // corrupted index, out of bounds
    {
        let mut shares_bad_indices = shares.clone();
        let multi_open_domain_size = advz.multi_open_domain(common.multiplicity).unwrap().size();
        for i in 0..shares_bad_indices.len() {
            shares_bad_indices[i].index += u32::try_from(multi_open_domain_size).unwrap();
            advz.recover_payload(&shares_bad_indices, &common)
                .expect_err("recover_payload should fail when indices are out of bounds");
        }
    }
}

#[test]
fn verify_share_with_multiplicity() {
    let advz_params = AdvzParams {
        recovery_threshold: 16,
        num_storage_nodes: 20,
        max_multiplicity: 4,
        payload_len: 4000,
    };
    let (mut advz, payload) = advz_init_with::<Bn254>(advz_params);

    let disperse = advz.disperse(payload).unwrap();
    let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);

    for share in shares {
        advz.verify_share(&share, &common, &commit)
            .unwrap()
            .unwrap()
    }
}

#[test]
fn verify_share_with_different_multiplicity() {
    // leader_multiplicity < everyone else's multiplicity
    verify_share_with_different_multiplicity_helper::<Bn254, Sha256>(4, 2);
    // leader_multiplicity > everyone else's multiplicity
    verify_share_with_different_multiplicity_helper::<Bn254, Sha256>(2, 4);
}

fn verify_share_with_different_multiplicity_helper<E, H>(
    multiplicity: u32,
    leader_multiplicity: u32,
) where
    E: Pairing,
    H: HasherDigest,
{
    // play with these items
    let num_storage_nodes = 6;
    let recovery_threshold = 4;

    // more items as a function of the above
    assert_ne!(
        multiplicity, leader_multiplicity,
        "leader_multiplicity should differ from multiplicity for this test"
    );
    let max_degree = recovery_threshold * multiplicity.max(leader_multiplicity);
    let mut rng = jf_utils::test_rng();
    let srs = init_srs(max_degree as usize, &mut rng);
    let advz =
        Advz::<E, H>::with_multiplicity(num_storage_nodes, recovery_threshold, multiplicity, &srs)
            .unwrap();
    let mut leader_advz = Advz::<E, H>::with_multiplicity(
        num_storage_nodes,
        recovery_threshold,
        leader_multiplicity,
        &srs,
    )
    .unwrap();
    let payload = {
        // ensure payload is large enough to fill at least 1 polynomial at
        // maximum multiplicity.
        let coeff_byte_len = field_byte_len::<<E as Pairing>::ScalarField>();
        let payload_byte_len = max_degree as usize * coeff_byte_len;
        init_random_payload(payload_byte_len, &mut rng)
    };

    // compute shares using `leader_multiplicity`
    let disperse = leader_advz.disperse(payload).unwrap();
    let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);

    // verify shares using `multiplicity` != `leader_multiplicity`
    for share in shares {
        assert_arg_err(
            advz.verify_share(&share, &common, &commit),
            format!("inconsistent multiplicities should be arg error").as_str(),
        );
    }
}

#[test]
fn max_multiplicity() {
    // regression test for https://github.com/EspressoSystems/jellyfish/issues/663

    // play with these items
    let num_storage_nodes = 6;
    let recovery_threshold = 4;
    let max_multiplicity = 1 << 5; // intentionally large so as to fit many payload sizes into a single polynomial

    let payload_byte_lens = [0, 1, 100, 10_000];
    type E = Bn254;

    // more items as a function of the above
    let (mut advz, payload_bytes) = advz_init_with::<E>(AdvzParams {
        recovery_threshold,
        num_storage_nodes,
        max_multiplicity,
        payload_len: *payload_byte_lens.iter().max().unwrap(),
    });
    let elem_byte_len = bytes_to_field::elem_byte_capacity::<<E as Pairing>::ScalarField>();
    let (mut found_small_payload, mut found_large_payload) = (false, false);

    for payload_byte_len in payload_byte_lens {
        let payload = &payload_bytes[..payload_byte_len];
        let num_payload_elems = payload_byte_len.div_ceil(elem_byte_len) as u32;

        let disperse = advz.disperse(payload).unwrap();
        let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);

        // test: multiplicity set correctly
        assert!(
            common.multiplicity <= max_multiplicity,
            "derived multiplicity should never exceed max_multiplicity"
        );
        if num_payload_elems < max_multiplicity * recovery_threshold {
            // small payload
            found_small_payload = true;
            assert!(
                num_payload_elems <= common.multiplicity * advz.recovery_threshold,
                "derived multiplicity too small"
            );

            if num_payload_elems > 0 {
                // TODO TEMPORARY: enforce power-of-2
                // https://github.com/EspressoSystems/jellyfish/issues/668
                //
                // After this issue is fixed the following test should use
                // `common.multiplicity - 1` instead of `common.multiplicity / 2`.
                assert!(
                    num_payload_elems > common.multiplicity / 2 * advz.recovery_threshold,
                    "derived multiplicity too large: payload_byte_len {}, common.multiplicity {}",
                    payload_byte_len,
                    common.multiplicity
                );
            } else {
                assert_eq!(
                    common.multiplicity, 1,
                    "zero-length payload should have multiplicity 1, found {}",
                    common.multiplicity
                );
            }

            assert!(
                common.poly_commits.len() <= 1,
                "small payload should fit into a single polynomial"
            );
        } else {
            // large payload
            found_large_payload = true;
            assert_eq!(
                common.multiplicity, max_multiplicity,
                "derived multiplicity should equal max_multiplicity for large payload"
            );
        }

        // sanity: recover payload
        let bytes_recovered = advz.recover_payload(&shares, &common).unwrap();
        assert_eq!(bytes_recovered, payload);

        // sanity: verify shares
        for share in shares {
            advz.verify_share(&share, &common, &commit)
                .unwrap()
                .unwrap();
        }
    }

    assert!(found_large_payload, "missing test for large payload");
    assert!(found_small_payload, "missing test for small payload");
}

impl<E, H> Share<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    /// Like [`MerkleProof::elem`] except the returned reference is mutable.
    fn extract_leaf_mut(
        proof: &mut KzgEvalsMerkleTreeProof<E, H>,
    ) -> VidResult<&mut Vec<KzgEval<E>>> {
        // `eval_proof.proof` is a`Vec<MerkleNode>` with length >= 1
        // whose first item always has variant `Leaf`. See
        // `MerkleProof::verify_membership_proof`.
        let merkle_node = proof
            .proof
            .get_mut(0)
            .ok_or_else(|| VidError::Internal(anyhow::anyhow!("empty merkle proof")))?;
        let MerkleNode::Leaf { elem, .. } = merkle_node else {
            return Err(VidError::Internal(anyhow::anyhow!(
                "expect MerkleNode::Leaf variant"
            )));
        };
        Ok(elem)
    }
}

struct AdvzParams {
    recovery_threshold: u32,
    num_storage_nodes: u32,
    max_multiplicity: u32,
    payload_len: usize,
}

/// Routine initialization tasks.
///
/// Returns the following tuple:
/// 1. An initialized [`Advz`] instance.
/// 2. A `Vec<u8>` filled with random bytes.
pub(super) fn advz_init() -> (Advz<Bn254, Sha256>, Vec<u8>) {
    let advz_params = AdvzParams {
        recovery_threshold: 16,
        num_storage_nodes: 20,
        max_multiplicity: 1,
        payload_len: 4000,
    };
    advz_init_with(advz_params)
}

fn advz_init_with<E: Pairing>(advz_params: AdvzParams) -> (Advz<E, Sha256>, Vec<u8>) {
    let mut rng = jf_utils::test_rng();
    let poly_len = advz_params.recovery_threshold * advz_params.max_multiplicity;
    let srs = init_srs(poly_len as usize, &mut rng);
    assert_ne!(
        advz_params.max_multiplicity, 0,
        "multiplicity should not be zero"
    );
    let advz = if advz_params.max_multiplicity > 1 {
        Advz::with_multiplicity(
            advz_params.num_storage_nodes,
            advz_params.recovery_threshold,
            advz_params.max_multiplicity,
            srs,
        )
        .unwrap()
    } else {
        Advz::new(
            advz_params.num_storage_nodes,
            advz_params.recovery_threshold,
            srs,
        )
        .unwrap()
    };
    let bytes_random = init_random_payload(advz_params.payload_len, &mut rng);
    (advz, bytes_random)
}

/// Convenience wrapper to assert [`VidError::Argument`] return value.
pub(super) fn assert_arg_err<T>(res: VidResult<T>, msg: &str) {
    assert!(matches!(res, Err(Argument(_))), "{}", msg);
}

pub(super) fn init_random_payload<R>(len: usize, rng: &mut R) -> Vec<u8>
where
    R: RngCore + CryptoRng,
{
    let mut bytes_random = vec![0u8; len];
    rng.fill_bytes(&mut bytes_random);
    bytes_random
}

pub(super) fn init_srs<E, R>(num_coeffs: usize, rng: &mut R) -> UnivariateUniversalParams<E>
where
    E: Pairing,
    R: RngCore + CryptoRng,
{
    UnivariateKzgPCS::gen_srs_for_testing(rng, checked_fft_size(num_coeffs - 1).unwrap()).unwrap()
}
