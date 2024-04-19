// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementations of [`Precomputable`] for `Advz`.

use crate::VidError;
use crate::{
    advz::{
        polynomial_eval, AdvzInternal, Common, HasherDigest, KzgCommit, KzgEvalsMerkleTree,
        MaybeGPU, Pairing, PolynomialMultiplier, UnivariateKzgPCS,
    },
    precomputable::Precomputable,
    vid, VidDisperse, VidResult,
};
use alloc::string::ToString;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer, vec::Vec};
use jf_merkle_tree::{MerkleCommitment, MerkleTreeScheme};
use jf_pcs::{prelude::Commitment, PolynomialCommitmentScheme, UnivariatePCS};
use jf_utils::canonical;
use serde::{Deserialize, Serialize};

use super::Advz;

impl<E, H, T> Precomputable for AdvzInternal<E, H, T>
where
    E: Pairing,
    H: HasherDigest,
    AdvzInternal<E, H, T>: MaybeGPU<E>,
{
    type PrecomputeData = PrecomputeData<E>;

    fn commit_only_precompute<B>(
        &self,
        payload: B,
    ) -> VidResult<(Self::Commit, Self::PrecomputeData)>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        let polys = self.bytes_to_polys(payload);
        let poly_commits: Vec<Commitment<E>> =
            UnivariateKzgPCS::batch_commit(&self.ck, &polys).map_err(vid)?;
        Ok((
            Self::derive_commit(&poly_commits, payload.len(), self.num_storage_nodes)?,
            PrecomputeData { poly_commits },
        ))
    }

    fn disperse_precompute<B>(
        &self,
        payload: B,
        data: &Self::PrecomputeData,
    ) -> VidResult<VidDisperse<Self>>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        let payload_byte_len = payload.len().try_into().map_err(vid)?;
        let disperse_time = start_timer!(|| ark_std::format!(
            "(PRECOMPUTE): VID disperse {} payload bytes to {} nodes",
            payload_byte_len,
            self.num_storage_nodes
        ));
        let _chunk_size = self.multiplicity * self.recovery_threshold;
        let code_word_size = self.multiplicity * self.num_storage_nodes;

        // partition payload into polynomial coefficients
        // and count `elems_len` for later
        let bytes_to_polys_time = start_timer!(|| "encode payload bytes into polynomials");
        let polys = self.bytes_to_polys(payload);
        end_timer!(bytes_to_polys_time);

        // evaluate polynomials
        let all_storage_node_evals_timer = start_timer!(|| ark_std::format!(
            "compute all storage node evals for {} polynomials with {} coefficients",
            polys.len(),
            _chunk_size
        ));
        let all_storage_node_evals = self.evaluate_polys(&polys)?;
        end_timer!(all_storage_node_evals_timer);

        // vector commitment to polynomial evaluations
        // TODO why do I need to compute the height of the merkle tree?
        let all_evals_commit_timer =
            start_timer!(|| "compute merkle root of all storage node evals");
        let all_evals_commit =
            KzgEvalsMerkleTree::<E, H>::from_elems(None, &all_storage_node_evals).map_err(vid)?;
        end_timer!(all_evals_commit_timer);

        let common_timer = start_timer!(|| ark_std::format!(
            "(PRECOMPUTE): compute {} KZG commitments",
            polys.len()
        ));
        let common = Common {
            poly_commits: data.poly_commits.clone(),
            all_evals_digest: all_evals_commit.commitment().digest(),
            payload_byte_len,
            num_storage_nodes: self.num_storage_nodes,
            multiplicity: self.multiplicity,
        };
        end_timer!(common_timer);

        let commit = Self::derive_commit(
            &common.poly_commits,
            payload_byte_len,
            self.num_storage_nodes,
        )?;
        let pseudorandom_scalar = Self::pseudorandom_scalar(&common, &commit)?;

        // Compute aggregate polynomial as a pseudorandom linear combo of polynomial via
        // evaluation of the polynomial whose coefficients are polynomials and whose
        // input point is the pseudorandom scalar.
        let aggregate_poly =
            polynomial_eval(polys.iter().map(PolynomialMultiplier), pseudorandom_scalar);

        let agg_proofs_timer = start_timer!(|| ark_std::format!(
            "compute aggregate proofs for {} storage nodes",
            self.num_storage_nodes
        ));
        let aggregate_proofs = UnivariateKzgPCS::multi_open_rou_proofs(
            &self.ck,
            &aggregate_poly,
            code_word_size as usize,
            &self.multi_open_domain,
        )
        .map_err(vid)?;
        end_timer!(agg_proofs_timer);

        let assemblage_timer = start_timer!(|| "assemble shares for dispersal");
        let shares =
            self.assemble_shares(all_storage_node_evals, aggregate_proofs, all_evals_commit)?;
        end_timer!(assemblage_timer);
        end_timer!(disperse_time);

        Ok(VidDisperse {
            shares,
            common,
            commit,
        })
    }

    fn is_consistent_precompute(
        commit: &Self::Commit,
        precompute_data: &Self::PrecomputeData,
        payload_byte_len: u32,
        num_storage_nodes: u32,
    ) -> VidResult<()> {
        if *commit
            != Advz::<E, H>::derive_commit(
                &precompute_data.poly_commits,
                payload_byte_len,
                num_storage_nodes,
            )?
        {
            return Err(VidError::Argument(
                "precompute data inconsistent with commit".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(
    Debug,
    Clone,
    CanonicalSerialize,
    CanonicalDeserialize,
    Derivative,
    Deserialize,
    Serialize,
    PartialEq,
    Eq,
)]
#[derivative(Hash(bound = ""))]
/// Data that can be precomputed as used in dispersal
pub struct PrecomputeData<E>
where
    E: Pairing,
{
    #[serde(with = "canonical")]
    poly_commits: Vec<KzgCommit<E>>,
}

#[cfg(test)]
mod tests {
    use crate::{
        advz::{
            tests::{advz_init, init_random_payload, init_srs},
            Advz,
        },
        precomputable::Precomputable,
        VidScheme,
    };
    use ark_bls12_381::Bls12_381;
    use sha2::Sha256;

    #[ignore]
    #[test]
    fn commit_only_with_data_timer() {
        // run with 'print-trace' feature to see timer output
        let (recovery_threshold, num_storage_nodes) = (256, 512);
        let mut rng = jf_utils::test_rng();
        let multiplicity = 1;
        let srs = init_srs((recovery_threshold * multiplicity) as usize, &mut rng);
        let advz = Advz::<Bls12_381, Sha256>::with_multiplicity(
            num_storage_nodes,
            recovery_threshold,
            multiplicity,
            srs,
        )
        .unwrap();
        let payload_random = init_random_payload(1 << 20, &mut rng);

        let (_commit, _data) = advz.commit_only_precompute(payload_random).unwrap();
    }

    #[ignore]
    #[test]
    fn disperse_with_data_timer() {
        // run with 'print-trace' feature to see timer output
        let (recovery_threshold, num_storage_nodes) = (64, 128);
        let multiplicity = 4;
        let mut rng = jf_utils::test_rng();
        let srs = init_srs((recovery_threshold * multiplicity) as usize, &mut rng);
        let advz = Advz::<Bls12_381, Sha256>::with_multiplicity(
            num_storage_nodes,
            recovery_threshold,
            multiplicity,
            srs,
        )
        .unwrap();
        let payload_random = init_random_payload(1 << 20, &mut rng);
        let (_commit, data) = advz.commit_only_precompute(&payload_random).unwrap();
        let _ = advz.disperse_precompute(payload_random, &data);
    }

    #[test]
    fn commit_disperse_recover_with_precomputed_data() {
        let (advz, bytes_random, _) = advz_init();
        let (commit, data) = advz.commit_only_precompute(&bytes_random).unwrap();
        let disperse = advz.disperse_precompute(&bytes_random, &data).unwrap();
        let (shares, common) = (disperse.shares, disperse.common);
        for share in &shares {
            let v = advz.verify_share(share, &common, &commit);
            assert!(v.is_ok(), "share verification should succeed");
        }

        let bytes_recovered = advz
            .recover_payload(&shares, &common)
            .expect("recover_payload should succeed");
        assert_eq!(bytes_recovered, bytes_random);
    }

    #[test]
    fn commit_and_verify_consistent_precomputed_data() {
        let (advz, bytes_random, num_storage_nodes) = advz_init();
        let (commit, data) = advz.commit_only_precompute(&bytes_random).unwrap();
        assert!(Advz::is_consistent_precompute(
            &commit,
            &data,
            bytes_random.len() as u32,
            num_storage_nodes
        )
        .is_ok())
    }
}
