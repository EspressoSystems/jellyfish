// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementations of [`Precomputable`] for `Advz`.

use core::mem;

use crate::{
    merkle_tree::{MerkleCommitment, MerkleTreeScheme},
    pcs::{prelude::Commitment, PolynomialCommitmentScheme, UnivariatePCS},
    vid::{
        advz::{
            bytes_to_field, polynomial_eval, Advz, Common, HasherDigest, KzgEval,
            KzgEvalsMerkleTree, KzgEvalsMerkleTreeIndex, Pairing, PolynomialMultiplier, Share,
            UnivariateKzgPCS,
        },
        precomputable::Precomputable,
        vid, VidDisperse, VidResult,
    },
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer, vec, vec::Vec};
use itertools::Itertools;
use jf_utils::canonical;
use serde::{Deserialize, Serialize};

use super::KzgCommit;

impl<E, H> Precomputable for Advz<E, H>
where
    E: Pairing,
    H: HasherDigest,
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
        let chunk_size = self.multiplicity * self.payload_chunk_size;

        let polys: Vec<_> = bytes_to_field::<_, KzgEval<E>>(payload)
            .chunks(chunk_size)
            .into_iter()
            .map(|evals_iter| self.polynomial(evals_iter))
            .collect();
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
        let chunk_size = self.multiplicity * self.payload_chunk_size;
        let code_word_size = self.multiplicity * self.num_storage_nodes;

        // partition payload into polynomial coefficients
        // and count `elems_len` for later
        let bytes_to_elems = start_timer!(|| "encode payload into field elements");
        let elems_iter = bytes_to_field::<_, KzgEval<E>>(payload);
        end_timer!(bytes_to_elems);
        let inverse_fft = start_timer!(|| "field elements into polynomials (inverse FFT)");
        let polys: Vec<_> = elems_iter
            .chunks(chunk_size)
            .into_iter()
            .map(|evals_iter| self.polynomial(evals_iter))
            .collect();
        end_timer!(inverse_fft);

        // evaluate polynomials
        let all_storage_node_evals_timer = start_timer!(|| ark_std::format!(
            "compute all storage node evals for {} polynomials with {} coefficients",
            polys.len(),
            chunk_size
        ));
        let all_storage_node_evals = {
            let mut all_storage_node_evals = vec![Vec::with_capacity(polys.len()); code_word_size];

            for poly in polys.iter() {
                let poly_evals = UnivariateKzgPCS::<E>::multi_open_rou_evals(
                    poly,
                    code_word_size,
                    &self.multi_open_domain,
                )
                .map_err(vid)?;

                for (storage_node_evals, poly_eval) in
                    all_storage_node_evals.iter_mut().zip(poly_evals)
                {
                    storage_node_evals.push(poly_eval);
                }
            }

            // sanity checks
            assert_eq!(all_storage_node_evals.len(), code_word_size);
            for storage_node_evals in all_storage_node_evals.iter() {
                assert_eq!(storage_node_evals.len(), polys.len());
            }

            all_storage_node_evals
        };
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
            poly_commits: data.poly_commits.clone(), /* UnivariateKzgPCS::batch_commit(&self.ck,
                                                      * &polys).map_err(vid)?, */
            all_evals_digest: all_evals_commit.commitment().digest(),
            payload_byte_len,
            num_storage_nodes: self.num_storage_nodes.try_into().map_err(vid)?,
            multiplicity: self.multiplicity.try_into().map_err(vid)?,
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
            code_word_size,
            &self.multi_open_domain,
        )
        .map_err(vid)?;
        end_timer!(agg_proofs_timer);

        let assemblage_timer = start_timer!(|| "assemble shares for dispersal");

        let mut shares = Vec::with_capacity(code_word_size);
        let mut evals = Vec::new();
        let mut proofs = Vec::new();
        for index in 0..code_word_size {
            evals.extend(all_storage_node_evals[index].iter());
            proofs.push(aggregate_proofs[index].clone());
            if (index + 1) % self.multiplicity == 0 {
                shares.push(Share {
                    index,
                    evals: mem::take(&mut evals),
                    aggregate_proofs: mem::take(&mut proofs),
                    evals_proof: all_evals_commit // TODO: check MT lookup for each index
                        .lookup(KzgEvalsMerkleTreeIndex::<E, H>::from(index as u64))
                        .expect_ok()
                        .map_err(vid)?
                        .1,
                });
            }
        }

        end_timer!(assemblage_timer);

        end_timer!(disperse_time);
        Ok(VidDisperse {
            shares,
            common,
            commit,
        })
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

    use crate::vid::precomputable::Precomputable;
    use ark_bls12_381::Bls12_381;

    use sha2::Sha256;

    use crate::vid::{
        advz::{
            tests::{avdz_init, init_random_payload, init_srs},
            Advz,
        },
        VidScheme,
    };

    #[ignore]
    #[test]
    fn commit_only_with_data_timer() {
        // run with 'print-trace' feature to see timer output
        let (payload_chunk_size, num_storage_nodes) = (256, 512);
        let mut rng = jf_utils::test_rng();
        let multiplicity = 1;
        let srs = init_srs(payload_chunk_size * multiplicity, &mut rng);
        let advz = Advz::<Bls12_381, Sha256>::new(
            payload_chunk_size,
            num_storage_nodes,
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
        let (payload_chunk_size, num_storage_nodes) = (64, 128);
        let multiplicity = 4;
        let mut rng = jf_utils::test_rng();
        let srs = init_srs(payload_chunk_size * multiplicity, &mut rng);
        let advz = Advz::<Bls12_381, Sha256>::new(
            payload_chunk_size,
            num_storage_nodes,
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
        let (advz, bytes_random) = avdz_init();
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
}
