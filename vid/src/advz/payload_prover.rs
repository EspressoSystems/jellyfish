// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementations of [`PayloadProver`] for `Advz`.
//!
//! Two implementations:
//! 1. `PROOF = `[`SmallRangeProof`]: Useful for small sub-slices of `payload`
//!    such as an individual transaction within a block. Not snark-friendly
//!    because it requires a pairing. Consists of metadata required to verify a
//!    KZG batch proof.
//! 2. `PROOF = `[`LargeRangeProof`]: Useful for large sub-slices of `payload`
//!    such as a complete namespace. Snark-friendly because it does not require
//!    a pairing. Consists of metadata required to rebuild a KZG commitment.

use super::{
    bytes_to_field::{bytes_to_field, elem_byte_capacity},
    AdvzInternal, KzgEval, KzgProof, MaybeGPU, PolynomialCommitmentScheme, Vec, VidResult,
};
use crate::{
    payload_prover::{PayloadProver, Statement},
    vid, VidError, VidScheme,
};
use anyhow::anyhow;
use ark_ec::pairing::Pairing;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{format, ops::Range};
use itertools::Itertools;
use jf_merkle_tree::hasher::HasherDigest;
use jf_pcs::prelude::UnivariateKzgPCS;
use jf_utils::canonical;
use serde::{Deserialize, Serialize};

/// A proof intended for use on small payload subslices.
///
/// KZG batch proofs and accompanying metadata.
///
/// TODO use batch proof instead of `Vec<P>` <https://github.com/EspressoSystems/jellyfish/issues/387>
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "P: CanonicalSerialize + CanonicalDeserialize")]
pub struct SmallRangeProof<P> {
    #[serde(with = "canonical")]
    proofs: Vec<P>,
    prefix_bytes: Vec<u8>,
    suffix_bytes: Vec<u8>,
}

/// A proof intended for use on large payload subslices.
///
/// Metadata needed to recover a KZG commitment.
#[derive(
    Clone, Debug, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct LargeRangeProof<F: CanonicalSerialize + CanonicalDeserialize> {
    #[serde(with = "canonical")]
    prefix_elems: Vec<F>,
    #[serde(with = "canonical")]
    suffix_elems: Vec<F>,
    prefix_bytes: Vec<u8>,
    suffix_bytes: Vec<u8>,
}

impl<E, H, T> PayloadProver<SmallRangeProof<KzgProof<E>>> for AdvzInternal<E, H, T>
where
    E: Pairing,
    H: HasherDigest,
    T: Sync,
    AdvzInternal<E, H, T>: MaybeGPU<E>,
{
    fn payload_proof<B>(
        &self,
        payload: B,
        range: Range<usize>,
    ) -> VidResult<SmallRangeProof<KzgProof<E>>>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        check_range_nonempty_and_in_bounds(payload.len(), &range)?;

        // index conversion
        let multiplicity = self.min_multiplicity(payload.len())?;
        let range_elem = self.range_byte_to_elem(&range);
        let range_poly = self.range_elem_to_poly(&range_elem, multiplicity);
        let range_elem_byte = self.range_elem_to_byte_clamped(&range_elem, payload.len());
        let range_poly_byte =
            self.range_poly_to_byte_clamped(&range_poly, payload.len(), multiplicity);
        let offset_elem =
            self.offset_poly_to_elem(range_poly.start, range_elem.start, multiplicity);
        let final_points_range_end =
            self.final_poly_points_range_end(range_elem.len(), offset_elem, multiplicity);

        // prepare list of input points
        //
        // perf: if payload is small enough to fit into a single polynomial then
        // we don't need all the points in this domain.
        let points: Vec<_> = Self::eval_domain(
            usize::try_from(self.recovery_threshold * multiplicity).map_err(vid)?,
        )?
        .elements()
        .collect();

        let elems_iter = bytes_to_field::<_, KzgEval<E>>(&payload[range_poly_byte]);
        let mut proofs = Vec::with_capacity(range_poly.len() * points.len());
        for (i, evals_iter) in elems_iter
            .chunks((self.recovery_threshold * multiplicity) as usize)
            .into_iter()
            .enumerate()
        {
            let poly = Self::interpolate_polynomial(
                evals_iter,
                (self.recovery_threshold * multiplicity) as usize,
            )?;
            let points_range = Range {
                // first polynomial? skip to the start of the proof range
                start: if i == 0 { offset_elem } else { 0 },
                // final polynomial? stop at the end of the proof range
                end: if i == range_poly.len() - 1 {
                    final_points_range_end
                } else {
                    points.len()
                },
            };
            proofs.extend(
                UnivariateKzgPCS::multi_open(&self.ck, &poly, &points[points_range])
                    .map_err(vid)?
                    .0,
            );
        }

        Ok(SmallRangeProof {
            proofs,
            prefix_bytes: payload[range_elem_byte.start..range.start].to_vec(),
            suffix_bytes: payload[range.end..range_elem_byte.end].to_vec(),
        })
    }

    fn payload_verify(
        &self,
        stmt: Statement<Self>,
        proof: &SmallRangeProof<KzgProof<E>>,
    ) -> VidResult<Result<(), ()>> {
        Self::check_stmt_consistency(&stmt)?;

        // prepare list of data elems
        let data_elems: Vec<_> = bytes_to_field::<_, KzgEval<E>>(
            proof
                .prefix_bytes
                .iter()
                .chain(stmt.payload_subslice)
                .chain(proof.suffix_bytes.iter()),
        )
        .collect();

        if data_elems.len() != proof.proofs.len() {
            return Err(VidError::Argument(format!(
                "data len {} differs from proof len {}",
                data_elems.len(),
                proof.proofs.len()
            )));
        }

        // index conversion
        let range_elem = self.range_byte_to_elem(&stmt.range);
        let range_poly = self.range_elem_to_poly(&range_elem, stmt.common.multiplicity);
        let offset_elem =
            self.offset_poly_to_elem(range_poly.start, range_elem.start, stmt.common.multiplicity);
        let final_points_range_end = self.final_poly_points_range_end(
            range_elem.len(),
            offset_elem,
            stmt.common.multiplicity,
        );

        // prepare list of input points
        //
        // perf: if payload is small enough to fit into a single polynomial then
        // we don't need all the points in this domain.
        let points: Vec<_> = Self::eval_domain(
            usize::try_from(self.recovery_threshold * stmt.common.multiplicity).map_err(vid)?,
        )?
        .elements()
        .collect();

        // verify proof
        let mut cur_proof_index = 0;
        for (i, poly_commit) in stmt.common.poly_commits[range_poly.clone()]
            .iter()
            .enumerate()
        {
            let points_range = Range {
                // first polynomial? skip to the start of the proof range
                start: if i == 0 { offset_elem } else { 0 },
                // final polynomial? stop at the end of the proof range
                end: if i == range_poly.len() - 1 {
                    final_points_range_end
                } else {
                    points.len()
                },
            };
            // TODO naive verify for multi_open https://github.com/EspressoSystems/jellyfish/issues/387
            for point in points[points_range].iter() {
                let data_elem = data_elems
                    .get(cur_proof_index)
                    .ok_or_else(|| VidError::Internal(anyhow!("ran out of data elems")))?;
                let cur_proof = proof
                    .proofs
                    .get(cur_proof_index)
                    .ok_or_else(|| VidError::Internal(anyhow!("ran out of proofs")))?;
                if !UnivariateKzgPCS::verify(&self.vk, poly_commit, point, data_elem, cur_proof)
                    .map_err(vid)?
                {
                    return Ok(Err(()));
                }
                cur_proof_index += 1;
            }
        }
        assert_eq!(cur_proof_index, proof.proofs.len()); // sanity
        Ok(Ok(()))
    }
}

impl<E, H, T> PayloadProver<LargeRangeProof<KzgEval<E>>> for AdvzInternal<E, H, T>
where
    E: Pairing,
    H: HasherDigest,
    T: Sync,
    AdvzInternal<E, H, T>: MaybeGPU<E>,
{
    fn payload_proof<B>(
        &self,
        payload: B,
        range: Range<usize>,
    ) -> VidResult<LargeRangeProof<KzgEval<E>>>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        check_range_nonempty_and_in_bounds(payload.len(), &range)?;

        // index conversion
        let multiplicity = self.min_multiplicity(payload.len())?;
        let range_elem = self.range_byte_to_elem(&range);
        let range_poly = self.range_elem_to_poly(&range_elem, multiplicity);
        let range_elem_byte = self.range_elem_to_byte_clamped(&range_elem, payload.len());
        let range_poly_byte =
            self.range_poly_to_byte_clamped(&range_poly, payload.len(), multiplicity);
        let offset_elem =
            self.offset_poly_to_elem(range_poly.start, range_elem.start, multiplicity);

        // compute the prefix and suffix elems
        let mut elems_iter = bytes_to_field::<_, KzgEval<E>>(payload[range_poly_byte].iter());
        let prefix_elems: Vec<_> = elems_iter.by_ref().take(offset_elem).collect();
        let suffix_elems: Vec<_> = elems_iter.skip(range_elem.len()).collect();

        Ok(LargeRangeProof {
            prefix_elems,
            suffix_elems,
            prefix_bytes: payload[range_elem_byte.start..range.start].to_vec(),
            suffix_bytes: payload[range.end..range_elem_byte.end].to_vec(),
        })
    }

    fn payload_verify(
        &self,
        stmt: Statement<Self>,
        proof: &LargeRangeProof<KzgEval<E>>,
    ) -> VidResult<Result<(), ()>> {
        Self::check_stmt_consistency(&stmt)?;

        // index conversion
        let range_poly = self.range_byte_to_poly(&stmt.range, stmt.common.multiplicity);

        // rebuild the needed payload elements from statement and proof
        let elems_iter = proof
            .prefix_elems
            .iter()
            .cloned()
            .chain(bytes_to_field::<_, KzgEval<E>>(
                proof
                    .prefix_bytes
                    .iter()
                    .chain(stmt.payload_subslice)
                    .chain(proof.suffix_bytes.iter()),
            ))
            .chain(proof.suffix_elems.iter().cloned());
        // rebuild the poly commits, check against `common`
        for (commit_index, evals_iter) in range_poly.into_iter().zip(
            elems_iter
                .chunks((self.recovery_threshold * stmt.common.multiplicity) as usize)
                .into_iter(),
        ) {
            let poly = Self::interpolate_polynomial(
                evals_iter,
                (stmt.common.multiplicity * self.recovery_threshold) as usize,
            )?;
            let poly_commit = UnivariateKzgPCS::commit(&self.ck, &poly).map_err(vid)?;
            if poly_commit != stmt.common.poly_commits[commit_index] {
                return Ok(Err(()));
            }
        }
        Ok(Ok(()))
    }
}

impl<E, H, T> AdvzInternal<E, H, T>
where
    E: Pairing,
    H: HasherDigest,
    T: Sync,
    AdvzInternal<E, H, T>: MaybeGPU<E>,
{
    // lots of index manipulation
    fn range_byte_to_elem(&self, range: &Range<usize>) -> Range<usize> {
        range_coarsen(range, elem_byte_capacity::<KzgEval<E>>())
    }
    fn range_elem_to_byte_clamped(&self, range: &Range<usize>, len: usize) -> Range<usize> {
        let result = range_refine(range, elem_byte_capacity::<KzgEval<E>>());
        Range {
            end: ark_std::cmp::min(result.end, len),
            ..result
        }
    }
    fn range_elem_to_poly(&self, range: &Range<usize>, multiplicity: u32) -> Range<usize> {
        range_coarsen(range, (self.recovery_threshold * multiplicity) as usize)
    }
    fn range_byte_to_poly(&self, range: &Range<usize>, multiplicity: u32) -> Range<usize> {
        range_coarsen(
            range,
            (self.recovery_threshold * multiplicity) as usize * elem_byte_capacity::<KzgEval<E>>(),
        )
    }
    fn range_poly_to_byte_clamped(
        &self,
        range: &Range<usize>,
        len: usize,
        multiplicity: u32,
    ) -> Range<usize> {
        let result = range_refine(
            range,
            (self.recovery_threshold * multiplicity) as usize * elem_byte_capacity::<KzgEval<E>>(),
        );
        Range {
            end: ark_std::cmp::min(result.end, len),
            ..result
        }
    }
    fn offset_poly_to_elem(
        &self,
        range_poly_start: usize,
        range_elem_start: usize,
        multiplicity: u32,
    ) -> usize {
        let start_poly_byte = index_refine(
            range_poly_start,
            (self.recovery_threshold * multiplicity) as usize * elem_byte_capacity::<KzgEval<E>>(),
        );
        range_elem_start - index_coarsen(start_poly_byte, elem_byte_capacity::<KzgEval<E>>())
    }
    fn final_poly_points_range_end(
        &self,
        range_elem_len: usize,
        offset_elem: usize,
        multiplicity: u32,
    ) -> usize {
        (range_elem_len + offset_elem - 1) % (self.recovery_threshold * multiplicity) as usize + 1
    }

    fn check_stmt_consistency(stmt: &Statement<Self>) -> VidResult<()> {
        check_range_nonempty_and_in_bounds(
            stmt.common.payload_byte_len.try_into().map_err(vid)?,
            &stmt.range,
        )?;
        if stmt.payload_subslice.len() != stmt.range.len() {
            return Err(VidError::Argument(format!(
                "payload_subslice length {} inconsistent with range length {}",
                stmt.payload_subslice.len(),
                stmt.range.len()
            )));
        }
        Self::is_consistent(stmt.commit, stmt.common)
    }
}

fn range_coarsen(range: &Range<usize>, denominator: usize) -> Range<usize> {
    assert!(!range.is_empty(), "{:?}", range);
    Range {
        start: index_coarsen(range.start, denominator),
        end: index_coarsen(range.end - 1, denominator) + 1,
    }
}

fn range_refine(range: &Range<usize>, multiplier: usize) -> Range<usize> {
    assert!(!range.is_empty(), "{:?}", range);
    Range {
        start: index_refine(range.start, multiplier),
        end: index_refine(range.end, multiplier),
    }
}

fn index_coarsen(index: usize, denominator: usize) -> usize {
    index / denominator
}

fn index_refine(index: usize, multiplier: usize) -> usize {
    index * multiplier
}

fn check_range_nonempty_and_in_bounds(len: usize, range: &Range<usize>) -> VidResult<()> {
    if range.is_empty() {
        return Err(VidError::Argument(format!(
            "empty range ({}..{})",
            range.start, range.end
        )));
    }
    // no need to check range.start because we already checked range.is_empty()
    if range.end > len {
        return Err(VidError::Argument(format!(
            "range ({}..{}) out of bounds for length {}",
            range.start, range.end, len
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        advz::{
            bytes_to_field::elem_byte_capacity,
            payload_prover::{LargeRangeProof, SmallRangeProof, Statement},
            test::*,
            *,
        },
        payload_prover::PayloadProver,
    };
    use ark_bn254::Bn254;
    use ark_std::{ops::Range, print, println, rand::Rng};
    use sha2::Sha256;

    fn correctness_generic<E, H>()
    where
        E: Pairing,
        H: HasherDigest,
    {
        // play with these items
        let (recovery_threshold, num_storage_nodes, max_multiplicity) = (4, 6, 2);
        let num_polys = 3;
        let num_random_cases = 20;

        // more items as a function of the above
        let poly_elems_len = recovery_threshold as usize * max_multiplicity as usize;
        let payload_elems_len = num_polys * poly_elems_len;
        let poly_bytes_len = poly_elems_len * elem_byte_capacity::<E::ScalarField>();
        let payload_bytes_base_len = payload_elems_len * elem_byte_capacity::<E::ScalarField>();
        let mut rng = jf_utils::test_rng();
        let srs = init_srs(payload_elems_len, &mut rng);
        let mut advz = Advz::<E, H>::with_multiplicity(
            num_storage_nodes,
            recovery_threshold,
            max_multiplicity,
            srs,
        )
        .unwrap();

        // TEST: different payload byte lengths
        let payload_byte_len_noise_cases = vec![0, poly_bytes_len / 2, poly_bytes_len - 1];
        let payload_len_cases = payload_byte_len_noise_cases
            .into_iter()
            .map(|l| payload_bytes_base_len - l);

        // TEST: prove data ranges for this payload
        // it takes too long to test all combos of (polynomial, start, len)
        // so do some edge cases and random cases
        let edge_cases = {
            let mut edge_cases = make_edge_cases(0, poly_bytes_len); // inside the first polynomial
            edge_cases.extend(make_edge_cases(
                payload_bytes_base_len - poly_bytes_len,
                payload_bytes_base_len,
            )); // inside the final polynomial
            edge_cases.extend(make_edge_cases(0, payload_bytes_base_len)); // spanning the entire payload
            edge_cases
        };
        let random_cases = {
            let mut random_cases = Vec::with_capacity(num_random_cases);
            for _ in 0..num_random_cases {
                let start = rng.gen_range(0..payload_bytes_base_len - 1);
                let end = rng.gen_range(start + 1..payload_bytes_base_len);
                random_cases.push(Range { start, end });
            }
            random_cases
        };
        let all_cases = [(edge_cases, "edge"), (random_cases, "rand")];

        // at least one test case should have nontrivial multiplicity
        let mut nontrivial_multiplicity = false;

        for payload_len_case in payload_len_cases {
            let payload = init_random_payload(payload_len_case, &mut rng);
            let d = advz.disperse(&payload).unwrap();
            if d.common.multiplicity > 1 {
                nontrivial_multiplicity = true;
            }
            println!("payload byte len case: {}", payload.len());

            for cases in all_cases.iter() {
                for range in cases.0.iter() {
                    print!("{} case: {:?}", cases.1, range);

                    // ensure range fits inside payload
                    let range = if range.start >= payload.len() {
                        println!(" outside payload len {}, skipping", payload.len());
                        continue;
                    } else if range.end > payload.len() {
                        println!(" clamped to payload len {}", payload.len());
                        Range {
                            end: payload.len(),
                            ..*range
                        }
                    } else {
                        println!();
                        range.clone()
                    };

                    let stmt = Statement {
                        payload_subslice: &payload[range.clone()],
                        range: range.clone(),
                        commit: &d.commit,
                        common: &d.common,
                    };

                    let small_range_proof: SmallRangeProof<_> =
                        advz.payload_proof(&payload, range.clone()).unwrap();
                    advz.payload_verify(stmt.clone(), &small_range_proof)
                        .unwrap()
                        .unwrap();

                    let large_range_proof: LargeRangeProof<_> =
                        advz.payload_proof(&payload, range.clone()).unwrap();
                    advz.payload_verify(stmt.clone(), &large_range_proof)
                        .unwrap()
                        .unwrap();

                    // test wrong proofs
                    let stmt_corrupted = Statement {
                        // corrupt the payload subslice by adding 1 to each byte
                        payload_subslice: &stmt
                            .payload_subslice
                            .iter()
                            .cloned()
                            .map(|b| b.wrapping_add(1))
                            .collect::<Vec<_>>(),
                        ..stmt
                    };
                    advz.payload_verify(stmt_corrupted.clone(), &small_range_proof)
                        .unwrap()
                        .unwrap_err();
                    advz.payload_verify(stmt_corrupted, &large_range_proof)
                        .unwrap()
                        .unwrap_err();

                    // TODO more tests for bad proofs, eg:
                    // - valid proof, different range
                    // - corrupt proof
                    // - etc
                }
            }
        }

        assert!(
            nontrivial_multiplicity,
            "at least one payload size should use multiplicity > 1"
        );

        fn make_edge_cases(min: usize, max: usize) -> Vec<Range<usize>> {
            vec![
                Range {
                    start: min,
                    end: min + 1,
                },
                Range {
                    start: min,
                    end: min + 2,
                },
                Range {
                    start: min,
                    end: max - 1,
                },
                Range {
                    start: min,
                    end: max,
                },
                Range {
                    start: min + 1,
                    end: min + 2,
                },
                Range {
                    start: min + 1,
                    end: min + 3,
                },
                Range {
                    start: min + 1,
                    end: max - 1,
                },
                Range {
                    start: min + 1,
                    end: max,
                },
                Range {
                    start: max - 2,
                    end: max - 1,
                },
                Range {
                    start: max - 2,
                    end: max,
                },
                Range {
                    start: max - 1,
                    end: max,
                },
            ]
        }
    }

    #[test]
    fn correctness() {
        correctness_generic::<Bn254, Sha256>();
    }
}
