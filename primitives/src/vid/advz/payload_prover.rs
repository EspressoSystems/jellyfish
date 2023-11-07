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

use ark_poly::EvaluationDomain;

use super::{
    bytes_to_field, bytes_to_field::elem_byte_capacity, AffineRepr, Debug, DenseUVPolynomial,
    Digest, DynDigest, GenericAdvz, MerkleTreeScheme, PolynomialCommitmentScheme, PrimeField,
    UnivariatePCS, Vec, VidResult, Write,
};
use crate::{
    alloc::string::ToString,
    vid::{
        payload_prover::{PayloadProver, Statement},
        vid, VidError, VidScheme,
    },
};
use ark_std::{format, ops::Range};

/// A proof intended for use on small payload subslices.
///
/// KZG batch proofs and accompanying metadata.
///
/// TODO use batch proof instead of `Vec<P>` <https://github.com/EspressoSystems/jellyfish/issues/387>
pub struct SmallRangeProof<P> {
    proofs: Vec<P>,
    prefix_bytes: Vec<u8>,
    suffix_bytes: Vec<u8>,
    chunk_range: Range<usize>,
}

/// A proof intended for use on large payload subslices.
///
/// Metadata needed to recover a KZG commitment.
pub struct LargeRangeProof<F> {
    prefix_elems: Vec<F>,
    suffix_elems: Vec<F>,
    prefix_bytes: Vec<u8>,
    suffix_bytes: Vec<u8>,
    chunk_range: Range<usize>,
}

impl<P, T, H, V> PayloadProver<SmallRangeProof<P::Proof>> for GenericAdvz<P, T, H, V>
where
    // TODO ugly trait bounds https://github.com/EspressoSystems/jellyfish/issues/253
    P: UnivariatePCS<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Evaluation: PrimeField,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
    H: Digest + DynDigest + Default + Clone + Write,
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug,
    V::Index: From<u64>,
{
    fn payload_proof<B>(
        &self,
        payload: B,
        range: Range<usize>,
    ) -> VidResult<SmallRangeProof<P::Proof>>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        check_range_nonempty_and_inside_payload(payload, &range)?;

        // index conversion
        let range_elem = self.range_byte_to_elem(&range);
        let range_poly = self.range_elem_to_poly(&range_elem);
        let start_namespace_byte = self.index_poly_to_byte(range_poly.start);
        let offset_elem = range_elem.start - self.index_byte_to_elem(start_namespace_byte);
        let range_elem_byte = self.range_elem_to_byte(&range_elem);

        check_range_poly(&range_poly)?;

        // grab the polynomial that contains `range`
        // TODO allow precomputation: https://github.com/EspressoSystems/jellyfish/issues/397
        let polynomial = self.polynomial(
            bytes_to_field::<_, P::Evaluation>(payload[start_namespace_byte..].iter())
                .take(self.payload_chunk_size),
        );

        // prepare list of input points
        // perf: can't avoid use of `skip`
        let points: Vec<_> = {
            self.eval_domain
                .elements()
                .skip(offset_elem)
                .take(range_elem.len())
                .collect()
        };

        let (proofs, _evals) = P::multi_open(&self.ck, &polynomial, &points).map_err(vid)?;

        Ok(SmallRangeProof {
            proofs,
            prefix_bytes: payload[range_elem_byte.start..range.start].to_vec(),
            suffix_bytes: payload[range.end..range_elem_byte.end].to_vec(),
            chunk_range: range,
        })
    }

    fn payload_verify(
        &self,
        stmt: Statement<Self>,
        proof: &SmallRangeProof<P::Proof>,
    ) -> VidResult<Result<(), ()>> {
        Self::check_stmt_proof_consistency(&stmt, &proof.chunk_range)?;

        // index conversion
        let range_elem = self.range_byte_to_elem(&proof.chunk_range);
        let range_poly = self.range_elem_to_poly(&range_elem);
        let start_namespace_byte = self.index_poly_to_byte(range_poly.start);
        let offset_elem = range_elem.start - self.index_byte_to_elem(start_namespace_byte);

        check_range_poly(&range_poly)?;
        Self::check_common_commit_consistency(stmt.common, stmt.commit)?;

        // prepare list of data elems
        let data_elems: Vec<_> = bytes_to_field::<_, P::Evaluation>(
            proof
                .prefix_bytes
                .iter()
                .chain(stmt.payload_subslice)
                .chain(proof.suffix_bytes.iter()),
        )
        .collect();

        // prepare list of input points
        // perf: can't avoid use of `skip`
        let points: Vec<_> = {
            self.eval_domain
                .elements()
                .skip(offset_elem)
                .take(range_elem.len())
                .collect()
        };

        // verify proof
        // TODO naive verify for multi_open https://github.com/EspressoSystems/jellyfish/issues/387
        if data_elems.len() != proof.proofs.len() {
            return Err(VidError::Argument(format!(
                "data len {} differs from proof len {}",
                data_elems.len(),
                proof.proofs.len()
            )));
        }
        assert_eq!(data_elems.len(), points.len()); // sanity
        let poly_commit = &stmt.common.poly_commits[range_poly.start];
        for (point, (elem, pf)) in points
            .iter()
            .zip(data_elems.iter().zip(proof.proofs.iter()))
        {
            if !P::verify(&self.vk, poly_commit, point, elem, pf).map_err(vid)? {
                return Ok(Err(()));
            }
        }
        Ok(Ok(()))
    }
}

impl<P, T, H, V> PayloadProver<LargeRangeProof<P::Evaluation>> for GenericAdvz<P, T, H, V>
where
    // TODO ugly trait bounds https://github.com/EspressoSystems/jellyfish/issues/253
    P: UnivariatePCS<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Evaluation: PrimeField,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
    H: Digest + DynDigest + Default + Clone + Write,
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug,
    V::Index: From<u64>,
{
    fn payload_proof<B>(
        &self,
        payload: B,
        range: Range<usize>,
    ) -> VidResult<LargeRangeProof<P::Evaluation>>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        check_range_nonempty_and_inside_payload(payload, &range)?;

        // index conversion
        let range_elem = self.range_byte_to_elem(&range);
        let range_poly = self.range_elem_to_poly(&range_elem);
        let start_namespace_byte = self.index_poly_to_byte(range_poly.start);
        let offset_elem = range_elem.start - self.index_byte_to_elem(start_namespace_byte);
        let range_elem_byte = self.range_elem_to_byte(&range_elem);

        check_range_poly(&range_poly)?;

        // compute the prefix and suffix elems
        let mut elems_iter =
            bytes_to_field::<_, P::Evaluation>(payload[start_namespace_byte..].iter())
                .take(self.payload_chunk_size);
        let prefix: Vec<_> = elems_iter.by_ref().take(offset_elem).collect();
        let suffix: Vec<_> = elems_iter.skip(range_elem.len()).collect();

        Ok(LargeRangeProof {
            prefix_elems: prefix,
            suffix_elems: suffix,
            prefix_bytes: payload[range_elem_byte.start..range.start].to_vec(),
            suffix_bytes: payload[range.end..range_elem_byte.end].to_vec(),
            chunk_range: range,
        })
    }

    fn payload_verify(
        &self,
        stmt: Statement<Self>,
        proof: &LargeRangeProof<P::Evaluation>,
    ) -> VidResult<Result<(), ()>> {
        Self::check_stmt_proof_consistency(&stmt, &proof.chunk_range)?;

        // index conversion
        let range_poly = self.range_byte_to_poly(&proof.chunk_range);

        check_range_poly(&range_poly)?;
        Self::check_common_commit_consistency(stmt.common, stmt.commit)?;

        // rebuild the poly commit, check against `common`
        let poly_commit = {
            let poly = self.polynomial(
                proof
                    .prefix_elems
                    .iter()
                    .cloned()
                    .chain(bytes_to_field::<_, P::Evaluation>(
                        proof
                            .prefix_bytes
                            .iter()
                            .chain(stmt.payload_subslice)
                            .chain(proof.suffix_bytes.iter()),
                    ))
                    .chain(proof.suffix_elems.iter().cloned()),
            );
            P::commit(&self.ck, &poly).map_err(vid)?
        };
        if poly_commit != stmt.common.poly_commits[range_poly.start] {
            return Ok(Err(()));
        }

        Ok(Ok(()))
    }
}

impl<P, T, H, V> GenericAdvz<P, T, H, V>
where
    // TODO ugly trait bounds https://github.com/EspressoSystems/jellyfish/issues/253
    P: UnivariatePCS<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Evaluation: PrimeField,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
    H: Digest + DynDigest + Default + Clone + Write,
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug,
    V::Index: From<u64>,
{
    // lots of index manipulation
    fn index_byte_to_elem(&self, index: usize) -> usize {
        index_coarsen(index, elem_byte_capacity::<P::Evaluation>())
    }
    fn index_poly_to_byte(&self, index: usize) -> usize {
        index_refine(
            index,
            self.payload_chunk_size * elem_byte_capacity::<P::Evaluation>(),
        )
    }
    fn range_byte_to_elem(&self, range: &Range<usize>) -> Range<usize> {
        range_coarsen(range, elem_byte_capacity::<P::Evaluation>())
    }
    fn range_elem_to_byte(&self, range: &Range<usize>) -> Range<usize> {
        range_refine(range, elem_byte_capacity::<P::Evaluation>())
    }
    fn range_elem_to_poly(&self, range: &Range<usize>) -> Range<usize> {
        range_coarsen(range, self.payload_chunk_size)
    }
    fn range_byte_to_poly(&self, range: &Range<usize>) -> Range<usize> {
        range_coarsen(
            range,
            self.payload_chunk_size * elem_byte_capacity::<P::Evaluation>(),
        )
    }

    fn check_common_commit_consistency(
        common: &<Self as VidScheme>::Common,
        commit: &<Self as VidScheme>::Commit,
    ) -> VidResult<()> {
        if *commit != Self::poly_commits_hash(common.poly_commits.iter())? {
            return Err(VidError::Argument(
                "common inconsistent with commit".to_string(),
            ));
        }
        Ok(())
    }

    fn check_stmt_proof_consistency(
        stmt: &Statement<Self>,
        proof_range: &Range<usize>,
    ) -> VidResult<()> {
        if stmt.range.is_empty() {
            return Err(VidError::Argument(format!(
                "empty range ({},{})",
                stmt.range.start, stmt.range.end
            )));
        }
        if stmt.payload_subslice.len() != stmt.range.len() {
            return Err(VidError::Argument(format!(
                "payload_subslice length {} inconsistent with range length {}",
                stmt.payload_subslice.len(),
                stmt.range.len()
            )));
        }
        if stmt.range != *proof_range {
            return Err(VidError::Argument(format!(
                "statement range ({},{}) differs from proof range ({},{})",
                stmt.range.start, stmt.range.end, proof_range.start, proof_range.end,
            )));
        }
        Ok(())
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

fn check_range_nonempty_and_inside_payload(payload: &[u8], range: &Range<usize>) -> VidResult<()> {
    if range.is_empty() {
        return Err(VidError::Argument(format!(
            "empty range ({}..{})",
            range.start, range.end
        )));
    }
    if range.end > payload.len() {
        return Err(VidError::Argument(format!(
            "range ({}..{}) out of bounds for payload len {}",
            range.start,
            range.end,
            payload.len()
        )));
    }
    Ok(())
}

fn check_range_poly(range_poly: &Range<usize>) -> VidResult<()> {
    // TODO TEMPORARY: forbid requests that span multiple polynomials
    if range_poly.len() != 1 {
        return Err(VidError::Argument(format!(
            "request spans {} polynomials, expect 1",
            range_poly.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::vid::{
        advz::{
            bytes_to_field::elem_byte_capacity,
            payload_prover::{LargeRangeProof, SmallRangeProof, Statement},
            tests::*,
            *,
        },
        payload_prover::PayloadProver,
    };
    use ark_bls12_381::Bls12_381;
    use ark_std::{ops::Range, println, rand::Rng};
    use digest::{generic_array::ArrayLength, OutputSizeUser};
    use sha2::Sha256;

    fn correctness_generic<E, H>()
    where
        E: Pairing,
        H: Digest + DynDigest + Default + Clone + Write,
        <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
    {
        // play with these items
        let (payload_chunk_size, num_storage_nodes) = (4, 6);
        let num_polys = 4;

        // more items as a function of the above
        let payload_elems_len = num_polys * payload_chunk_size;
        let payload_bytes_len = payload_elems_len * elem_byte_capacity::<E::ScalarField>();
        let poly_bytes_len = payload_chunk_size * elem_byte_capacity::<E::ScalarField>();
        let mut rng = jf_utils::test_rng();
        let payload = init_random_payload(payload_bytes_len, &mut rng);
        let srs = init_srs(payload_elems_len, &mut rng);

        let advz = Advz::<E, H>::new(payload_chunk_size, num_storage_nodes, srs).unwrap();
        let d = advz.disperse(&payload).unwrap();

        // TEST: prove data ranges for this paylaod
        // it takes too long to test all combos of (polynomial, start, len)
        // so do some edge cases and random cases
        let edge_cases = vec![
            Range { start: 0, end: 1 },
            Range { start: 0, end: 2 },
            Range {
                start: 0,
                end: poly_bytes_len - 1,
            },
            Range {
                start: 0,
                end: poly_bytes_len,
            },
            Range { start: 1, end: 2 },
            Range { start: 1, end: 3 },
            Range {
                start: 1,
                end: poly_bytes_len - 1,
            },
            Range {
                start: 1,
                end: poly_bytes_len,
            },
            Range {
                start: poly_bytes_len - 2,
                end: poly_bytes_len - 1,
            },
            Range {
                start: poly_bytes_len - 2,
                end: poly_bytes_len,
            },
            Range {
                start: poly_bytes_len - 1,
                end: poly_bytes_len,
            },
        ];
        let random_cases = {
            let num_cases = edge_cases.len();
            let mut random_cases = Vec::with_capacity(num_cases);
            for _ in 0..num_cases {
                let start = rng.gen_range(0..poly_bytes_len - 1);
                let end = rng.gen_range(start + 1..poly_bytes_len);
                random_cases.push(Range { start, end });
            }
            random_cases
        };
        let all_cases = [(edge_cases, "edge"), (random_cases, "rand")];

        for poly in 0..num_polys {
            let poly_offset = poly * poly_bytes_len;

            for cases in all_cases.iter() {
                for range in cases.0.iter() {
                    let range = Range {
                        start: range.start + poly_offset,
                        end: range.end + poly_offset,
                    };
                    println!("poly {} {} case: {:?}", poly, cases.1, range);

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
                    advz.payload_verify(stmt, &large_range_proof)
                        .unwrap()
                        .unwrap();
                }
            }
        }
    }

    #[test]
    fn correctness() {
        correctness_generic::<Bls12_381, Sha256>();
    }
}
