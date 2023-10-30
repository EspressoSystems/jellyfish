// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of [`Namespacer`] for [`Advz`].

use ark_poly::EvaluationDomain;
use jf_utils::{bytes_to_field, compile_time_checks};

use super::{
    AffineRepr, Debug, DenseUVPolynomial, Digest, DynDigest, GenericAdvz, MerkleTreeScheme,
    PolynomialCommitmentScheme, PrimeField, UnivariatePCS, Vec, Write,
};
use crate::{
    alloc::string::ToString,
    vid::{namespace::Namespacer, vid, VidError},
};
use ark_std::format;

impl<P, T, H, V> Namespacer for GenericAdvz<P, T, H, V>
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
    // TODO should be P::Proof, not Vec<P::Proof>
    // https://github.com/EspressoSystems/jellyfish/issues/387
    type DataProof = Vec<P::Proof>;

    fn data_proof(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
    ) -> crate::vid::VidResult<Self::DataProof> {
        // check args: `start`, `len` in bounds for `payload`
        if start + len > payload.as_slice().len() {
            return Err(VidError::Argument(format!(
                "start {} + len {} out of bounds for payload {}",
                start,
                len,
                payload.as_slice().len()
            )));
        }

        // index conversion
        let (start_elem, len_elem) = self.range_byte_to_elem(start, len);
        let (start_namespace, len_namespace) = self.range_elem_to_poly(start_elem, len_elem);
        let start_namespace_byte = self.index_poly_to_byte(start_namespace);

        // check args:
        // TODO TEMPORARY: forbid requests that span multiple polynomials
        if len_namespace > 1 {
            return Err(VidError::Argument(format!(
                "request spans {} polynomials, expect 1",
                len_namespace
            )));
        }

        // grab the `start_namespace`th polynomial
        let polynomial = self.polynomial(
            bytes_to_field::<_, P::Evaluation>(payload.as_slice()[start_namespace_byte..].iter())
                .take(self.payload_chunk_size),
        );

        // prepare the list of input points
        // TODO perf: can't avoid use of `skip`
        let points: Vec<_> = {
            let offset = start_elem - self.index_byte_to_elem(start_namespace_byte);
            self.eval_domain
                .elements()
                .skip(offset)
                .take(len_elem)
                .collect()
        };

        let (proofs, _evals) = P::multi_open(&self.ck, &polynomial, &points).map_err(vid)?;
        Ok(proofs)
    }

    fn data_verify(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
        commit: &Self::Commit,
        common: &Self::Common,
        proof: &Self::DataProof,
    ) -> crate::vid::VidResult<Result<(), ()>> {
        // check args: `start`, `len` in bounds for `payload`
        if start + len > payload.as_slice().len() {
            return Err(VidError::Argument(format!(
                "start {} + len {} out of bounds for payload {}",
                start,
                len,
                payload.as_slice().len()
            )));
        }

        // check args: `common` consistent with `commit`
        if *commit != Self::poly_commits_hash(common.poly_commits.iter())? {
            return Err(VidError::Argument(
                "common inconsistent with commit".to_string(),
            ));
        }

        // index conversion
        let (start_elem, len_elem) = self.range_byte_to_elem(start, len);
        let (start_namespace, _len_namespace) = self.range_elem_to_poly(start_elem, len_elem);
        let start_namespace_byte = self.index_poly_to_byte(start_namespace);

        // prepare list of data elems
        let start_elem_byte = self.index_elem_to_byte(start_elem);
        let data_elems: Vec<_> =
            bytes_to_field::<_, P::Evaluation>(payload.as_slice()[start_elem_byte..].iter())
                .take(len_elem)
                .collect();

        // prepare list of input points
        // TODO perf: can't avoid use of `skip`
        let points: Vec<_> = {
            let offset = start_elem - self.index_byte_to_elem(start_namespace_byte);
            self.eval_domain
                .elements()
                .skip(offset)
                .take(len_elem)
                .collect()
        };

        // verify proof
        // TODO naive verify for multi_open
        // https://github.com/EspressoSystems/jellyfish/issues/387
        if data_elems.len() != proof.len() {
            return Err(VidError::Argument(format!(
                "data len {} differs from proof len {}",
                data_elems.len(),
                proof.len()
            )));
        }
        assert_eq!(data_elems.len(), points.len()); // sanity
        let poly_commit = &common.poly_commits[start_namespace];
        for (point, (elem, pf)) in points.iter().zip(data_elems.iter().zip(proof.iter())) {
            if !P::verify(&self.vk, poly_commit, point, elem, pf).map_err(vid)? {
                return Ok(Err(()));
            }
        }
        Ok(Ok(()))
    }

    fn namespace_verify(
        &self,
        payload: &Self::Payload,
        namespace_index: usize,
        commit: &Self::Commit,
        common: &Self::Common,
    ) -> crate::vid::VidResult<Result<(), ()>> {
        // check args: `namespace_index`` in bounds for `common`.
        if namespace_index >= common.poly_commits.len() {
            return Err(VidError::Argument(format!(
                "namespace_index {} out of bounds for common.poly_commits {}",
                namespace_index,
                common.poly_commits.len()
            )));
        }

        let start = self.index_poly_to_byte(namespace_index);

        // check args: `namespace_index` in bounds for `payload`.
        if start >= payload.as_slice().len() {
            return Err(VidError::Argument(format!(
                "namespace_index {} out of bounds for payload {}",
                namespace_index,
                payload.as_slice().len()
            )));
        }

        // check args: `common` consistent with `commit`
        if *commit != Self::poly_commits_hash(common.poly_commits.iter())? {
            return Err(VidError::Argument(
                "common inconsistent with commit".to_string(),
            ));
        }

        // rebuild the `namespace_index`th poly commit, check against `common`
        let poly_commit = {
            let poly = self.polynomial(
                bytes_to_field::<_, P::Evaluation>(payload.as_slice()[start..].iter())
                    .take(self.payload_chunk_size),
            );
            P::commit(&self.ck, &poly).map_err(vid)?
        };
        if poly_commit != common.poly_commits[namespace_index] {
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
    // lots of index manipulation.
    // with infinite dev time we should implement type-safe indices to preclude
    // index-misuse bugs. fn index_byte_to_poly(&self, index: usize) -> usize {
    //     self.index_poly_to_byte(self.index_elem_to_poly(self.
    // index_byte_to_elem(index))) }
    fn range_byte_to_elem(&self, start: usize, len: usize) -> (usize, usize) {
        range_coarsen(start, len, compile_time_checks::<P::Evaluation>().0)
    }
    fn _range_elem_to_byte(&self, start: usize, len: usize) -> (usize, usize) {
        _range_refine(start, len, compile_time_checks::<P::Evaluation>().0)
    }
    fn range_elem_to_poly(&self, start: usize, len: usize) -> (usize, usize) {
        range_coarsen(start, len, self.payload_chunk_size)
    }
    fn index_byte_to_elem(&self, index: usize) -> usize {
        let (primefield_bytes_len, ..) = compile_time_checks::<P::Evaluation>();
        index / primefield_bytes_len // round down
    }
    fn index_elem_to_byte(&self, index: usize) -> usize {
        let (primefield_bytes_len, ..) = compile_time_checks::<P::Evaluation>();
        index * primefield_bytes_len
    }
    // fn index_elem_to_poly(&self, index: usize) -> usize {
    //     index / self.payload_chunk_size // round down
    // }
    fn index_poly_to_byte(&self, index: usize) -> usize {
        let (primefield_bytes_len, ..) = compile_time_checks::<P::Evaluation>();
        index * self.payload_chunk_size * primefield_bytes_len
    }
}

fn range_coarsen(start: usize, len: usize, denominator: usize) -> (usize, usize) {
    let new_start = start / denominator;

    // underflow occurs if len is 0, so handle this case separately
    if len == 0 {
        return (new_start, 0);
    }

    let new_end = (start + len - 1) / denominator;
    (new_start, new_end - new_start + 1)
}

fn _range_refine(start: usize, len: usize, multiplier: usize) -> (usize, usize) {
    (start * multiplier, len * multiplier)
}

#[cfg(test)]
mod tests {
    use crate::vid::{
        advz::{tests::*, *},
        namespace::Namespacer,
    };
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::Rng;
    use digest::{generic_array::ArrayLength, OutputSizeUser};
    use jf_utils::compile_time_checks;
    use sha2::Sha256;

    fn namespace_generic<E, H>()
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
        let payload_bytes_len = payload_elems_len * compile_time_checks::<E::ScalarField>().0;
        let mut rng = jf_utils::test_rng();
        let payload = init_random_payload(payload_bytes_len, &mut rng);
        let srs = init_srs(payload_elems_len, &mut rng);

        let advz = Advz::<E, H>::new(payload_chunk_size, num_storage_nodes, srs).unwrap();
        let d = advz.disperse(&payload).unwrap();

        // TEST: verify "namespaces" (each namespace is a polynomial)
        assert_eq!(num_polys, d.common.poly_commits.len());
        for namespace_index in 0..num_polys {
            advz.namespace_verify(&payload, namespace_index, &d.commit, &d.common)
                .unwrap()
                .unwrap();
        }

        // TEST: prove data ranges for this paylaod
        // it takes too long to test all combos of (namespace, start, len)
        // so do some edge cases and random cases
        let namespace_bytes_len = payload_chunk_size * compile_time_checks::<E::ScalarField>().0;
        let edge_cases = {
            let mut edge_cases = Vec::new();
            for namespace in 0..num_polys {
                let random_offset = rng.gen_range(0..namespace_bytes_len);
                let random_start = random_offset + (namespace * namespace_bytes_len);

                // len edge cases
                edge_cases.push((namespace, random_start, 0));
                edge_cases.push((namespace, random_start, 1));
                edge_cases.push((
                    namespace,
                    random_start,
                    namespace_bytes_len - random_offset - 1,
                ));
                edge_cases.push((namespace, random_start, namespace_bytes_len - random_offset));

                // start edge cases
                edge_cases.push((namespace, 0, rng.gen_range(0..namespace_bytes_len)));
                edge_cases.push((namespace, 1, rng.gen_range(0..namespace_bytes_len - 1)));
                edge_cases.push((namespace, namespace_bytes_len - 2, rng.gen_range(0..1)));
                edge_cases.push((namespace, namespace_bytes_len - 1, 0));
            }
            edge_cases
        };
        let random_cases = {
            let num_cases = edge_cases.len();
            let mut random_cases = Vec::with_capacity(num_cases);
            for _ in 0..num_cases {
                let namespace = rng.gen_range(0..num_polys);
                let offset = rng.gen_range(0..namespace_bytes_len);
                let start = offset + (namespace * namespace_bytes_len);
                let len = rng.gen_range(0..namespace_bytes_len - offset);
                random_cases.push((namespace, start, len));
            }
            random_cases
        };

        for (i, range) in edge_cases.iter().chain(random_cases.iter()).enumerate() {
            println!(
                "case {}/{}: namespace {}, start {}, len {}",
                i,
                edge_cases.len() + random_cases.len(),
                range.0,
                range.1,
                range.2
            );
            let proof = advz.data_proof(&payload, range.1, range.2).unwrap();
            advz.data_verify(&payload, range.1, range.2, &d.commit, &d.common, &proof)
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn namespace() {
        namespace_generic::<Bls12_381, Sha256>();
    }
}
