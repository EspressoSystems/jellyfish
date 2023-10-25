// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of [`Namespacer`] for [`Advz`].

use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;
use jf_utils::{bytes_to_field, compile_time_checks};

use super::{
    AffineRepr, Debug, DenseUVPolynomial, Digest, DynDigest, GenericAdvz, MerkleTreeScheme,
    PolynomialCommitmentScheme, PrimeField, UnivariatePCS, Vec, Write,
};
use crate::{
    alloc::string::ToString,
    vid::{namespace::Namespacer, vid, VidError},
};
use ark_std::{borrow::Borrow, format};

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
    type DataProof = ();

    fn data_proof(
        &self,
        _payload: &Self::Payload,
        _start: usize,
        _len: usize,
    ) -> crate::vid::VidResult<Self::DataProof> {
        todo!()
    }

    fn data_verify(
        &self,
        _payload: &Self::Payload,
        _start: usize,
        _len: usize,
        _proof: Self::DataProof,
    ) -> crate::vid::VidResult<Result<(), ()>> {
        todo!()
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

        let (primefield_bytes_len, ..) = compile_time_checks::<P::Evaluation>();
        let start = namespace_index * self.payload_chunk_size * primefield_bytes_len;

        // check args: `namespace_index` in bounds for `payload`.
        if start >= payload.as_slice().len() {
            return Err(VidError::Argument(format!(
                "namespace_index {} out of bounds for payload {}",
                namespace_index,
                payload.as_slice().len()
            )));
        }

        // check args: `common` consistent with `commit`
        let rebuilt_commit = {
            let mut hasher = H::new();
            for poly_commit in common.poly_commits.iter() {
                // TODO compiler bug? `as` should not be needed here!
                (poly_commit as &P::Commitment)
                    .serialize_uncompressed(&mut hasher)
                    .map_err(vid)?;
            }
            hasher.finalize()
        };
        if rebuilt_commit != *commit {
            return Err(VidError::Argument(
                "common inconsistent with commit".to_string(),
            ));
        }

        // rebuild the `namespace_index`th poly commit, check against `common`
        let poly_commit = {
            let elems_iter = bytes_to_field::<_, P::Evaluation>(payload.as_slice()[start..].iter())
                .map(|elem| *elem.borrow())
                .take(self.payload_chunk_size);

            // TODO TEMPORARY: use FFT to encode polynomials in eval form
            // Remove these FFTs after we get KZG in eval form
            // https://github.com/EspressoSystems/jellyfish/issues/339
            let mut coeffs: Vec<_> = elems_iter.collect();
            self.eval_domain.fft_in_place(&mut coeffs);

            let poly = P::Polynomial::from_coefficients_vec(coeffs);
            P::commit(&self.ck, &poly).map_err(vid)?
        };
        if poly_commit != common.poly_commits[namespace_index] {
            return Ok(Err(()));
        }

        Ok(Ok(()))
    }
}

#[cfg(test)]
mod tests {}
