// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of Verifiable Information Dispersal (VID) from <https://eprint.iacr.org/2021/1500>.
//!
//! `advz` named for the authors Alhaddad-Duan-Varia-Zhang.

use super::{vid, VidDisperse, VidError, VidResult, VidScheme};
use crate::{
    merkle_tree::{hasher::HasherMerkleTree, MerkleCommitment, MerkleTreeScheme},
    pcs::{
        prelude::UnivariateKzgPCS, PolynomialCommitmentScheme, StructuredReferenceString,
        UnivariatePCS,
    },
    reed_solomon_code::reed_solomon_erasure_decode_rou,
};
use anyhow::anyhow;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{
    fields::field_hashers::{DefaultFieldHasher, HashToField},
    FftField, Field, PrimeField,
};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    format,
    marker::PhantomData,
    ops::{Add, Mul},
    vec,
    vec::Vec,
    Zero,
};
use derivative::Derivative;
use digest::{crypto_common::Output, Digest, DynDigest};
use itertools::Itertools;
use jf_utils::{bytes_to_field, canonical, field_to_bytes};
use serde::{Deserialize, Serialize};

/// The [ADVZ VID scheme](https://eprint.iacr.org/2021/1500), a concrete impl for [`VidScheme`].
///
/// - `H` is any [`Digest`]-compatible hash function
/// - `E` is any [`Pairing`]
pub type Advz<E, H> = GenericAdvz<
    UnivariateKzgPCS<E>,
    <E as Pairing>::G1Affine,
    H,
    HasherMerkleTree<H, Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>>,
>;

/// Like [`Advz`] except with more abstraction.
///
/// - `P` is a [`PolynomialCommitmentScheme`]
/// - `T` is the group type underlying
///   [`PolynomialCommitmentScheme::Commitment`]
/// - `H` is a [`Digest`]-compatible hash function.
/// - `V` is a [`MerkleTreeScheme`], though any vector commitment would suffice
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq,
// PartialOrd, Serialize)]
pub struct GenericAdvz<P, T, H, V>
where
    P: PolynomialCommitmentScheme,
    P::Evaluation: FftField,
{
    payload_chunk_size: usize,
    num_storage_nodes: usize,
    ck: <P::SRS as StructuredReferenceString>::ProverParam,
    vk: <P::SRS as StructuredReferenceString>::VerifierParam,
    multi_open_domain: Radix2EvaluationDomain<P::Evaluation>,

    // TODO might be able to eliminate this field and instead use
    // `EvaluationDomain::reindex_by_subdomain()` on `multi_open_domain`
    // but that method consumes `other` and its doc is unclear.
    eval_domain: Radix2EvaluationDomain<P::Evaluation>,

    _pd: (PhantomData<T>, PhantomData<H>, PhantomData<V>),
}

impl<P, T, H, V> GenericAdvz<P, T, H, V>
where
    P: UnivariatePCS,
    P::Evaluation: FftField,
{
    /// Return a new instance of `Self`.
    ///
    /// # Errors
    /// Return [`VidError::Argument`] if `num_storage_nodes <
    /// payload_chunk_size`.
    pub fn new(
        payload_chunk_size: usize,
        num_storage_nodes: usize,
        srs: impl Borrow<P::SRS>,
    ) -> VidResult<Self> {
        if num_storage_nodes < payload_chunk_size {
            return Err(VidError::Argument(format!(
                "payload_chunk_size {} exceeds num_storage_nodes {}",
                payload_chunk_size, num_storage_nodes
            )));
        }
        let (ck, vk) = P::trim_fft_size(srs, payload_chunk_size).map_err(vid)?;
        let multi_open_domain =
            P::multi_open_rou_eval_domain(payload_chunk_size - 1, num_storage_nodes)
                .map_err(vid)?;
        let eval_domain = Radix2EvaluationDomain::new(payload_chunk_size).ok_or_else(|| {
            VidError::Internal(anyhow::anyhow!(
                "fail to construct doman of size {}",
                payload_chunk_size
            ))
        })?;

        // TODO TEMPORARY: enforce power-of-2 chunk size
        // Remove this restriction after we get KZG in eval form
        // https://github.com/EspressoSystems/jellyfish/issues/339
        if payload_chunk_size != eval_domain.size() {
            return Err(VidError::Argument(format!(
                "payload_chunk_size {} currently unsupported, round to {} instead",
                payload_chunk_size,
                eval_domain.size()
            )));
        }

        Ok(Self {
            payload_chunk_size,
            num_storage_nodes,
            ck,
            vk,
            multi_open_domain,
            eval_domain,
            _pd: Default::default(),
        })
    }
}

/// The [`VidScheme::Share`] type for [`Advz`].
#[derive(Derivative, Deserialize, Serialize)]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Share<P, V>
where
    P: PolynomialCommitmentScheme,
    V: MerkleTreeScheme,
    V::MembershipProof: Sync + Debug, /* TODO https://github.com/EspressoSystems/jellyfish/issues/253 */
{
    index: usize,
    #[serde(with = "canonical")]
    evals: Vec<P::Evaluation>,
    #[serde(with = "canonical")]
    aggregate_proof: P::Proof,
    evals_proof: V::MembershipProof,
}

/// The [`VidScheme::Common`] type for [`Advz`].
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative, Deserialize, Serialize)]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Common<P, V>
where
    P: PolynomialCommitmentScheme,
    V: MerkleTreeScheme,
{
    #[serde(with = "canonical")]
    poly_commits: Vec<P::Commitment>,
    all_evals_digest: V::NodeValue,
    elems_len: usize,
}

// We take great pains to maintain abstraction by relying only on traits and not
// concrete impls of those traits. Explanation of trait bounds:
// 1,2: `Polynomial` is univariate: domain (`Point`) same field as range
// (`Evaluation'). 3,4: `Commitment` is (convertible to/from) an elliptic curve
// group in affine form. 5: `H` is a hasher
//
// `PrimeField` needed only because `bytes_to_field` needs it.
// Otherwise we could relax to `FftField`.
impl<P, T, H, V> VidScheme for GenericAdvz<P, T, H, V>
where
    P: UnivariatePCS<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Evaluation: PrimeField,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>, // 2
    P::Commitment: From<T> + AsRef<T>,               // 3
    T: AffineRepr<ScalarField = P::Evaluation>,      // 4
    H: Digest + DynDigest + Default + Clone + Write, // 5
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug, /* TODO https://github.com/EspressoSystems/jellyfish/issues/253 */
    V::Index: From<u64>,
{
    type Commit = Output<H>;
    type Share = Share<P, V>;
    type Common = Common<P, V>;

    fn commit_only<I>(&self, payload: I) -> VidResult<Self::Commit>
    where
        I: IntoIterator,
        I::Item: Borrow<u8>,
    {
        let mut hasher = H::new();
        let elems_iter = bytes_to_field::<_, P::Evaluation>(payload);
        for coeffs_iter in elems_iter.chunks(self.payload_chunk_size).into_iter() {
            // TODO TEMPORARY: use FFT to encode polynomials in eval form
            // Remove these FFTs after we get KZG in eval form
            // https://github.com/EspressoSystems/jellyfish/issues/339
            let mut coeffs: Vec<_> = coeffs_iter.collect();
            self.eval_domain.fft_in_place(&mut coeffs);

            let poly = DenseUVPolynomial::from_coefficients_vec(coeffs);
            let commitment = P::commit(&self.ck, &poly).map_err(vid)?;
            commitment
                .serialize_uncompressed(&mut hasher)
                .map_err(vid)?;
        }
        Ok(hasher.finalize())
    }

    fn disperse<I>(&self, payload: I) -> VidResult<VidDisperse<Self>>
    where
        I: IntoIterator,
        I::Item: Borrow<u8>,
    {
        self.disperse_from_elems(bytes_to_field::<_, P::Evaluation>(payload))
    }

    fn verify_share(
        &self,
        share: &Self::Share,
        common: &Self::Common,
    ) -> VidResult<Result<(), ()>> {
        // check arguments
        if share.evals.len() != common.poly_commits.len() {
            return Err(VidError::Argument(format!(
                "(share eval, common poly commit) lengths differ ({},{})",
                share.evals.len(),
                common.poly_commits.len()
            )));
        }
        if share.index >= self.num_storage_nodes {
            return Ok(Err(())); // not an arg error
        }

        // verify eval proof
        if V::verify(
            common.all_evals_digest,
            &V::Index::from(share.index as u64),
            &share.evals_proof,
        )
        .map_err(vid)?
        .is_err()
        {
            return Ok(Err(()));
        }

        let pseudorandom_scalar = Self::pseudorandom_scalar(common)?;

        // Compute aggregate polynomial [commitment|evaluation]
        // as a pseudorandom linear combo of [commitments|evaluations]
        // via evaluation of the polynomial whose coefficients are
        // [commitments|evaluations] and whose input point is the pseudorandom
        // scalar.
        let aggregate_poly_commit = P::Commitment::from(
            polynomial_eval(
                common
                    .poly_commits
                    .iter()
                    .map(|x| CurveMultiplier(x.as_ref())),
                pseudorandom_scalar,
            )
            .into(),
        );
        let aggregate_eval =
            polynomial_eval(share.evals.iter().map(FieldMultiplier), pseudorandom_scalar);

        // verify aggregate proof
        Ok(P::verify(
            &self.vk,
            &aggregate_poly_commit,
            &self.multi_open_domain.element(share.index),
            &aggregate_eval,
            &share.aggregate_proof,
        )
        .map_err(vid)?
        .then_some(())
        .ok_or(()))
    }

    fn recover_payload(&self, shares: &[Self::Share], common: &Self::Common) -> VidResult<Vec<u8>> {
        // TODO can we avoid collect() here?
        Ok(field_to_bytes(self.recover_elems(shares, common)?).collect())
    }
}

impl<P, T, H, V> GenericAdvz<P, T, H, V>
where
    P: UnivariatePCS<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Evaluation: PrimeField,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
    H: Digest + DynDigest + Default + Clone + Write,
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug, /* TODO https://github.com/EspressoSystems/jellyfish/issues/253 */
    V::Index: From<u64>,
{
    /// Same as [`VidScheme::disperse`] except `payload` iterates over
    /// field elements.
    pub fn disperse_from_elems<I>(&self, payload: I) -> VidResult<VidDisperse<Self>>
    where
        I: IntoIterator,
        I::Item: Borrow<P::Evaluation>,
    {
        // partition payload into polynomial coefficients
        // and count `elems_len` for later
        let elems_iter = payload.into_iter().map(|elem| *elem.borrow());
        let mut elems_len = 0;
        let mut polys = Vec::new();
        for coeffs_iter in elems_iter.chunks(self.payload_chunk_size).into_iter() {
            // TODO TEMPORARY: use FFT to encode polynomials in eval form
            // Remove these FFTs after we get KZG in eval form
            // https://github.com/EspressoSystems/jellyfish/issues/339
            let mut coeffs: Vec<_> = coeffs_iter.collect();
            let pre_fft_len = coeffs.len();
            self.eval_domain.fft_in_place(&mut coeffs);
            if pre_fft_len == self.payload_chunk_size {
                assert_eq!(coeffs.len(), pre_fft_len); // sanity
            }

            elems_len += pre_fft_len;
            polys.push(DenseUVPolynomial::from_coefficients_vec(coeffs));
        }

        // evaluate polynomials
        let all_storage_node_evals = {
            let mut all_storage_node_evals =
                vec![Vec::with_capacity(polys.len()); self.num_storage_nodes];

            for poly in polys.iter() {
                let poly_evals =
                    P::multi_open_rou_evals(poly, self.num_storage_nodes, &self.multi_open_domain)
                        .map_err(vid)?;

                for (storage_node_evals, poly_eval) in
                    all_storage_node_evals.iter_mut().zip(poly_evals)
                {
                    storage_node_evals.push(poly_eval);
                }
            }

            // sanity checks
            assert_eq!(all_storage_node_evals.len(), self.num_storage_nodes);
            for storage_node_evals in all_storage_node_evals.iter() {
                assert_eq!(storage_node_evals.len(), polys.len());
            }

            all_storage_node_evals
        };

        // vector commitment to polynomial evaluations
        // TODO why do I need to compute the height of the merkle tree?
        let height: usize = all_storage_node_evals
            .len()
            .checked_ilog(V::ARITY)
            .ok_or_else(|| {
                VidError::Argument(format!(
                    "num_storage_nodes {} log base {} invalid",
                    all_storage_node_evals.len(),
                    V::ARITY
                ))
            })?
            .try_into()
            .expect("num_storage_nodes log base arity should fit into usize");
        let height = height + 1; // avoid fully qualified syntax for try_into()
        let all_evals_commit = V::from_elems(height, &all_storage_node_evals).map_err(vid)?;

        let common = Common {
            poly_commits: polys
                .iter()
                .map(|poly| P::commit(&self.ck, poly))
                .collect::<Result<_, _>>()
                .map_err(vid)?,
            all_evals_digest: all_evals_commit.commitment().digest(),
            elems_len,
        };

        let commit = {
            let mut hasher = H::new();
            for poly_commit in common.poly_commits.iter() {
                // TODO compiler bug? `as` should not be needed here!
                (poly_commit as &P::Commitment)
                    .serialize_uncompressed(&mut hasher)
                    .map_err(vid)?;
            }
            hasher.finalize()
        };

        let pseudorandom_scalar = Self::pseudorandom_scalar(&common)?;

        // Compute aggregate polynomial
        // as a pseudorandom linear combo of polynomials
        // via evaluation of the polynomial whose coefficients are polynomials
        // and whose input point is the pseudorandom scalar.
        let aggregate_poly =
            polynomial_eval(polys.iter().map(PolynomialMultiplier), pseudorandom_scalar);

        let aggregate_proofs = P::multi_open_rou_proofs(
            &self.ck,
            &aggregate_poly,
            self.num_storage_nodes,
            &self.multi_open_domain,
        )
        .map_err(vid)?;

        let shares = all_storage_node_evals
            .into_iter()
            .zip(aggregate_proofs)
            .enumerate()
            .map(|(index, (evals, aggregate_proof))| {
                Ok(Share {
                    index,
                    evals,
                    aggregate_proof,
                    evals_proof: all_evals_commit
                        .lookup(V::Index::from(index as u64))
                        .expect_ok()
                        .map_err(vid)?
                        .1,
                })
            })
            .collect::<Result<_, VidError>>()?;

        Ok(VidDisperse {
            shares,
            common,
            commit,
        })
    }

    /// Same as [`VidScheme::recover_payload`] except returns a [`Vec`] of field
    /// elements.
    pub fn recover_elems(
        &self,
        shares: &[<Self as VidScheme>::Share],
        common: &<Self as VidScheme>::Common,
    ) -> VidResult<Vec<P::Evaluation>> {
        if shares.len() < self.payload_chunk_size {
            return Err(VidError::Argument(format!(
                "not enough shares {}, expected at least {}",
                shares.len(),
                self.payload_chunk_size
            )));
        }

        // all shares must have equal evals len
        let num_polys = shares
            .first()
            .ok_or_else(|| VidError::Argument("shares is empty".into()))?
            .evals
            .len();
        if let Some((index, share)) = shares
            .iter()
            .enumerate()
            .find(|(_, s)| s.evals.len() != num_polys)
        {
            return Err(VidError::Argument(format!(
                "shares do not have equal evals lengths: share {} len {}, share {} len {}",
                0,
                num_polys,
                index,
                share.evals.len()
            )));
        }

        let result_len = num_polys * self.payload_chunk_size;
        let mut result = Vec::with_capacity(result_len);
        for i in 0..num_polys {
            let mut coeffs = reed_solomon_erasure_decode_rou(
                shares.iter().map(|s| (s.index, s.evals[i])),
                self.payload_chunk_size,
                &self.multi_open_domain,
            )
            .map_err(vid)?;

            // TODO TEMPORARY: use FFT to encode polynomials in eval form
            // Remove these FFTs after we get KZG in eval form
            // https://github.com/EspressoSystems/jellyfish/issues/339
            self.eval_domain.ifft_in_place(&mut coeffs);

            result.append(&mut coeffs);
        }
        assert_eq!(result.len(), result_len);
        result.truncate(common.elems_len);
        Ok(result)
    }

    fn pseudorandom_scalar(common: &<Self as VidScheme>::Common) -> VidResult<P::Evaluation> {
        let mut hasher = H::new();
        for poly_commit in common.poly_commits.iter() {
            poly_commit
                .serialize_uncompressed(&mut hasher)
                .map_err(vid)?;
        }
        common
            .all_evals_digest
            .serialize_uncompressed(&mut hasher)
            .map_err(vid)?;

        // Notes on hash-to-field:
        // - Can't use `Field::from_random_bytes` because it's fallible (in what sense
        //   is it from "random" bytes?!)
        // - `HashToField` does not expose an incremental API (ie. `update`) so use an
        //   ordinary hasher and pipe `hasher.finalize()` through `hash_to_field`
        //   (sheesh!)
        const HASH_TO_FIELD_DOMAIN_SEP: &[u8; 4] = b"rick";
        let hasher_to_field =
            <DefaultFieldHasher<H> as HashToField<P::Evaluation>>::new(HASH_TO_FIELD_DOMAIN_SEP);
        Ok(*hasher_to_field
            .hash_to_field(&hasher.finalize(), 1)
            .first()
            .ok_or_else(|| anyhow!("hash_to_field output is empty"))
            .map_err(vid)?)
    }
}

// `From` impls for `VidError`
//
// # Goal
// `anyhow::Error` has the property that `?` magically coerces the error into
// `anyhow::Error`. I want the same property for `VidError`.
// I don't know how to achieve this without the following boilerplate.
//
// # Boilerplate
// I want to coerce any error `E` into `VidError::Internal` similar to
// `anyhow::Error`. Unfortunately, I need to manually impl `From<E> for
// VidError` for each `E`. Can't do a generic impl because it conflicts with
// `impl<T> From<T> for T` in core.
// impl From<crate::errors::PrimitivesError> for VidError {
//     fn from(value: crate::errors::PrimitivesError) -> Self {
//         Self::Internal(value.into())
//     }
// }

// impl From<crate::pcs::prelude::PCSError> for VidError {
//     fn from(value: crate::pcs::prelude::PCSError) -> Self {
//         Self::Internal(value.into())
//     }
// }

// impl From<ark_serialize::SerializationError> for VidError {
//     fn from(value: ark_serialize::SerializationError) -> Self {
//         Self::Internal(value.into())
//     }
// }

/// Evaluate a generalized polynomial at a given point using Horner's method.
///
/// Coefficients can be anything that can be multiplied by a point
/// and such that the result of such multiplications can be added.
fn polynomial_eval<U, F, I>(coeffs: I, point: impl Borrow<F>) -> U
where
    I: IntoIterator,
    I::Item: for<'a> Mul<&'a F, Output = U>,
    U: Add<Output = U> + Zero,
{
    coeffs
        .into_iter()
        .fold(U::zero(), |res, coeff| coeff * point.borrow() + res)
}

struct FieldMultiplier<'a, F>(&'a F);

/// Arkworks does not provide (&F,&F) multiplication
impl<F> Mul<&F> for FieldMultiplier<'_, F>
where
    F: Field,
{
    type Output = F;

    fn mul(self, rhs: &F) -> Self::Output {
        *self.0 * rhs
    }
}

/// Arkworks does not provide (&C,&F) multiplication
struct CurveMultiplier<'a, C>(&'a C);

impl<C, F> Mul<&F> for CurveMultiplier<'_, C>
where
    C: AffineRepr<ScalarField = F>,
{
    type Output = C::Group;

    fn mul(self, rhs: &F) -> Self::Output {
        *self.0 * rhs
    }
}

/// Arkworks does not provide (&P,&F) multiplication
struct PolynomialMultiplier<'a, P>(&'a P);

impl<P, F> Mul<&F> for PolynomialMultiplier<'_, P>
where
    P: DenseUVPolynomial<F>,
    F: Field,
{
    type Output = P;

    fn mul(self, rhs: &F) -> Self::Output {
        // `Polynomial` does not impl `Mul` by scalar
        // so we need to multiply each coeff by `rhs`
        P::from_coefficients_vec(self.0.coeffs().iter().map(|coeff| *coeff * rhs).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{VidError::Argument, *};

    use crate::{merkle_tree::hasher::HasherNode, pcs::checked_fft_size};
    use ark_bls12_381::Bls12_381;
    use ark_std::{rand::RngCore, vec};
    use sha2::Sha256;

    #[test]
    fn sad_path_verify_share_corrupt_share() {
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(&bytes_random).unwrap();
        let (shares, common) = (disperse.shares, disperse.common);

        for (i, share) in shares.iter().enumerate() {
            // missing share eval
            {
                let share_missing_eval = Share {
                    evals: share.evals[1..].to_vec(),
                    ..share.clone()
                };
                assert_arg_err(
                    advz.verify_share(&share_missing_eval, &common),
                    "1 missing share should be arg error",
                );
            }

            // corrupted share eval
            {
                let mut share_bad_eval = share.clone();
                share_bad_eval.evals[0].double_in_place();
                advz.verify_share(&share_bad_eval, &common)
                    .unwrap()
                    .expect_err("bad share value should fail verification");
            }

            // corrupted index, in bounds
            {
                let share_bad_index = Share {
                    index: (share.index + 1) % advz.num_storage_nodes,
                    ..share.clone()
                };
                advz.verify_share(&share_bad_index, &common)
                    .unwrap()
                    .expect_err("bad share index should fail verification");
            }

            // corrupted index, out of bounds
            {
                let share_bad_index = Share {
                    index: share.index + advz.num_storage_nodes,
                    ..share.clone()
                };
                advz.verify_share(&share_bad_index, &common)
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
                advz.verify_share(&share_bad_evals_proof, &common)
                    .unwrap()
                    .expect_err("bad share evals proof should fail verification");
            }
        }
    }

    #[test]
    fn sad_path_verify_share_corrupt_commit() {
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(&bytes_random).unwrap();
        let (shares, common) = (disperse.shares, disperse.common);

        // missing commit
        let common_missing_item = Common {
            poly_commits: common.poly_commits[1..].to_vec(),
            ..common.clone()
        };
        assert_arg_err(
            advz.verify_share(&shares[0], &common_missing_item),
            "1 missing commit should be arg error",
        );

        // 1 corrupt commit, poly_commit
        let common_1_poly_corruption = {
            let mut corrupted = common.clone();
            corrupted.poly_commits[0] = <Bls12_381 as Pairing>::G1Affine::zero().into();
            corrupted
        };
        advz.verify_share(&shares[0], &common_1_poly_corruption)
            .unwrap()
            .expect_err("1 corrupt poly_commit should fail verification");

        // 1 corrupt commit, all_evals_digest
        let common_1_digest_corruption = {
            let mut corrupted = common;
            let mut digest_bytes = vec![0u8; corrupted.all_evals_digest.uncompressed_size()];
            corrupted
                .all_evals_digest
                .serialize_uncompressed(&mut digest_bytes)
                .expect("digest serialization should succeed");
            digest_bytes[0] += 1;
            corrupted.all_evals_digest =
                HasherNode::deserialize_uncompressed(digest_bytes.as_slice())
                    .expect("digest deserialization should succeed");
            corrupted
        };
        advz.verify_share(&shares[0], &common_1_digest_corruption)
            .unwrap()
            .expect_err("1 corrupt all_evals_digest should fail verification");
    }

    #[test]
    fn sad_path_verify_share_corrupt_share_and_commit() {
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(&bytes_random).unwrap();
        let (mut shares, mut common) = (disperse.shares, disperse.common);

        common.poly_commits.pop();
        shares[0].evals.pop();

        // equal nonzero lengths for common, share
        advz.verify_share(&shares[0], &common).unwrap().unwrap_err();

        common.poly_commits.clear();
        shares[0].evals.clear();

        // zero length for common, share
        advz.verify_share(&shares[0], &common).unwrap().unwrap_err();
    }

    #[test]
    fn sad_path_recover_payload_corrupt_shares() {
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(&bytes_random).unwrap();
        let (shares, common) = (disperse.shares, disperse.common);

        {
            // unequal share eval lengths
            let mut shares_missing_evals = shares.clone();
            for i in 0..shares_missing_evals.len() - 1 {
                shares_missing_evals[i].evals.pop();
                assert_arg_err(
                    advz.recover_payload(&shares_missing_evals, &common),
                    format!("{} shares missing 1 eval should be arg error", i + 1).as_str(),
                );
            }

            // 1 eval missing from all shares
            shares_missing_evals.last_mut().unwrap().evals.pop();
            let bytes_recovered = advz
                .recover_payload(&shares_missing_evals, &common)
                .expect("recover_payload should succeed when shares have equal eval lengths");
            assert_ne!(bytes_recovered, bytes_random);
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
            let mut shares_bad_indices = shares;
            for i in 0..shares_bad_indices.len() {
                shares_bad_indices[i].index += advz.multi_open_domain.size();
                advz.recover_payload(&shares_bad_indices, &common)
                    .expect_err("recover_payload should fail when indices are out of bounds");
            }
        }
    }

    /// Routine initialization tasks.
    ///
    /// Returns the following tuple:
    /// 1. An initialized [`Advz`] instance.
    /// 2. A `Vec<u8>` filled with random bytes.
    fn avdz_init() -> (Advz<Bls12_381, Sha256>, Vec<u8>) {
        let (payload_chunk_size, num_storage_nodes) = (4, 6);
        let mut rng = jf_utils::test_rng();
        let srs = UnivariateKzgPCS::<Bls12_381>::gen_srs_for_testing(
            &mut rng,
            checked_fft_size(payload_chunk_size).unwrap(),
        )
        .unwrap();
        let advz = Advz::new(payload_chunk_size, num_storage_nodes, srs).unwrap();

        let mut bytes_random = vec![0u8; 4000];
        rng.fill_bytes(&mut bytes_random);

        (advz, bytes_random)
    }

    /// Convenience wrapper to assert [`VidError::Argument`] return value.
    fn assert_arg_err<T>(res: VidResult<T>, msg: &str) {
        assert!(matches!(res, Err(Argument(_))), "{}", msg);
    }
}
