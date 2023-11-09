// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of Verifiable Information Dispersal (VID) from <https://eprint.iacr.org/2021/1500>.
//!
//! `advz` named for the authors Alhaddad-Duan-Varia-Zhang.

use super::{vid, VidDisperse, VidError, VidResult, VidScheme};
use crate::{
    alloc::string::ToString,
    merkle_tree::{
        hasher::{HasherDigest, HasherMerkleTree},
        MerkleCommitment, MerkleTreeScheme,
    },
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
    Field,
};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    end_timer, format,
    marker::PhantomData,
    ops::{Add, Mul},
    start_timer, vec,
    vec::Vec,
    Zero,
};
use bytes_to_field::{bytes_to_field, field_to_bytes};
use derivative::Derivative;
use digest::{crypto_common::Output, DynDigest};
use itertools::Itertools;
use jf_utils::canonical;
use serde::{Deserialize, Serialize};

mod bytes_to_field;
pub mod payload_prover;

/// The [ADVZ VID scheme](https://eprint.iacr.org/2021/1500), a concrete impl for [`VidScheme`].
///
/// - `E` is any [`Pairing`]
/// - `H` is a [`Digest`]-compatible hash function.
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq,
// PartialOrd, Serialize)]
pub struct Advz<E, H> where E: Pairing {
    payload_chunk_size: usize,
    num_storage_nodes: usize,
    ck: <<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS as StructuredReferenceString>::ProverParam,
    vk: <<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS as StructuredReferenceString>::VerifierParam,

    // TODO change `Evaluation` -> `Point`
    multi_open_domain: Radix2EvaluationDomain<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,

    // TODO might be able to eliminate this field and instead use
    // `EvaluationDomain::reindex_by_subdomain()` on `multi_open_domain`
    // but that method consumes `other` and its doc is unclear.
    eval_domain: Radix2EvaluationDomain<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,

    _pd: PhantomData<H>,
}

impl<E, H> Advz<E, H>
where
    E: Pairing,
{
    /// Return a new instance of `Self`.
    ///
    /// # Errors
    /// Return [`VidError::Argument`] if `num_storage_nodes <
    /// payload_chunk_size`.
    pub fn new(
        payload_chunk_size: usize,
        num_storage_nodes: usize,
        srs: impl Borrow<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS>,
    ) -> VidResult<Self> {
        if num_storage_nodes < payload_chunk_size {
            return Err(VidError::Argument(format!(
                "payload_chunk_size {} exceeds num_storage_nodes {}",
                payload_chunk_size, num_storage_nodes
            )));
        }
        let (ck, vk) =
            <UnivariateKzgPCS<E> as UnivariatePCS>::trim_fft_size(srs, payload_chunk_size - 1)
                .map_err(vid)?;
        let multi_open_domain = <UnivariateKzgPCS<E> as UnivariatePCS>::multi_open_rou_eval_domain(
            payload_chunk_size - 1,
            num_storage_nodes,
        )
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
// #[serde(bound = "H: CanonicalSerialize + CanonicalDeserialize,")]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(
    Clone,
    Debug(bound = ""),
    Eq(bound = ""),
    Hash(bound = ""),
    PartialEq(bound = "")
)]
pub struct Share<E, H>
where
    E: Pairing,
    // H: HasherDigest,
    H: DynDigest + Default + Clone + HasherDigest,
    // V: MerkleTreeScheme,
    // V::MembershipProof: Sync + Debug, /* TODO https://github.com/EspressoSystems/jellyfish/issues/253 */
{
    index: usize,
    #[serde(with = "canonical")]
    evals: Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
    #[serde(with = "canonical")]
    aggregate_proof: <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Proof,
    evals_proof: <HasherMerkleTree<
        H,
        Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
    > as MerkleTreeScheme>::MembershipProof,
}

/// The [`VidScheme::Common`] type for [`Advz`].
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative, Deserialize, Serialize)]
// #[serde(bound = "H: CanonicalSerialize + CanonicalDeserialize,")]
#[serde(bound = "Output<H>: Serialize + for<'a> Deserialize<'a>")]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(
    Clone,
    Debug(bound = ""),
    Default,
    Eq(bound = ""),
    Hash(bound = ""),
    PartialEq(bound = "")
)]
pub struct Common<E, H>
where
    E: Pairing,
    // H: HasherDigest,
    H: DynDigest + Default + Clone + HasherDigest,
{
    #[serde(with = "canonical")]
    poly_commits: Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Commitment>,
    all_evals_digest: <HasherMerkleTree<
        H,
        Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
    > as MerkleTreeScheme>::NodeValue,
    bytes_len: usize,
}

// We take great pains to maintain abstraction by relying only on traits and not
// concrete impls of those traits. Explanation of trait bounds:
// 1,2: `Polynomial` is univariate: domain (`Point`) same field as range
// (`Evaluation'). 3,4: `Commitment` is (convertible to/from) an elliptic curve
// group in affine form. 5: `H` is a hasher
//
// `PrimeField` needed only because `bytes_to_field` needs it.
// Otherwise we could relax to `FftField`.
impl<E, H> VidScheme for Advz<E, H>
where
    E: Pairing,
    // TODO replace with H: HasherDigest?
    H: DynDigest + Default + Clone + HasherDigest,
    // H: HasherDigest,
    // V: MerkleTreeScheme<
    //     Element = Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
    // >,
    // V::MembershipProof: Sync + Debug, /* TODO https://github.com/EspressoSystems/jellyfish/issues/253 */
    // V::Index: From<u64>,
{
    type Commit = Output<H>;
    type Share = Share<E, H>;
    type Common = Common<E, H>;

    fn commit_only<B>(&self, payload: B) -> VidResult<Self::Commit>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        let commit_time = start_timer!(|| format!(
            "VID commit_only {} payload bites to {} nodes",
            payload.len(),
            self.num_storage_nodes
        ));

        // Can't use `Self::poly_commits_hash()`` here because `P::commit()`` returns
        // `Result<P::Commitment,_>`` instead of `P::Commitment`.
        // There's probably an idiomatic way to do this using eg.
        // itertools::process_results() but the code is unreadable.
        let mut hasher = H::new();
        let elems_iter = bytes_to_field::<
            _,
            <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation,
        >(payload);
        for evals_iter in elems_iter.chunks(self.payload_chunk_size).into_iter() {
            let poly = self.polynomial(evals_iter);
            let commitment =
                <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::commit(&self.ck, &poly)
                    .map_err(vid)?;
            commitment
                .serialize_uncompressed(&mut hasher)
                .map_err(vid)?;
        }
        end_timer!(commit_time);
        Ok(hasher.finalize())
    }

    fn disperse<B>(&self, payload: B) -> VidResult<VidDisperse<Self>>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        let payload_len = payload.len();
        let disperse_time = start_timer!(|| format!(
            "VID disperse {} payload bytes to {} nodes",
            payload_len, self.num_storage_nodes
        ));

        // partition payload into polynomial coefficients
        // and count `elems_len` for later
        let bytes_to_polys_time = start_timer!(|| "encode payload bytes into polynomials");
        let elems_iter = bytes_to_field::<
            _,
            <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation,
        >(payload);
        let polys: Vec<_> = elems_iter
            .chunks(self.payload_chunk_size)
            .into_iter()
            .map(|evals_iter| self.polynomial(evals_iter))
            .collect();
        end_timer!(bytes_to_polys_time);

        // evaluate polynomials
        let all_storage_node_evals_timer = start_timer!(|| format!(
            "compute all storage node evals for {} polynomials of degree {}",
            polys.len(),
            self.payload_chunk_size
        ));
        let all_storage_node_evals = {
            let mut all_storage_node_evals =
                vec![Vec::with_capacity(polys.len()); self.num_storage_nodes];

            for poly in polys.iter() {
                let poly_evals = <UnivariateKzgPCS<E> as UnivariatePCS>::multi_open_rou_evals(
                    poly,
                    self.num_storage_nodes,
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
            assert_eq!(all_storage_node_evals.len(), self.num_storage_nodes);
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
        let height: usize = all_storage_node_evals
            .len()
            .checked_ilog(
                <HasherMerkleTree<
                    H,
                    Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
                > as MerkleTreeScheme>::ARITY,
            )
            .ok_or_else(|| {
                VidError::Argument(format!(
                    "num_storage_nodes {} log base {} invalid",
                    all_storage_node_evals.len(),
                    <HasherMerkleTree<
                        H,
                        Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
                    > as MerkleTreeScheme>::ARITY
                ))
            })?
            .try_into()
            .expect("num_storage_nodes log base arity should fit into usize");
        let height = height + 1; // avoid fully qualified syntax for try_into()
        let all_evals_commit =
            <HasherMerkleTree<
                H,
                Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
            > as MerkleTreeScheme>::from_elems(height, &all_storage_node_evals)
            .map_err(vid)?;
        end_timer!(all_evals_commit_timer);

        let common_timer = start_timer!(|| format!("compute {} KZG commitments", polys.len()));
        let common = Common {
            poly_commits: polys
                .iter()
                .map(|poly| {
                    <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::commit(&self.ck, poly)
                })
                .collect::<Result<_, _>>()
                .map_err(vid)?,
            all_evals_digest: all_evals_commit.commitment().digest(),
            bytes_len: payload_len,
        };
        end_timer!(common_timer);

        let commit = Self::poly_commits_hash(common.poly_commits.iter())?;
        let pseudorandom_scalar = Self::pseudorandom_scalar(&common, &commit)?;

        // Compute aggregate polynomial
        // as a pseudorandom linear combo of polynomials
        // via evaluation of the polynomial whose coefficients are polynomials
        // and whose input point is the pseudorandom scalar.
        let aggregate_poly =
            polynomial_eval(polys.iter().map(PolynomialMultiplier), pseudorandom_scalar);

        let agg_proofs_timer = start_timer!(|| format!(
            "compute aggregate proofs for {} storage nodes",
            self.num_storage_nodes
        ));
        let aggregate_proofs = <UnivariateKzgPCS<E> as UnivariatePCS>::multi_open_rou_proofs(
            &self.ck,
            &aggregate_poly,
            self.num_storage_nodes,
            &self.multi_open_domain,
        )
        .map_err(vid)?;
        end_timer!(agg_proofs_timer);

        let assemblage_timer = start_timer!(|| "assemble shares for dispersal");
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
                        .lookup(<HasherMerkleTree<
                            H,
                            Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
                        > as MerkleTreeScheme>::Index::from(
                            index as u64
                        ))
                        .expect_ok()
                        .map_err(vid)?
                        .1,
                })
            })
            .collect::<Result<_, VidError>>()?;
        end_timer!(assemblage_timer);

        end_timer!(disperse_time);
        Ok(VidDisperse {
            shares,
            common,
            commit,
        })
    }

    fn verify_share(
        &self,
        share: &Self::Share,
        common: &Self::Common,
        commit: &Self::Commit,
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

        // check `common` against `commit`
        let commit_rebuilt = Self::poly_commits_hash(common.poly_commits.iter())?;
        if commit_rebuilt != *commit {
            return Err(VidError::Argument(
                "commit inconsistent with common".to_string(),
            ));
        }

        // verify eval proof
        if <HasherMerkleTree<
        H,
        Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
    > as MerkleTreeScheme>::verify(
            common.all_evals_digest,
            &<HasherMerkleTree<
            H,
            Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
        > as MerkleTreeScheme>::Index::from(share.index as u64),
            &share.evals_proof,
        )
        .map_err(vid)?
        .is_err()
        {
            return Ok(Err(()));
        }

        let pseudorandom_scalar = Self::pseudorandom_scalar(common, commit)?;

        // Compute aggregate polynomial [commitment|evaluation]
        // as a pseudorandom linear combo of [commitments|evaluations]
        // via evaluation of the polynomial whose coefficients are
        // [commitments|evaluations] and whose input point is the pseudorandom
        // scalar.
        let aggregate_poly_commit =
            <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Commitment::from(
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
        Ok(<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::verify(
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

        let elems_capacity = num_polys * self.payload_chunk_size;
        let mut elems = Vec::with_capacity(elems_capacity);
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
            self.eval_domain.fft_in_place(&mut coeffs);

            elems.append(&mut coeffs);
        }
        assert_eq!(elems.len(), elems_capacity);

        let mut payload: Vec<_> = field_to_bytes(elems).collect();
        payload.truncate(common.bytes_len);
        Ok(payload)
    }
}

impl<E, H> Advz<E, H>
where
    E: Pairing,
    H: DynDigest + Default + Clone + HasherDigest,
    // H: HasherDigest,
    // V: MerkleTreeScheme<
    //     Element = Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
    // >,
    // V::MembershipProof: Sync + Debug, /* TODO https://github.com/EspressoSystems/jellyfish/issues/253 */
    // V::Index: From<u64>,
{
    fn pseudorandom_scalar(
        common: &<Self as VidScheme>::Common,
        commit: &<Self as VidScheme>::Commit,
    ) -> VidResult<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation> {
        let mut hasher = H::new();
        commit.serialize_uncompressed(&mut hasher).map_err(vid)?;
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
        let hasher_to_field = <DefaultFieldHasher<H> as HashToField<
            <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation,
        >>::new(HASH_TO_FIELD_DOMAIN_SEP);
        Ok(*hasher_to_field
            .hash_to_field(&hasher.finalize(), 1)
            .first()
            .ok_or_else(|| anyhow!("hash_to_field output is empty"))
            .map_err(vid)?)
    }

    fn polynomial<I>(
        &self,
        coeffs: I,
    ) -> <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Polynomial
    where
        I: Iterator,
        I::Item: Borrow<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>,
    {
        // TODO TEMPORARY: use FFT to encode polynomials in eval form
        // Remove these FFTs after we get KZG in eval form
        // https://github.com/EspressoSystems/jellyfish/issues/339
        let mut coeffs_vec: Vec<_> = coeffs.map(|c| *c.borrow()).collect();
        let pre_fft_len = coeffs_vec.len();
        self.eval_domain.ifft_in_place(&mut coeffs_vec);

        // sanity check: the fft did not resize coeffs.
        // If pre_fft_len != self.payload_chunk_size then we were not given the correct
        // number of coeffs. In that case coeffs.len() could be anything, so
        // there's nothing to sanity check.
        if pre_fft_len == self.payload_chunk_size {
            assert_eq!(coeffs_vec.len(), pre_fft_len);
        }

        DenseUVPolynomial::from_coefficients_vec(coeffs_vec)
    }

    fn poly_commits_hash<I>(poly_commits: I) -> VidResult<<Self as VidScheme>::Commit>
    where
        I: Iterator,
        I::Item: Borrow<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Commitment>,
    {
        let mut hasher = H::new();
        for poly_commit in poly_commits {
            poly_commit
                .borrow()
                .serialize_uncompressed(&mut hasher)
                .map_err(vid)?;
        }
        Ok(hasher.finalize())
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

    use crate::{
        merkle_tree::hasher::HasherNode,
        pcs::{checked_fft_size, prelude::UnivariateUniversalParams},
    };
    use ark_bls12_381::Bls12_381;
    use ark_std::{
        rand::{CryptoRng, RngCore},
        vec,
    };
    use sha2::Sha256;

    #[test]
    fn disperse_timer() {
        // run with 'print-trace' feature to see timer output
        let (payload_chunk_size, num_storage_nodes) = (256, 512);
        let mut rng = jf_utils::test_rng();
        let srs = init_srs(payload_chunk_size, &mut rng);
        let advz =
            Advz::<Bls12_381, Sha256>::new(payload_chunk_size, num_storage_nodes, srs).unwrap();
        let payload_random = init_random_payload(1 << 20, &mut rng);

        let _ = advz.disperse(&payload_random);
    }

    #[test]
    fn commit_only_timer() {
        // run with 'print-trace' feature to see timer output
        let (payload_chunk_size, num_storage_nodes) = (256, 512);
        let mut rng = jf_utils::test_rng();
        let srs = init_srs(payload_chunk_size, &mut rng);
        let advz =
            Advz::<Bls12_381, Sha256>::new(payload_chunk_size, num_storage_nodes, srs).unwrap();
        let payload_random = init_random_payload(1 << 20, &mut rng);

        let _ = advz.commit_only(&payload_random);
    }

    #[test]
    fn sad_path_verify_share_corrupt_share() {
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(&bytes_random).unwrap();
        let (shares, common, commit) = (disperse.shares, disperse.common, disperse.commit);

        for (i, share) in shares.iter().enumerate() {
            // missing share eval
            {
                let share_missing_eval = Share {
                    evals: share.evals[1..].to_vec(),
                    ..share.clone()
                };
                assert_arg_err(
                    advz.verify_share(&share_missing_eval, &common, &commit),
                    "1 missing share should be arg error",
                );
            }

            // corrupted share eval
            {
                let mut share_bad_eval = share.clone();
                share_bad_eval.evals[0].double_in_place();
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
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(&bytes_random).unwrap();
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
            corrupted.poly_commits[0] = <Bls12_381 as Pairing>::G1Affine::zero().into();
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
            corrupted.all_evals_digest =
                HasherNode::deserialize_uncompressed(digest_bytes.as_slice())
                    .expect("digest deserialization should succeed");
            corrupted
        };
        advz.verify_share(&shares[0], &common_1_digest_corruption, &commit)
            .unwrap()
            .expect_err("1 corrupt all_evals_digest should fail verification");
    }

    #[test]
    fn sad_path_verify_share_corrupt_share_and_commit() {
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(&bytes_random).unwrap();
        let (mut shares, mut common, commit) = (disperse.shares, disperse.common, disperse.commit);

        common.poly_commits.pop();
        shares[0].evals.pop();

        // equal nonzero lengths for common, share
        assert_arg_err(
            advz.verify_share(&shares[0], &common, &commit),
            "common inconsistent with commit should be arg error",
        );

        common.poly_commits.clear();
        shares[0].evals.clear();

        // zero length for common, share
        assert_arg_err(
            advz.verify_share(&shares[0], &common, &commit),
            "expect arg error for common inconsistent with commit",
        );
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
    pub(super) fn avdz_init() -> (Advz<Bls12_381, Sha256>, Vec<u8>) {
        let (payload_chunk_size, num_storage_nodes) = (4, 6);
        let mut rng = jf_utils::test_rng();
        let srs = init_srs(payload_chunk_size, &mut rng);
        let advz = Advz::new(payload_chunk_size, num_storage_nodes, srs).unwrap();
        let bytes_random = init_random_payload(4000, &mut rng);
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
        UnivariateKzgPCS::gen_srs_for_testing(rng, checked_fft_size(num_coeffs - 1).unwrap())
            .unwrap()
    }
}
