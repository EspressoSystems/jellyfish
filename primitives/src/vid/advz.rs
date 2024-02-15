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
        hasher::{HasherDigest, HasherMerkleTree, HasherNode},
        MerkleCommitment, MerkleTreeScheme,
    },
    pcs::{
        prelude::UnivariateKzgPCS, PolynomialCommitmentScheme, StructuredReferenceString,
        UnivariatePCS,
    },
    reed_solomon_code::reed_solomon_erasure_decode_rou,
};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    borrow::Borrow,
    end_timer,
    fmt::Debug,
    format,
    marker::PhantomData,
    ops::{Add, Mul},
    start_timer, vec,
    vec::Vec,
    Zero,
};
use bytes_to_field::{bytes_to_field, field_to_bytes};
use core::mem;
use derivative::Derivative;
use digest::crypto_common::Output;
use itertools::Itertools;
use jf_utils::canonical;
use serde::{Deserialize, Serialize};

mod bytes_to_field;
pub mod payload_prover;
pub mod precomputable;

/// The [ADVZ VID scheme](https://eprint.iacr.org/2021/1500), a concrete impl for [`VidScheme`].
///
/// - `E` is any [`Pairing`]
/// - `H` is a [`digest::Digest`]-compatible hash function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Advz<E, H>
where
    E: Pairing,
{
    payload_chunk_size: usize,
    num_storage_nodes: usize,
    multiplicity: usize,
    ck: KzgProverParam<E>,
    vk: KzgVerifierParam<E>,
    multi_open_domain: Radix2EvaluationDomain<KzgPoint<E>>,

    // TODO might be able to eliminate this field and instead use
    // `EvaluationDomain::reindex_by_subdomain()` on `multi_open_domain`
    // but that method consumes `other` and its doc is unclear.
    eval_domain: Radix2EvaluationDomain<KzgPoint<E>>,

    _pd: PhantomData<H>,
}

// [Nested associated type projection is overly conservative · Issue #38078 · rust-lang/rust](https://github.com/rust-lang/rust/issues/38078)
// I want to do this but I cant:
// type Kzg<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>;
// So instead I do this:
type KzgPolynomial<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Polynomial;
type KzgCommit<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Commitment;
type KzgPoint<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Point;
type KzgEval<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation;
type KzgProof<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Proof;
type KzgSrs<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS;
type KzgProverParam<E> = <<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS as StructuredReferenceString>::ProverParam;
type KzgVerifierParam<E> = <<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS as StructuredReferenceString>::VerifierParam;

type KzgEvalsMerkleTree<E, H> = HasherMerkleTree<H, Vec<KzgEval<E>>>;
type KzgEvalsMerkleTreeNode<E, H> = <KzgEvalsMerkleTree<E, H> as MerkleTreeScheme>::NodeValue;
type KzgEvalsMerkleTreeIndex<E, H> = <KzgEvalsMerkleTree<E, H> as MerkleTreeScheme>::Index;
type KzgEvalsMerkleTreeProof<E, H> =
    <KzgEvalsMerkleTree<E, H> as MerkleTreeScheme>::MembershipProof;

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
        payload_chunk_size: usize, // k
        num_storage_nodes: usize,  // n (code rate: r = k/n)
        multiplicity: usize,       // batch m chunks, keep the rate r = (m*k)/(m*n)
        srs: impl Borrow<KzgSrs<E>>,
    ) -> VidResult<Self> {
        // TODO support any degree, give multiple shares to nodes if needed
        // https://github.com/EspressoSystems/jellyfish/issues/393
        if num_storage_nodes < payload_chunk_size {
            return Err(VidError::Argument(format!(
                "payload_chunk_size {} exceeds num_storage_nodes {}",
                payload_chunk_size, num_storage_nodes
            )));
        }

        if !(1..=16).contains(&multiplicity) || !multiplicity.is_power_of_two() {
            return Err(VidError::Argument(format!(
                "multiplicity {} not allowed",
                multiplicity
            )));
        }

        // Later we will convert to u32.
        // Better to know now whether that conversion will succeed.
        if u32::try_from(num_storage_nodes).is_err() {
            return Err(VidError::Argument(format!(
                "num_storage nodes {} should be convertible to u32",
                num_storage_nodes
            )));
        }
        if u32::try_from(multiplicity).is_err() {
            return Err(VidError::Argument(format!(
                "multiplicity {} should be convertible to u32",
                multiplicity
            )));
        }

        // erasure code params
        let chunk_size = multiplicity * payload_chunk_size; // message length m
        let code_word_size = multiplicity * num_storage_nodes; // code word length n
        let poly_degree = chunk_size - 1;

        let (ck, vk) = UnivariateKzgPCS::trim_fft_size(srs, poly_degree).map_err(vid)?;
        let multi_open_domain =
            UnivariateKzgPCS::<E>::multi_open_rou_eval_domain(poly_degree, code_word_size)
                .map_err(vid)?;
        let eval_domain = Radix2EvaluationDomain::new(chunk_size).ok_or_else(|| {
            VidError::Internal(anyhow::anyhow!(
                "fail to construct doman of size {}",
                chunk_size
            ))
        })?;

        // TODO TEMPORARY: enforce power-of-2 chunk size
        // Remove this restriction after we get KZG in eval form
        // https://github.com/EspressoSystems/jellyfish/issues/339
        if chunk_size != eval_domain.size() {
            return Err(VidError::Argument(format!(
                "payload_chunk_size {} currently unsupported, round to {} instead",
                chunk_size,
                eval_domain.size()
            )));
        }

        Ok(Self {
            payload_chunk_size,
            num_storage_nodes,
            multiplicity,
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
#[serde(bound = "Output<H>: Serialize + for<'a> Deserialize<'a>")]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    Eq(bound = ""),
    Hash(bound = ""),
    PartialEq(bound = "")
)]
pub struct Share<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    index: usize,

    #[serde(with = "canonical")]
    evals: Vec<KzgEval<E>>,

    #[serde(with = "canonical")]
    // aggretate_proofs.len() equals self.multiplicity
    // TODO further aggregate into a single KZG proof.
    aggregate_proofs: Vec<KzgProof<E>>,

    evals_proof: KzgEvalsMerkleTreeProof<E, H>,
}

/// The [`VidScheme::Common`] type for [`Advz`].
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative, Deserialize, Serialize)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    Eq(bound = ""),
    Hash(bound = ""),
    PartialEq(bound = "")
)]
pub struct Common<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    #[serde(with = "canonical")]
    poly_commits: Vec<KzgCommit<E>>,

    #[serde(with = "canonical")]
    all_evals_digest: KzgEvalsMerkleTreeNode<E, H>,

    payload_byte_len: u32,
    num_storage_nodes: u32,
    multiplicity: u32,
}

impl<E, H> VidScheme for Advz<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    // use HasherNode<H> instead of Output<H> to easily meet trait bounds
    type Commit = HasherNode<H>;

    type Share = Share<E, H>;
    type Common = Common<E, H>;

    fn commit_only<B>(&self, payload: B) -> VidResult<Self::Commit>
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
        let poly_commits = UnivariateKzgPCS::batch_commit(&self.ck, &polys).map_err(vid)?;
        Self::derive_commit(&poly_commits, payload.len(), self.num_storage_nodes)
    }

    fn disperse<B>(&self, payload: B) -> VidResult<VidDisperse<Self>>
    where
        B: AsRef<[u8]>,
    {
        let payload = payload.as_ref();
        let payload_byte_len = payload.len().try_into().map_err(vid)?;
        let disperse_time = start_timer!(|| format!(
            "VID disperse {} payload bytes to {} nodes",
            payload_byte_len, self.num_storage_nodes
        ));
        let chunk_size = self.multiplicity * self.payload_chunk_size;
        let code_word_size = self.multiplicity * self.num_storage_nodes;

        // partition payload into polynomial coefficients
        // and count `elems_len` for later
        let bytes_to_polys_time = start_timer!(|| "encode payload bytes into polynomials");
        let elems_iter = bytes_to_field::<_, KzgEval<E>>(payload);
        let polys: Vec<_> = elems_iter
            .chunks(chunk_size)
            .into_iter()
            .map(|evals_iter| self.polynomial(evals_iter))
            .collect();
        end_timer!(bytes_to_polys_time);

        // evaluate polynomials
        let all_storage_node_evals_timer = start_timer!(|| format!(
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

        let common_timer = start_timer!(|| format!("compute {} KZG commitments", polys.len()));
        let common = Common {
            poly_commits: UnivariateKzgPCS::batch_commit(&self.ck, &polys).map_err(vid)?,
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

        let agg_proofs_timer = start_timer!(|| format!(
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
        let mut shares = Vec::with_capacity(self.num_storage_nodes);
        let mut evals = Vec::with_capacity(polys.len() * self.multiplicity);
        let mut proofs = Vec::with_capacity(self.multiplicity);
        let mut index = 0;
        for i in 0..code_word_size {
            evals.extend(all_storage_node_evals[i].iter());
            proofs.push(aggregate_proofs[i].clone());
            if (i + 1) % self.multiplicity == 0 {
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
                index += 1;
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

    fn verify_share(
        &self,
        share: &Self::Share,
        common: &Self::Common,
        commit: &Self::Commit,
    ) -> VidResult<Result<(), ()>> {
        // check arguments
        let multiplicity: usize = common.multiplicity.try_into().map_err(vid)?;
        if share.evals.len() / multiplicity != common.poly_commits.len() {
            return Err(VidError::Argument(format!(
                "(share eval, common poly commit) lengths differ ({},{})",
                share.evals.len() / multiplicity,
                common.poly_commits.len()
            )));
        }

        let num_storage_nodes: u32 = self.num_storage_nodes.try_into().map_err(vid)?; // pacify cargo check --target wasm32-unknown-unknown --no-default-features
        if common.num_storage_nodes != num_storage_nodes {
            return Err(VidError::Argument(format!(
                "common num_storage_nodes differs from self ({},{})",
                common.num_storage_nodes, self.num_storage_nodes
            )));
        }

        let polys_len = common.poly_commits.len();

        if share.index >= self.num_storage_nodes {
            return Ok(Err(())); // not an arg error
        }

        Self::is_consistent(commit, common)?;

        // verify eval proof
        // TODO: check all indices that represents the shares
        if KzgEvalsMerkleTree::<E, H>::verify(
            common.all_evals_digest,
            &KzgEvalsMerkleTreeIndex::<E, H>::from(share.index as u64),
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
        let aggregate_poly_commit = KzgCommit::<E>::from(
            polynomial_eval(
                common
                    .poly_commits
                    .iter()
                    .map(|x| CurveMultiplier(x.as_ref())),
                pseudorandom_scalar,
            )
            .into(),
        );

        // verify aggregate proof
        (0..self.multiplicity)
            .map(|i| {
                let aggregate_eval = polynomial_eval(
                    share.evals[i * polys_len..(i + 1) * polys_len]
                        .iter()
                        .map(FieldMultiplier),
                    pseudorandom_scalar,
                );
                Ok(UnivariateKzgPCS::verify(
                    &self.vk,
                    &aggregate_poly_commit,
                    &self
                        .multi_open_domain
                        .element((share.index * multiplicity) + i),
                    &aggregate_eval,
                    &share.aggregate_proofs[i],
                )
                .map_err(vid)?
                .then_some(())
                .ok_or(()))
            })
            .collect()
    }

    fn recover_payload(&self, shares: &[Self::Share], common: &Self::Common) -> VidResult<Vec<u8>> {
        if shares.len() < self.payload_chunk_size {
            return Err(VidError::Argument(format!(
                "not enough shares {}, expected at least {}",
                shares.len(),
                self.payload_chunk_size
            )));
        }
        let num_storage_nodes: u32 = self.num_storage_nodes.try_into().map_err(vid)?; // pacify cargo check --target wasm32-unknown-unknown --no-default-features
        if common.num_storage_nodes != num_storage_nodes {
            return Err(VidError::Argument(format!(
                "common num_storage_nodes differs from self ({},{})",
                common.num_storage_nodes, self.num_storage_nodes
            )));
        }

        // all shares must have equal evals len
        let num_evals = shares
            .first()
            .ok_or_else(|| VidError::Argument("shares is empty".into()))?
            .evals
            .len();
        if let Some((index, share)) = shares
            .iter()
            .enumerate()
            .find(|(_, s)| s.evals.len() != num_evals)
        {
            return Err(VidError::Argument(format!(
                "shares do not have equal evals lengths: share {} len {}, share {} len {}",
                0,
                num_evals,
                index,
                share.evals.len()
            )));
        }
        if num_evals != self.multiplicity * common.poly_commits.len() {
            return Err(VidError::Argument(format!(
                "num_evals should be (multiplicity * poly_commits): {} but is instead: {}",
                self.multiplicity * common.poly_commits.len(),
                num_evals,
            )));
        }
        let chunk_size = self.multiplicity * self.payload_chunk_size;
        let num_polys = num_evals / self.multiplicity;

        let elems_capacity = num_polys * chunk_size;
        let mut elems = Vec::with_capacity(elems_capacity);

        let mut evals = Vec::with_capacity(num_evals);
        for p in 0..num_polys {
            for share in shares {
                // extract all evaluations for polynomial p from the share
                for m in 0..self.multiplicity {
                    evals.push((
                        (share.index * self.multiplicity) + m,
                        share.evals[(m * num_polys) + p],
                    ))
                }
            }
            let mut coeffs = reed_solomon_erasure_decode_rou(
                mem::take(&mut evals),
                chunk_size,
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
        payload.truncate(common.payload_byte_len.try_into().map_err(vid)?);
        Ok(payload)
    }

    fn is_consistent(commit: &Self::Commit, common: &Self::Common) -> VidResult<()> {
        if *commit
            != Advz::<E, H>::derive_commit(
                &common.poly_commits,
                common.payload_byte_len,
                common.num_storage_nodes,
            )?
        {
            return Err(VidError::Argument(
                "common inconsistent with commit".to_string(),
            ));
        }
        Ok(())
    }

    fn get_payload_byte_len(common: &Self::Common) -> usize {
        common
            .payload_byte_len
            .try_into()
            .expect("u32 should be convertible to usize")
    }

    fn get_num_storage_nodes(common: &Self::Common) -> usize {
        common
            .num_storage_nodes
            .try_into()
            .expect("u32 should be convertible to usize")
    }

    fn get_multiplicity(common: &Self::Common) -> usize {
        common
            .multiplicity
            .try_into()
            .expect("u32 should be convertible to usize")
    }
}

impl<E, H> Advz<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    fn pseudorandom_scalar(
        common: &<Self as VidScheme>::Common,
        commit: &<Self as VidScheme>::Commit,
    ) -> VidResult<KzgEval<E>> {
        let mut hasher = H::new();
        commit.serialize_uncompressed(&mut hasher).map_err(vid)?;
        common
            .all_evals_digest
            .serialize_uncompressed(&mut hasher)
            .map_err(vid)?;

        // Notes on hash-to-field:
        // - Can't use `Field::from_random_bytes` because it's fallible. (In what sense
        //   is it from "random" bytes?!). This despite the docs explicitly say: "This
        //   function is primarily intended for sampling random field elements from a
        //   hash-function or RNG output."
        // - We could use `ark_ff::fields::field_hashers::HashToField` but that forces
        //   us to add additional trait bounds `Clone + Default + DynDigest` everywhere.
        //   Also, `HashToField` does not expose an incremental API (ie. `update`) so we
        //   would need to use an ordinary hasher and pipe `hasher.finalize()` through
        //   `hash_to_field`. (Ugh!)
        // - We don't need the resulting field element to be cryptographically
        //   indistinguishable from uniformly random. We only need it to be
        //   unpredictable. So it suffices to use
        Ok(PrimeField::from_le_bytes_mod_order(&hasher.finalize()))
    }

    fn polynomial<I>(&self, coeffs: I) -> KzgPolynomial<E>
    where
        I: Iterator,
        I::Item: Borrow<KzgEval<E>>,
    {
        // TODO TEMPORARY: use FFT to encode polynomials in eval form
        // Remove these FFTs after we get KZG in eval form
        // https://github.com/EspressoSystems/jellyfish/issues/339
        let mut coeffs_vec: Vec<_> = coeffs.map(|c| *c.borrow()).collect();
        let pre_fft_len = coeffs_vec.len();
        self.eval_domain.ifft_in_place(&mut coeffs_vec);

        // sanity check: the fft did not resize coeffs.
        // If pre_fft_len != self.payload_chunk_size * self.multiplicity
        // then we were not given the correct number of coeffs. In that case
        // coeffs.len() could be anything, so there's nothing to sanity check.
        if pre_fft_len == self.payload_chunk_size * self.multiplicity {
            assert_eq!(coeffs_vec.len(), pre_fft_len);
        }

        DenseUVPolynomial::from_coefficients_vec(coeffs_vec)
    }

    /// Derive a commitment from whatever data is needed.
    ///
    /// Generic types `T`, `U` allow caller to pass `usize` or anything else.
    /// Yes, Rust really wants these horrible trait bounds on
    /// `<T as TryInto<u32>>::Error`.
    fn derive_commit<T, U>(
        poly_commits: &[KzgCommit<E>],
        payload_byte_len: T,
        num_storage_nodes: U,
    ) -> VidResult<<Self as VidScheme>::Commit>
    where
        T: TryInto<u32>,
        <T as TryInto<u32>>::Error: ark_std::fmt::Display + Debug + Send + Sync + 'static,
        U: TryInto<u32>,
        <U as TryInto<u32>>::Error: ark_std::fmt::Display + Debug + Send + Sync + 'static,
    {
        let payload_byte_len: u32 = payload_byte_len.try_into().map_err(vid)?;
        let num_storage_nodes: u32 = num_storage_nodes.try_into().map_err(vid)?;
        let mut hasher = H::new();
        payload_byte_len
            .serialize_uncompressed(&mut hasher)
            .map_err(vid)?;
        num_storage_nodes
            .serialize_uncompressed(&mut hasher)
            .map_err(vid)?;
        for poly_commit in poly_commits {
            poly_commit
                .serialize_uncompressed(&mut hasher)
                .map_err(vid)?;
        }
        Ok(hasher.finalize().into())
    }
}

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

    #[ignore]
    #[test]
    fn disperse_timer() {
        // run with 'print-trace' feature to see timer output
        let (payload_chunk_size, num_storage_nodes) = (256, 512);
        let mut rng = jf_utils::test_rng();
        let srs = init_srs(payload_chunk_size, &mut rng);
        let advz =
            Advz::<Bls12_381, Sha256>::new(payload_chunk_size, num_storage_nodes, 1, srs).unwrap();
        let payload_random = init_random_payload(1 << 20, &mut rng);

        let _ = advz.disperse(payload_random);
    }

    #[ignore]
    #[test]
    fn commit_only_timer() {
        // run with 'print-trace' feature to see timer output
        let (payload_chunk_size, num_storage_nodes) = (256, 512);
        let mut rng = jf_utils::test_rng();
        let srs = init_srs(payload_chunk_size, &mut rng);
        let advz =
            Advz::<Bls12_381, Sha256>::new(payload_chunk_size, num_storage_nodes, 1, srs).unwrap();
        let payload_random = init_random_payload(1 << 20, &mut rng);

        let _ = advz.commit_only(payload_random);
    }

    #[test]
    fn sad_path_verify_share_corrupt_share() {
        let (advz, bytes_random) = avdz_init();
        let disperse = advz.disperse(bytes_random).unwrap();
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
        let disperse = advz.disperse(bytes_random).unwrap();
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
            assert_arg_err(
                advz.recover_payload(&shares_missing_evals, &common),
                format!(
                    "shares contain {} but expected {}",
                    shares_missing_evals[0].evals.len(),
                    &common.poly_commits.len()
                )
                .as_str(),
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
        let advz = Advz::new(payload_chunk_size, num_storage_nodes, 1, srs).unwrap();
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
