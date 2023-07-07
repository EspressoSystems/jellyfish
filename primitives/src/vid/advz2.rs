//! Implementation of Verifiable Information Dispersal (VID) from <https://eprint.iacr.org/2021/1500>.
//!
//! `advz` named for the authors Alhaddad-Duan-Varia-Zhang.
//!
//!
#![allow(dead_code)] // TODO remove this
use super::{vid, VidError, VidPayload, VidResult};
use crate::{
    merkle_tree::{
        hasher::{HasherDigest, HasherMerkleTree},
        MerkleTreeScheme,
    },
    pcs::{
        prelude::UnivariateKzgPCS, PolynomialCommitmentScheme, StructuredReferenceString,
        UnivariatePCS,
    },
};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, format, marker::PhantomData, vec::Vec};
use derivative::Derivative;
use digest::crypto_common::Output;
use jf_utils::{bytes_to_field_elements, canonical};
use serde::{Deserialize, Serialize};

type Srs<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS;
type ProverParam<E> = <<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS as StructuredReferenceString>::ProverParam;
type VerifierParam<E> = <<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::SRS as StructuredReferenceString>::VerifierParam;
type PolyEval<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation;
type KzgProof<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Proof;
type KzgCommit<E> = <UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Commitment;
type EvalsMerkleTree<E, H> = HasherMerkleTree<H, Vec<PolyEval<E>>>;
type EvalsMerkleProof<E, H> = <EvalsMerkleTree<E, H> as MerkleTreeScheme>::MembershipProof;
type EvalsMerkleRoot<E, H> = <EvalsMerkleTree<E, H> as MerkleTreeScheme>::NodeValue;

/// The [ADVZ VID scheme](https://eprint.iacr.org/2021/1500), a concrete impl for [`VidParam`].
///
/// - `H` is any [`Digest`]-compatible hash function
/// - `E` is any [`Pairing`]
///
/// TODO(Gus): Simpler generic params E,H as compared to [`GenericAdvz`].
///
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdvzParams<E>
where
    E: Pairing,
{
    payload_chunk_size: usize,
    num_storage_nodes: usize,
    ck: ProverParam<E>,
    vk: VerifierParam<E>,
}

/// TODO rustdoc
pub struct AdvzPayload<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    txs: Vec<Vec<PolyEval<E>>>,
    params: <Self as VidPayload>::Params,
    _phantom_h: PhantomData<H>,
}

impl<E> AdvzParams<E>
where
    E: Pairing,
{
    /// Return a new instance of `Self`.
    ///
    /// # Errors
    /// Return [`VidError::Argument`] if `num_storage_nodes < payload_chunk_size`.
    pub fn new(
        payload_chunk_size: usize,
        num_storage_nodes: usize,
        srs: impl Borrow<Srs<E>>,
    ) -> VidResult<Self> {
        if num_storage_nodes < payload_chunk_size {
            return Err(VidError::Argument(format!(
                "payload_chunk_size {} exceeds num_storage_nodes {}",
                payload_chunk_size, num_storage_nodes
            )));
        }
        let (ck, vk) =
            UnivariateKzgPCS::<E>::trim_fft_size(srs, payload_chunk_size).map_err(vid)?;
        Ok(Self {
            payload_chunk_size,
            num_storage_nodes,
            ck,
            vk,
        })
    }
}

/// The [`VidScheme::StorageShare`] type for [`Advz`].
#[derive(Derivative, Deserialize, Serialize)]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(Clone, Debug)]
pub struct Share<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    index: usize,

    #[serde(with = "canonical")]
    evals: Vec<PolyEval<E>>,

    #[serde(with = "canonical")]
    aggregate_proof: KzgProof<E>,

    evals_proof: EvalsMerkleProof<E, H>,
}

/// The [`VidScheme::StorageCommon`] type for [`Advz`].
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative, Deserialize, Serialize)]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(Clone, Debug, Default, Eq, PartialEq)]
pub struct Common<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    #[serde(with = "canonical")]
    poly_commits: Vec<KzgCommit<E>>,

    #[serde(with = "canonical")]
    all_evals_digest: EvalsMerkleRoot<E, H>,
}

impl<E, H> VidPayload for AdvzPayload<E, H>
where
    E: Pairing,
    H: HasherDigest,
{
    type Params = AdvzParams<E>;
    type Commitment = Output<H>;
    type StorageCommon = Common<E, H>;
    type StorageShare = Share<E, H>;

    type PayloadProof = ();

    type TxProof = ();

    fn from_txs<I>(params: Self::Params, txs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<[u8]>,
    {
        let txs = txs.into_iter().map(bytes_to_field_elements).collect();

        Self {
            txs,
            params,
            _phantom_h: PhantomData,
        }
    }

    fn txs(&self) -> Vec<Vec<u8>> {
        todo!()
    }

    fn payload_proof(&self) -> Self::PayloadProof {
        todo!()
    }

    fn verify_payload_proof(&self, _proof: &Self::PayloadProof) -> VidResult<Result<(), ()>> {
        todo!()
    }

    fn tx(&self, _index: usize) -> Vec<u8> {
        todo!()
    }

    fn tx_proof(&self, _index: usize) -> Self::TxProof {
        todo!()
    }

    fn verify_tx_proof(
        &self,
        _tx: impl AsRef<[u8]>,
        _proof: &Self::TxProof,
    ) -> VidResult<Result<(), ()>> {
        todo!()
    }

    fn commit(&self) -> Self::Commitment {
        todo!()
    }

    fn dispersal_data(&self) -> VidResult<(Vec<Self::StorageShare>, Self::StorageCommon)> {
        todo!()
    }

    fn verify_share(
        _params: &Self::Params,
        _share: &Self::StorageShare,
        _common: &Self::StorageCommon,
    ) -> VidResult<Result<(), ()>> {
        todo!()
    }

    fn from_shares<I>(
        _params: &Self::Params,
        _shares: I,
        _common: &Self::StorageCommon,
    ) -> VidResult<Self>
    where
        I: IntoIterator,
        I::Item: Borrow<Self::StorageShare>,
    {
        todo!()
    }
}
