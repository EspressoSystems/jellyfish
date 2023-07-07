//! Trait and implementation for a Verifiable Information Retrieval (VID).
/// See <https://arxiv.org/abs/2111.12323> section 1.3--1.4 for intro to VID semantics.
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, error::Error, fmt::Debug, string::String, vec::Vec};
use displaydoc::Display;

pub mod advz;
pub mod advz2;

/// The error type for `VidScheme` methods.
#[derive(Display, Debug)]
pub enum VidError {
    /// invalid args: {0}
    Argument(String),
    /// internal error: {0}
    Internal(anyhow::Error),
}

impl Error for VidError {}

/// Convenience wrapper to convert any error into a [`VidError`].
///
/// Private fn so as not to expose error conversion API outside this crate
/// as per [stackoverflow](https://stackoverflow.com/a/70057677).
///
/// # No-std support
/// `no_std` mode requires `.map_err(vid)` to convert from a non-`anyhow` error
/// as per [`anyhow` docs](https://docs.rs/anyhow/latest/anyhow/index.html#no-std-support),
fn vid<E>(e: E) -> VidError
where
    E: ark_std::fmt::Display + Debug + Send + Sync + 'static,
{
    VidError::Internal(anyhow::anyhow!(e))
}

/// Convenience [`Result`] wrapper for [`VidError`].
pub type VidResult<T> = Result<T, VidError>;

/// VID: Verifiable Information Dispersal
/// TODO(Gus): Deprecate this trait in favour of the incremental API?
pub trait VidScheme {
    /// Payload commitment.
    type Commitment: Clone + Debug + Eq + PartialEq + Sync; // TODO https://github.com/EspressoSystems/jellyfish/issues/253

    /// Share-specific data sent to a storage node.
    type StorageShare: Clone + Debug + Sync; // TODO https://github.com/EspressoSystems/jellyfish/issues/253

    /// Common data sent to all storage nodes.
    type StorageCommon: CanonicalSerialize + CanonicalDeserialize + Clone + Eq + PartialEq + Sync; // TODO https://github.com/EspressoSystems/jellyfish/issues/253

    /// Compute a payload commitment.
    fn commit(&self, payload: &[u8]) -> VidResult<Self::Commitment>;

    /// Compute shares to send to the storage nodes
    fn dispersal_data(
        &self,
        payload: &[u8],
    ) -> VidResult<(Vec<Self::StorageShare>, Self::StorageCommon)>;

    /// Verify a share. Used by both storage node and retrieval client.
    /// Why is return type a nested `Result`? See <https://sled.rs/errors>
    /// Returns:
    /// - VidResult::Err in case of actual error
    /// - VidResult::Ok(Result::Err) if verification fails
    /// - VidResult::Ok(Result::Ok) if verification succeeds
    fn verify_share(
        &self,
        share: &Self::StorageShare,
        common: &Self::StorageCommon,
    ) -> VidResult<Result<(), ()>>;

    /// Recover payload from shares.
    /// Do not verify shares or check recovered payload against anything.
    fn recover_payload(
        &self,
        shares: &[Self::StorageShare],
        common: &Self::StorageCommon,
    ) -> VidResult<Vec<u8>>;
}

/// TODO: KEEP IT SIMPLE: FOR NOW, DON'T SPLIT `VidBlock` FROM `VidPayload`. `VidPayload` SOULD BE NON-INCREMENTAL.
/// TODO: Should this be lightweight computation only?
/// eg. bytes-to-field is ok. But FFT, KZG commits, etc is bad.
/// If so then split a `VidBlock` trait for the heavy computation.
///
/// Why `Sized`? Because `from_shares` return type is `VidResult<Self>` instead of `Self`.
/// Why does this matter? Rust language bug: https://stackoverflow.com/questions/54465400/why-does-returning-self-in-trait-work-but-returning-optionself-requires
pub trait VidPayload: Sized {
    /// VID public parameters.
    type Params;

    /// payload proof
    type PayloadProof;

    /// individual tx proof
    type TxProof;

    /// Construct a new `VidPayload` from an iterator over serialized txs.
    ///
    /// Heavy computation...
    fn from_txs<I>(params: Self::Params, txs: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<[u8]>;

    /// Return an iterator over the list of serialized txs in this payload.
    // fn txs(&self) -> Self::TxIter;
    fn txs(&self) -> Vec<Vec<u8>>; // TODO return an iterator instead

    /// Return a proof for this payload.
    fn payload_proof(&self) -> Self::PayloadProof;

    /// Verify a payload proof against this payload.
    fn verify_payload_proof(&self, proof: &Self::PayloadProof) -> VidResult<Result<(), ()>>;

    /// Return a serialized tx in this payload.
    fn tx(&self, index: usize) -> Vec<u8>;

    /// Return a proof for a tx in this payload.
    fn tx_proof(&self, index: usize) -> Self::TxProof;

    /// Verify a tx proof against this payload.
    ///
    /// TODO doctest: verify_tx_proof(tx(i), tx_proof(i)) == true
    fn verify_tx_proof(
        &self,
        tx: impl AsRef<[u8]>,
        proof: &Self::TxProof,
    ) -> VidResult<Result<(), ()>>;

    /// Needed for [`txs`] method because https://rust-lang.github.io/impl-trait-initiative/
    /// TODO(Gus): make this a nested iterator over `u8`?
    // type TxIter: Iterator<Item = Vec<u8>>;

    // FROM HERE: PORTED FROM `VidScheme`

    /// Share-specific data sent to a storage node.
    type StorageShare;

    /// Common data sent to all storage nodes.
    ///
    /// TODO: rename to `Header`
    /// New method `header()` return header
    type StorageCommon;

    /// Payload commitment.
    type Commitment;

    /// Return the payload commitment.
    fn commit(&self) -> Self::Commitment;

    /// Compute shares to send to the storage nodes.
    ///
    /// TODO: rename to `shares()`, return only iterator over `StorageShare`
    fn dispersal_data(&self) -> VidResult<(Vec<Self::StorageShare>, Self::StorageCommon)>;

    /// Verify a share. Used by both storage node and retrieval client.
    ///
    /// Why is return type a nested `Result`? See <https://sled.rs/errors>
    /// Returns:
    /// - VidResult::Err in case of actual error
    /// - VidResult::Ok(Result::Err) if verification fails
    /// - VidResult::Ok(Result::Ok) if verification succeeds
    fn verify_share(
        params: &Self::Params,
        share: &Self::StorageShare,
        common: &Self::StorageCommon,
    ) -> VidResult<Result<(), ()>>;

    /// Recover payload from shares.
    ///
    /// Do not verify shares or check recovered payload against anything.
    ///
    /// TODO(Gus):
    /// - Should return either
    ///   1. A `VidPayload` (need an assoc type for it), or
    ///   2. A `Vec<Vec<u8>>` of serialized txs.
    ///   `VidPayload` might do a lot of work that the caller might not want.
    /// - How does the user verify the recovered payload against the commitment?
    ///   (Is it bundled into `common`?)
    /// - Should we split a new `VidHeader` from `VidPayload`?
    ///   Then `VidPayload` could do only bytes-to-field encoding;
    ///   all heavy computation can be done in `VidHeader`.
    fn from_shares<I>(
        params: &Self::Params,
        shares: I,
        common: &Self::StorageCommon,
    ) -> VidResult<Self>
    where
        I: IntoIterator,
        I::Item: Borrow<Self::StorageShare>;
}
