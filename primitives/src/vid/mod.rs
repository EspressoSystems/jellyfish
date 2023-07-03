//! Trait and implementation for a Verifiable Information Retrieval (VID).
//!
/// See <https://arxiv.org/abs/2111.12323> section 1.3--1.4 for intro to VID semantics.
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std as std; // needed for thiserror crate
use ark_std::{fmt::Debug, string::String, vec::Vec};

pub mod advz;

/// The error type for `VidScheme` methods.
///
/// # Use of both `thiserror` and `anyhow`
/// This library is both a producer and consumer of errors.
/// It provides a custom error `VidError` for consumers of this library, aided by `thiserror`.
/// Moreover, it is a consumer of errors from lower-level libraries, aided by `anyhow`.
/// We have yet to settle on a preferred error handling philosophy.
#[derive(thiserror::Error, Debug)]
pub enum VidError {
    /// Caller provided an invalid argument
    #[error("invalid arguments: {0}")]
    Argument(String),
    /// Internal error
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// Convenience [`Result`] wrapper for [`VidError`].
pub type VidResult<T> = Result<T, VidError>;

/// VID: Verifiable Information Dispersal
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
