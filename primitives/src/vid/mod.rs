// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait and implementation for a Verifiable Information Retrieval (VID).
/// See <https://arxiv.org/abs/2111.12323> section 1.3--1.4 for intro to VID semantics.
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{error::Error, fmt::Debug, string::String, vec::Vec};
use displaydoc::Display;

pub mod advz;

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
