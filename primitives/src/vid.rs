// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait and implementation for a Verifiable Information Retrieval (VID).
/// See <https://arxiv.org/abs/2111.12323> section 1.3--1.4 for intro to VID semantics.
use ark_std::{
    error::Error,
    fmt::{Debug, Display},
    hash::Hash,
    string::String,
    vec::Vec,
};
use displaydoc::Display;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tagged_base64::TaggedBase64;

/// VID: Verifiable Information Dispersal
pub trait VidScheme {
    /// Payload commitment.
    type Commit: Clone
        + Debug
        + Display
        + DeserializeOwned
        + Eq
        + PartialEq
        + Hash
        + Serialize
        + Sync
        + for<'a> TryFrom<&'a TaggedBase64>
        + Into<TaggedBase64>; // TODO https://github.com/EspressoSystems/jellyfish/issues/253

    /// Share-specific data sent to a storage node.
    type Share: Clone + Debug + DeserializeOwned + Eq + PartialEq + Hash + Serialize + Sync; // TODO https://github.com/EspressoSystems/jellyfish/issues/253

    /// Common data sent to all storage nodes.
    type Common: Clone + Debug + DeserializeOwned + Eq + PartialEq + Hash + Serialize + Sync; // TODO https://github.com/EspressoSystems/jellyfish/issues/253

    /// Compute a payload commitment
    fn commit_only<B>(&self, payload: B) -> VidResult<Self::Commit>
    where
        B: AsRef<[u8]>;

    /// Compute shares to send to the storage nodes
    fn disperse<B>(&self, payload: B) -> VidResult<VidDisperse<Self>>
    where
        B: AsRef<[u8]>;

    /// Verify a share. Used by both storage node and retrieval client.
    /// Why is return type a nested `Result`? See <https://sled.rs/errors>
    /// Returns:
    /// - VidResult::Err in case of actual error
    /// - VidResult::Ok(Result::Err) if verification fails
    /// - VidResult::Ok(Result::Ok) if verification succeeds
    fn verify_share(
        &self,
        share: &Self::Share,
        common: &Self::Common,
        commit: &Self::Commit,
    ) -> VidResult<Result<(), ()>>;

    /// Recover payload from shares.
    /// Do not verify shares or check recovered payload against anything.
    fn recover_payload(&self, shares: &[Self::Share], common: &Self::Common) -> VidResult<Vec<u8>>;

    /// Check that a [`VidScheme::Common`] is consistent with a
    /// [`VidScheme::Commit`].
    ///
    /// TODO conform to nested result pattern like [`VidScheme::verify_share`].
    /// Unfortunately, `VidResult<()>` is more user-friently.
    fn is_consistent(commit: &Self::Commit, common: &Self::Common) -> VidResult<()>;

    /// Extract the payload byte length data from a [`VidScheme::Common`].
    fn get_payload_byte_len(common: &Self::Common) -> usize;

    /// Extract the number of storage nodes from a [`VidScheme::Common`].
    fn get_num_storage_nodes(common: &Self::Common) -> usize;
}

/// Convenience struct to aggregate disperse data.
///
/// Return type for [`VidScheme::disperse`].
///
/// # Why the `?Sized` bound?
/// Rust hates you: <https://stackoverflow.com/a/54465962>
#[derive(Derivative, Deserialize, Serialize)]
#[serde(bound = "V::Share: Serialize + for<'a> Deserialize<'a>,
     V::Common: Serialize + for<'a> Deserialize<'a>,
     V::Commit: Serialize + for<'a> Deserialize<'a>,")]
// Somehow these bizarre bounds suffice for downstream derivations
#[derivative(
    Clone(bound = ""),
    Debug(bound = "V::Share: Debug, V::Common: Debug, V::Commit: Debug"),
    Eq(bound = ""),
    Hash(bound = "V::Share: Hash, V::Common: Hash, V::Commit: Hash"),
    PartialEq(bound = "")
)]
pub struct VidDisperse<V: VidScheme + ?Sized> {
    /// VID disperse shares to send to the storage nodes.
    pub shares: Vec<V::Share>,
    /// VID common data to send to all storage nodes.
    pub common: V::Common,
    /// VID payload commitment.
    pub commit: V::Commit,
}

pub mod payload_prover;

pub mod advz; // instantiation of `VidScheme`

// BOILERPLATE: error handling

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
