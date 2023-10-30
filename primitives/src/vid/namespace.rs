// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait for namespace functionality in Verifiable Information Retrieval (VID).

use super::{VidResult, VidScheme};

/// Namespace functionality for [`VidScheme`].
pub trait Namespacer: VidScheme {
    /// data proof
    type DataProof;

    /// Compute a proof for `payload` for data index range `start..start+len-1`.
    ///
    /// See TODO in [`namespace_verify`] on `payload`.
    fn data_proof(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
    ) -> VidResult<Self::DataProof>;

    /// Verify a proof for `payload` for data index range `start..start+len-1`.
    ///
    /// See TODO in [`namespace_verify`] on `payload`.
    fn data_verify(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
        commit: &Self::Commit,
        common: &Self::Common,
        proof: &Self::DataProof,
    ) -> VidResult<Result<(), ()>>;

    /// Verify the `payload` namespace indexed by `namespace_index` against
    /// `commit`, `common`.
    ///
    /// TODO: We prefer not to include the whole `payload`. But the namespace
    /// proof needs a few payload bytes from outside the namespace. In the
    /// future `payload` should be replaced by a payload subset that includes
    /// only the bytes needed to verify a namespace.
    fn namespace_verify(
        &self,
        payload: &Self::Payload,
        namespace_index: usize,
        commit: &Self::Commit,
        common: &Self::Common,
    ) -> VidResult<Result<(), ()>>;
}
