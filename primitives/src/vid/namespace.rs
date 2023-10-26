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

    /// Compute a proof for `payload` for data index range `start..start+len`.
    fn data_proof(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
    ) -> VidResult<Self::DataProof>;

    /// Verify a proof for `payload` for data index range `start..start+len`.
    fn data_verify(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
        proof: &Self::DataProof,
    ) -> VidResult<Result<(), ()>>;

    /// Verify the `payload` namespace indexed by `namespace_index` against
    /// `commit`, `common`.
    ///
    /// TODO: Seems ugly to include `common` in this API but [`advz`] impl needs
    /// it.
    fn namespace_verify(
        &self,
        payload: &Self::Payload,
        namespace_index: usize,
        commit: &Self::Commit,
        common: &Self::Common,
    ) -> VidResult<Result<(), ()>>;
}
