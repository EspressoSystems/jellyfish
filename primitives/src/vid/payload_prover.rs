// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait for additional functionality in Verifiable Information Retrieval (VID)
//! to make and verify a proof of correctness of an arbitrary sub-slice of data
//! from a payload.

use super::{VidResult, VidScheme};
use ark_std::ops::Range;

/// Payload proof functionality for [`VidScheme`].
pub trait PayloadProver<PROOF>: VidScheme {
    /// Compute a proof for a sub-slice of payload data.
    fn payload_proof<B>(&self, payload: B, range: Range<usize>) -> VidResult<PROOF>
    where
        B: AsRef<[u8]>;

    /// Verify a proof made by `payload_proof`.
    fn payload_verify<B>(
        &self,
        chunk: B,
        commit: &Self::Commit,
        common: &Self::Common,
        proof: &PROOF,
    ) -> VidResult<Result<(), ()>>
    where
        B: AsRef<[u8]>;
}
