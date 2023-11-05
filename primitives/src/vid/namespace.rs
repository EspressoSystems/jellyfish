// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait for namespace functionality in Verifiable Information Retrieval (VID).
//!
//! TODO should this trait even exist? It's very implementation-dependent.

use super::{VidResult, VidScheme};
use ark_std::ops::Range;

/// Payload proof functionality for [`VidScheme`].
pub trait PayloadProver<PROOF>: VidScheme {
    ///doc
    fn payload_proof<B>(&self, payload: B, range: Range<usize>) -> VidResult<PROOF>
    where
        B: AsRef<[u8]>;
    /// doc
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
