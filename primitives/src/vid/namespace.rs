// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait for namespace functionality in Verifiable Information Retrieval (VID).
//!
//! TODO should this trait even exist? It's very implementation-dependent.

use super::{VidResult, VidScheme};
use ark_std::ops::Range;

// pub trait Namespacer2<P>: VidScheme {

//     fn data_proof(
//         &self,
//         payload: &[u8],
//         start: usize,
//         len: usize,
//     ) -> VidResult<Self::DataProof>;

// }

/// Namespace functionality for [`VidScheme`].
pub trait Namespacer: VidScheme {
    ///doc
    type DataProof2;

    /// doc
    type ChunkProof2;

    ///doc
    fn data_proof2<B>(&self, payload: B, range: Range<usize>) -> VidResult<Self::DataProof2>
    where
        B: AsRef<[u8]>;

    /// doc
    fn data_verify2<B>(
        &self,
        chunk: B,
        commit: &Self::Commit,
        common: &Self::Common,
        proof: &Self::DataProof2,
    ) -> VidResult<Result<(), ()>>
    where
        B: AsRef<[u8]>;

    /// doc
    fn chunk_proof2<B>(&self, payload: B, range: Range<usize>) -> VidResult<Self::ChunkProof2>
    where
        B: AsRef<[u8]>;

    /// doc
    fn chunk_verify2<B>(
        &self,
        chunk: B,
        commit: &Self::Commit,
        common: &Self::Common,
        proof: &Self::ChunkProof2,
    ) -> VidResult<Result<(), ()>>
    where
        B: AsRef<[u8]>;
}
