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
    /// data proof
    type DataProof;

    ///doc
    type DataProof2;

    /// chunk proof
    type ChunkProof;

    /// doc
    type ChunkProof2;

    /// Compute a proof for `payload` for data index range `start..start+len-1`.
    ///
    /// TODO explain how this differs from `chunk_proof`
    fn data_proof(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
    ) -> VidResult<Self::DataProof>;

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

    /// Verify a proof for `payload` for data index range `start..start+len-1`.
    ///
    /// See TODO in `namespace_verify` on `payload`.
    fn data_verify(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
        commit: &Self::Commit,
        common: &Self::Common,
        proof: &Self::DataProof,
    ) -> VidResult<Result<(), ()>>;

    /// Compute a proof for `payload` for data index range `start..start+len-1`.
    fn chunk_proof(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
    ) -> VidResult<Self::ChunkProof>;

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

    /// Verify the `payload` namespace indexed by `namespace_index` against
    /// `commit`, `common`.
    ///
    /// TODO: We prefer not to include the whole `payload`. But the namespace
    /// proof needs a few payload bytes from outside the namespace. In the
    /// future `payload` should be replaced by a payload subset that includes
    /// only the bytes needed to verify a namespace.
    fn chunk_verify(
        &self,
        payload: &Self::Payload,
        start: usize,
        len: usize,
        commit: &Self::Commit,
        common: &Self::Common,
        proof: &Self::ChunkProof,
    ) -> VidResult<Result<(), ()>>;
}
