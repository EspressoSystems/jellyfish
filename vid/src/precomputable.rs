// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Trait for additional functionality in Verifiable Information Retrieval (VID)
//! for precomputation of specific data that allows for calling
//! methods using the data to save computation for the callee.

use core::fmt::Debug;

use super::{VidDisperse, VidResult, VidScheme};
use ark_std::hash::Hash;
use serde::{de::DeserializeOwned, Serialize};
/// Allow for precomputation of certain data for [`VidScheme`].
pub trait Precomputable: VidScheme {
    /// Precomputed data that can be (re-)used during disperse computation
    type PrecomputeData: Clone + Debug + Eq + PartialEq + Hash + Sync + Serialize + DeserializeOwned;

    /// Similar to [`VidScheme::commit_only`] but returns additional data that
    /// can be used as input to `disperse_precompute` for faster dispersal.
    fn commit_only_precompute<B>(
        &self,
        payload: B,
    ) -> VidResult<(Self::Commit, Self::PrecomputeData)>
    where
        B: AsRef<[u8]>;

    /// Similar to [`VidScheme::disperse`] but takes as input additional
    /// data for more efficient computation and faster disersal.
    fn disperse_precompute<B>(
        &self,
        payload: B,
        data: &Self::PrecomputeData,
    ) -> VidResult<VidDisperse<Self>>
    where
        B: AsRef<[u8]>;

    /// Check that a [`Precomputable::PrecomputeData`] is consistent with a
    /// [`VidScheme::Commit`].
    fn is_consistent_precompute(
        commit: &Self::Commit,
        precompute_data: &Self::PrecomputeData,
        payload_byte_len: u32,
        num_storage_nodes: u32,
    ) -> VidResult<()>;
}
