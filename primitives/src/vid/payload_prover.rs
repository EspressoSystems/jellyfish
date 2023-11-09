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
    /// Compute a proof for a subslice of payload data.
    ///
    /// # Arguments
    ///
    /// - `payload`: a (possibly large) binary payload.
    /// - `range`: indicates the subslice `payload[range.start..range.end]` of
    ///   `playload` for which a proof will be made.
    ///
    /// # Why not just a single `&[u8]` argument for `payload`?
    ///
    /// You might think it's sufficient that [`PayloadProver::payload_proof`]
    /// take only a single `&[u8]` argument that the user creates via
    /// `payload[range.start..range.end]`. However, the generated proof might
    /// depend on `range.start` or on `payload` bytes outside of `range`. This
    /// data would be lost if [`PayloadProver::payload_proof`] accepted only a
    /// single `&[u8]` argument.
    fn payload_proof<B>(&self, payload: B, range: Range<usize>) -> VidResult<PROOF>
    where
        B: AsRef<[u8]>;

    /// Verify a proof made by [`PayloadProver::payload_proof`].
    ///
    /// # Arguments
    ///
    /// - `stmt`: see [`Statement`].
    /// - `proof`: made by a call to [`PayloadProver::payload_proof`].
    fn payload_verify(&self, stmt: Statement<Self>, proof: &PROOF) -> VidResult<Result<(), ()>>;
}

/// A convenience struct to reduce the list of arguments to
/// [`PayloadProver::payload_verify`]. It's the statement proved by
/// [`PayloadProver::payload_proof`].
///
/// # Why the `?Sized` bound?
///
/// Rust hates you: <https://stackoverflow.com/a/54465962>
// TODO: figure out how to derive basic things like Clone, Debug, etc.
// Seems that `Derivative` can't handle reference members.
// #[derive(Derivative)]
// #[derivative(
//     Clone(bound = "V::Common: Clone, V::Commit:Clone"),
// )]
pub struct Statement<'a, V>
where
    V: VidScheme + ?Sized,
{
    /// The subslice `payload[range.start..range.end]` from a call to
    /// [`PayloadProver::payload_proof`].
    pub payload_subslice: &'a [u8],
    /// The range used to make [`Self::payload_subslice`].
    pub range: Range<usize>,
    /// VID commitment against which the proof will be checked.
    pub commit: &'a V::Commit,
    /// VID data against which the proof will be checked.
    pub common: &'a V::Common,
}

impl<'a, V> Clone for Statement<'a, V>
where
    V: VidScheme,
{
    fn clone(&self) -> Self {
        Self {
            payload_subslice: self.payload_subslice,
            range: self.range.clone(),
            commit: self.commit,
            common: self.common,
        }
    }
}
