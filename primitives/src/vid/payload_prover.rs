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
    ///
    /// `chunk` is the payload sub-slice for which a proof was generated via
    /// `payload_proof` using `range`. In other words, `chunk` should equal
    /// `payload[range.start..range.end]`.
    fn payload_verify(&self, stmt: Statement<Self>, proof: &PROOF) -> VidResult<Result<(), ()>>;
}

/// A convenience struct to reduce the list of arguments to [`PayloadProver::payload_verify`].
/// It's the statement proved by [`PayloadProver::payload_proof`].
///
/// # Why the `?Sized` bound?
/// Rust hates you: <https://stackoverflow.com/a/54465962>
// TODO: figure out how to derive basic things like Clone, Debug, etc.
// Nothing works with the combo of both type parameter `V` and lifetime 'a.
// #[derive(Derivative)]
// #[derivative(
//     Clone(bound = "V::Common: Clone, V::Commit:Clone"),
//     // Debug(bound = "for<'b> &'b V::Common: ark_std::fmt::Debug, for<'b> &'b V::Commit: ark_std::fmt::Debug"),
//     // Eq(bound = ""),
//     // Hash(bound = ""),
//     // PartialEq(bound = "")
// )]
pub struct Statement<'a, V>
where
    V: VidScheme + ?Sized,
{
    /// The subslice `payload[range.start..range.end]` from a call to [`PayloadProver::payload_proof`].
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
