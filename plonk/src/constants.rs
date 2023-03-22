// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Crate wide constants.

/// Proof-system-related constants.
///
/// label for the extra data field to be appended to the transcript during
/// initialization
pub(crate) const EXTRA_TRANSCRIPT_MSG_LABEL: &[u8] = b"extra info";

/// Compute the ratio between the quotient polynomial domain size and
/// the vanishing polynomial domain size
#[inline]
pub(crate) const fn domain_size_ratio(n: usize, num_wire_types: usize) -> usize {
    (num_wire_types * (n + 1) + 2) / n + 1
}

/// Keccak-256 have a 64 byte state size to accommodate two hash digests.
pub const KECCAK256_STATE_SIZE: usize = 64;
