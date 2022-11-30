// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Constants for curve specific parameters.

/// ciphersuite identifier for schnorr signature
pub const CS_ID_SCHNORR: &str = "SCHNORR_WITH_RESCUE_HASH_v01";

/// ciphersuite identifier for BLS signature
pub const CS_ID_BLS_SIG_NAIVE: &str = "BLS_SIG_WITH_NAIVE_HtG_v01";

/// Size in bytes of a secret key in our BLS signature scheme.
pub const BLS_SIG_KEY_SIZE: usize = 32;
/// Size in bytes of a signature in our BLS signature scheme.
pub const BLS_SIG_SIGNATURE_SIZE: usize = 96;
/// Size in bytes of a verification key in our BLS signature scheme.
pub const BLS_SIG_VERKEY_SIZE: usize = 192;
