// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Constants for curve specific parameters.

/// ciphersuite identifier for schnorr signature
pub const CS_ID_SCHNORR: &str = "SCHNORR_WITH_RESCUE_HASH_v01";

/// ciphersuite identifier for BLS signature
pub const CS_ID_BLS_SIG_NAIVE: &str = "BLS_SIG_WITH_NAIVE_HtG_v01";

/// ciphersuite identifier for BLS VRF
pub const CS_ID_BLS_VRF_NAIVE: &str = "BLS_VRF_WITH_NAIVE_HtG_v01";
