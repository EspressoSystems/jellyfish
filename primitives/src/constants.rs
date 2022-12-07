// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Constants for curve specific parameters.

/// ciphersuite identifier for schnorr signature
pub const CS_ID_SCHNORR: &str = "SCHNORR_WITH_RESCUE_HASH_v01";

/// ciphersuite identifier for BLS signature, see:
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-ciphersuite-format
pub const CS_ID_BLS_MIN_SIG: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
