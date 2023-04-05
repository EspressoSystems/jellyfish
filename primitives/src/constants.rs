// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Constants for curve specific parameters.

/// ciphersuite identifier for schnorr signature
pub const CS_ID_SCHNORR: &str = "SCHNORR_WITH_RESCUE_HASH_v01";

/// ciphersuite identifier for BLS signature over BLS12_381, see:
/// <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-ciphersuite-format>
pub const CS_ID_BLS_MIN_SIG: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Size in bytes of a secret key in our BLS signature scheme.
pub const BLS_SIG_SK_SIZE: usize = 32;
/// Size in bytes of a signature in our BLS signature scheme.
pub const BLS_SIG_SIGNATURE_SIZE: usize = 96;
/// Size in bytes of a compressed signature in our BLS signature scheme.
pub const BLS_SIG_COMPRESSED_SIGNATURE_SIZE: usize = 48;
/// Size in bytes of a verification key in our BLS signature scheme.
pub const BLS_SIG_PK_SIZE: usize = 192;
/// Size in bytes of a compressed verification key in our BLS signature scheme.
pub const BLS_SIG_COMPRESSED_PK_SIZE: usize = 96;

/// ciphersuite identifier for BLS signature over BN254
/// Note this is **adapted** from <https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#name-ciphersuite-format>.
/// In particular the "hash-and-pray" method is not part of <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16>, so the tag "NCTH" (non constant time hash) is not standard.
pub const CS_ID_BLS_BN254: &str = "BLS_SIG_BN254G1_XMD:KECCAK_NCTH_NUL_";
