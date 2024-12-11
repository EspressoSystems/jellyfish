//! Poseidon2 Constants copied from <https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/>

use ark_ff::PrimeField;
use hex::FromHex;

// #[cfg(feature = "bls12-381")]
pub mod bls12_381;
// #[cfg(feature = "bn254")]
// pub mod bn254;

#[inline]
pub(crate) fn from_hex<F: PrimeField>(s: &str) -> F {
    F::from_be_bytes_mod_order(&<[u8; 32]>::from_hex(s).expect("Invalid HexStr"))
}
