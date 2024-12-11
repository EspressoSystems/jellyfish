//! Poseidon2 Constants copied from <https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/>

use ark_ff::PrimeField;
use hex::FromHex;

#[cfg(feature = "bls12-381")]
pub mod bls12_381;
#[cfg(feature = "bn254")]
pub mod bn254;

#[inline]
pub(crate) fn from_hex<F: PrimeField>(s: &str) -> F {
    F::from_be_bytes_mod_order(&<[u8; 32]>::from_hex(s).expect("Invalid HexStr"))
}

/// macros to derive instances that implements `trait Poseidon2Params`
#[macro_export]
macro_rules! define_poseidon2_params {
    (
        $struct_name:ident,
        $state_size:expr,
        $sbox_size:expr,
        $ext_rounds:expr,
        $int_rounds:expr,
        $rc_ext:ident,
        $rc_int:ident,
        $mat_diag_m_1:ident
    ) => {
        /// Poseidon parameters for Bls12-381 scalar field, with
        /// - state size = $state_size
        /// - sbox size = $sbox_size
        /// - external rounds = $ext_rounds
        /// - internal rounds = $int_rounds
        pub struct $struct_name;

        impl Poseidon2Params<Fr, $state_size> for $struct_name {
            const T: usize = $state_size;
            const D: usize = $sbox_size;
            const EXT_ROUNDS: usize = $ext_rounds;
            const INT_ROUNDS: usize = $int_rounds;

            fn external_rc() -> &'static [[Fr; $state_size]] {
                &*$rc_ext
            }

            fn internal_rc() -> &'static [Fr] {
                &*$rc_int
            }

            fn internal_mat_diag_m_1() -> &'static [Fr; $state_size] {
                &$mat_diag_m_1
            }
        }
    };
}
