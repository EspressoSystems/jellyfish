// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! !!!Warning!!!
//! The parameters in this file are mock parameters for testing purpose.
//! They are not correct and shall not be used for anything else

use crate::rescue::{RescueParameter, ROUNDS, STATE_SIZE};
use ark_bls12_381::Fq;

/// This is a dummy implementation of Rescue parameters
/// to satisfy trait bound for Fq.
/// This code should not be used for any other purpose.
impl RescueParameter for Fq {
    const A: u64 = 5;
    const A_INV: &'static [u64] = &[0, 0, 0, 0, 0, 0];

    const MDS_LE: [[&'static [u8]; STATE_SIZE]; STATE_SIZE] =
        [[&[0u8; 32]; STATE_SIZE]; STATE_SIZE];

    const INIT_VEC_LE: [&'static [u8]; STATE_SIZE] = [&[0u8; 32]; STATE_SIZE];

    const KEY_INJECTION_LE: [[&'static [u8]; 4]; 2 * ROUNDS] = [[&[0u8; 32]; 4]; 2 * ROUNDS];

    const PERMUTATION_ROUND_KEYS: [[&'static [u8]; 4]; 25] = [[&[0u8; 32]; 4]; 25];
}
