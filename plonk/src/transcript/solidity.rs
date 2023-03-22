// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements solidity transcript.
use super::PlonkTranscript;
use crate::{constants::KECCAK256_STATE_SIZE, errors::PlonkError};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use sha3::{Digest, Keccak256};

/// Transcript with `keccak256` hash function.
///
/// It is almost identical to `RescueTranscript` except using Solidity's
/// `keccak256` for Solidity-friendly protocols.
///
/// It is currently implemented simply as
/// - an append only vector of field elements
/// - a state that is initialized with 0
///
/// We keep appending new elements to the transcript vector,
/// and when a challenge is to be generated,
/// we reset the state with the fresh challenge.
///
/// 1. state: \[F: STATE_SIZE\] = hash(state|transcript)
/// 2. challenge = state\[0\]
/// 3. transcript = vec!\[challenge\]
pub struct SolidityTranscript {
    transcript: Vec<u8>,
    state: [u8; KECCAK256_STATE_SIZE], // 64 bytes state size
}

impl<F> PlonkTranscript<F> for SolidityTranscript {
    /// Create a new plonk transcript. `label` is omitted for efficiency.
    fn new(_label: &'static [u8]) -> Self {
        SolidityTranscript {
            transcript: Vec::new(),
            state: [0u8; KECCAK256_STATE_SIZE],
        }
    }

    /// Append the message to the transcript. `_label` is omitted for
    /// efficiency.
    fn append_message(&mut self, _label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        // We remove the labels for better efficiency
        self.transcript.extend_from_slice(msg);
        Ok(())
    }

    /// Generate the challenge for the current transcript,
    /// and then append it to the transcript. `_label` is omitted for
    /// efficiency.
    fn get_and_append_challenge<E>(
        &mut self,
        _label: &'static [u8],
    ) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing,
    {
        // 1. state = keccak256(state|transcript|0) || keccak256(state|transcript|1)
        let input0 = [self.state.as_ref(), self.transcript.as_ref(), &[0u8]].concat();
        let input1 = [self.state.as_ref(), self.transcript.as_ref(), &[1u8]].concat();

        let mut hasher = Keccak256::new();
        hasher.update(&input0);
        let buf0 = hasher.finalize();

        let mut hasher = Keccak256::new();
        hasher.update(&input1);
        let buf1 = hasher.finalize();

        self.state.copy_from_slice(&[buf0, buf1].concat());

        // 2. challenge: sample field from random bytes.
        let challenge = E::ScalarField::from_le_bytes_mod_order(&self.state[..48]);
        Ok(challenge)
    }
}

#[test]
fn test_solidity_keccak() {
    use hex::FromHex;
    use sha3::{Digest, Keccak256};
    let message = "the quick brown fox jumps over the lazy dog".as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(message);
    let output = hasher.finalize();

    // test example result yanked from smart contract execution
    assert_eq!(
        output[..],
        <[u8; 32]>::from_hex("865bf05cca7ba26fb8051e8366c6d19e21cadeebe3ee6bfa462b5c72275414ec")
            .unwrap()
    );
}
