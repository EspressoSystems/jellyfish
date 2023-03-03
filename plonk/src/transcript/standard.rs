// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module is a wrapper of the Merlin transcript.
use super::PlonkTranscript;
use crate::errors::PlonkError;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use jf_utils::to_bytes;
use merlin::Transcript;

/// A wrapper of `merlin::Transcript`.
pub struct StandardTranscript(Transcript);

impl<F> PlonkTranscript<F> for StandardTranscript {
    /// create a new plonk transcript
    fn new(label: &'static [u8]) -> Self {
        Self(Transcript::new(label))
    }

    // append the message to the transcript
    fn append_message(&mut self, label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        self.0.append_message(label, msg);

        Ok(())
    }

    // generate the challenge for the current transcript
    // and append it to the transcript
    fn get_and_append_challenge<E>(
        &mut self,
        label: &'static [u8],
    ) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing,
    {
        let mut buf = [0u8; 64];
        self.0.challenge_bytes(label, &mut buf);
        let challenge = E::ScalarField::from_le_bytes_mod_order(&buf);
        self.0.append_message(label, &to_bytes!(&challenge)?);
        Ok(challenge)
    }
}
