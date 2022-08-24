// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Module for PolyIOP transcript.

mod errors {
    use ark_std::string::String;
    use displaydoc::Display;

    /// A `enum` specifying the possible failure modes of the Transcript.
    #[derive(Display, Debug)]
    pub enum TranscriptError {
        /// Invalid Transcript: {0}
        InvalidTranscript(String),
        /// An error during (de)serialization: {0}
        SerializationError(ark_serialize::SerializationError),
    }

    impl From<ark_serialize::SerializationError> for TranscriptError {
        fn from(e: ark_serialize::SerializationError) -> Self {
            Self::SerializationError(e)
        }
    }
}

pub(crate) use errors::TranscriptError;

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{marker::PhantomData, string::ToString};
use jf_utils::to_bytes;
use merlin::Transcript;

/// An IOP transcript consists of a Merlin transcript and a flag `is_empty` to
/// indicate that if the transcript is empty.
///
/// It is associated with a prime field `F` for which challenges are generated
/// over.
///
/// The `is_empty` flag is useful in the case where a protocol is initiated by
/// the verifier, in which case the prover should start its phase by receiving a
/// `non-empty` transcript.
#[derive(Clone)]
pub(crate) struct IOPTranscript<F: PrimeField> {
    transcript: Transcript,
    is_empty: bool,
    #[doc(hidden)]
    phantom: PhantomData<F>,
}

// TODO: merge this with jf_plonk::transcript
impl<F: PrimeField> IOPTranscript<F> {
    /// Create a new IOP transcript.
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            transcript: Transcript::new(label),
            is_empty: true,
            phantom: PhantomData::default(),
        }
    }

    /// Append the message to the transcript.
    pub(crate) fn append_message(
        &mut self,
        label: &'static [u8],
        msg: &[u8],
    ) -> Result<(), TranscriptError> {
        self.transcript.append_message(label, msg);
        self.is_empty = false;
        Ok(())
    }

    /// Append the message to the transcript.
    pub(crate) fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        self.append_message(label, &to_bytes!(group_elem)?)
    }

    /// Generate the challenge from the current transcript
    /// and append it to the transcript.
    ///
    /// The output field element is statistical uniform as long
    /// as the field has a size less than 2^384.
    pub(crate) fn get_and_append_challenge(
        &mut self,
        label: &'static [u8],
    ) -> Result<F, TranscriptError> {
        //  we need to reject when transcript is empty
        if self.is_empty {
            return Err(TranscriptError::InvalidTranscript(
                "transcript is empty".to_string(),
            ));
        }

        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label, &mut buf);
        let challenge = F::from_le_bytes_mod_order(&buf);
        self.append_serializable_element(label, &challenge)?;
        Ok(challenge)
    }
}
