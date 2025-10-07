// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements solidity transcript.
use super::PlonkTranscript;
use crate::{
    constants::KECCAK256_STATE_SIZE, errors::PlonkError, proof_system::structs::VerifyingKey,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use jf_pcs::prelude::Commitment;
use jf_utils::to_bytes;
use sha3::{Digest, Keccak256};

/// Transcript with `keccak256` hash function.
///
/// We append new elements to the transcript vector,
/// and when a challenge is generated, the state is updated and transcript is
/// emptied.
///
/// 1. state = hash(state | transcript)
/// 2. transcript = Vec::new()
/// 3. challenge = bytes_to_field(state)
pub struct SolidityTranscript {
    pub(crate) state: [u8; KECCAK256_STATE_SIZE],
    pub(crate) transcript: Vec<u8>,
}

impl<F: PrimeField> PlonkTranscript<F> for SolidityTranscript {
    /// Create a new plonk transcript. `label` is omitted for efficiency.
    fn new(_label: &'static [u8]) -> Self {
        SolidityTranscript {
            state: [0u8; KECCAK256_STATE_SIZE],
            transcript: Vec::new(),
        }
    }
    /// Append the message to the transcript. `_label` is omitted for
    /// efficiency.
    fn append_message(&mut self, _label: &'static [u8], msg: &[u8]) -> Result<(), PlonkError> {
        // We remove the labels for better efficiency
        self.transcript.extend_from_slice(msg);
        Ok(())
    }

    // override default implementation since we want to use BigEndian serialization
    fn append_commitment<E, P>(
        &mut self,
        label: &'static [u8],
        comm: &Commitment<E>,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        P: SWCurveConfig<BaseField = F>,
    {
        let zero = F::zero();
        let (x, y) = if comm.0.is_zero() {
            // this is solidity precompile representation of Points of Infinity
            (zero, zero)
        } else {
            comm.0.xy().unwrap()
        };

        <Self as PlonkTranscript<F>>::append_message(
            self,
            label,
            &[x.into_bigint().to_bytes_be(), y.into_bigint().to_bytes_be()].concat(),
        )
    }

    // override default implementation since we want to use BigEndian serialization
    fn append_field_elem<E>(
        &mut self,
        label: &'static [u8],
        challenge: &E::ScalarField,
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(
            self,
            label,
            &challenge.into_bigint().to_bytes_be(),
        )
    }

    fn append_vk_and_pub_input<E, P>(
        &mut self,
        vk: &VerifyingKey<E>,
        pub_input: &[E::ScalarField],
    ) -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        E::ScalarField: PrimeField,
        P: SWCurveConfig<BaseField = F>,
    {
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"field size in bits",
            E::ScalarField::MODULUS_BIT_SIZE.to_be_bytes().as_ref(),
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"domain size",
            vk.domain_size.to_be_bytes().as_ref(),
        )?;
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"input size",
            vk.num_inputs.to_be_bytes().as_ref(),
        )?;
        // in EVM, memory word size is 32 bytes, the first 3 fields put onto the
        // transcript occupies 4+8+8=20 bytes, thus to align with the memory
        // boundray, we pad with 12 bytes of zeros.
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"EVM word alignment padding",
            &[0u8; 12],
        )?;

        // include [x]_2 G2 point from SRS
        // all G1 points from SRS are implicit reflected in committed polys
        //
        // Since this is a fixed value, we don't need solidity-efficient serialization,
        // we simply append the `to_bytes!()` which uses compressed, little-endian form
        // instead of other proof-dependent field like number of public inputs or
        // concrete polynomial commitments which uses uncompressed, big-endian
        // form.
        <Self as PlonkTranscript<F>>::append_message(
            self,
            b"SRS G2 element",
            &to_bytes!(&vk.open_key.powers_of_h[1])?,
        )?;

        self.append_field_elems::<E>(b"wire subsets separators", &vk.k)?;
        self.append_commitments(b"selector commitments", &vk.selector_comms)?;
        self.append_commitments(b"sigma commitments", &vk.sigma_comms)?;
        self.append_field_elems::<E>(b"public input", pub_input)
    }

    fn get_challenge<E>(&mut self, _label: &'static [u8]) -> Result<E::ScalarField, PlonkError>
    where
        E: Pairing<BaseField = F>,
        E::ScalarField: PrimeField,
    {
        // 1. state = hash(state | transcript)
        let mut hasher = Keccak256::new();
        hasher.update(self.state);
        hasher.update(&self.transcript);
        let buf = hasher.finalize();
        self.state.copy_from_slice(&buf);

        // 2. transcript = Vec::new()
        self.transcript = Vec::new();

        // 3. challenge = bytes_to_field(state)
        Ok(E::ScalarField::from_be_bytes_mod_order(&buf))
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
