// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Interfaces for Plonk-based proof systems
use ark_ec::pairing::Pairing;
use ark_std::{
    error::Error,
    fmt::Debug,
    rand::{CryptoRng, RngCore},
    vec::Vec,
};
use jf_relation::Arithmetization;
pub mod batch_arg;
pub(crate) mod prover;
pub(crate) mod snark;
pub mod structs;
pub(crate) mod verifier;
use crate::transcript::PlonkTranscript;
pub use snark::PlonkKzgSnark;

// TODO: (alex) should we name it `PlonkishSNARK` instead? since we use
// `PlonkTranscript` on prove and verify.
/// An interface for SNARKs with universal setup.
pub trait UniversalSNARK<E: Pairing> {
    /// The SNARK proof computed by the prover.
    type Proof: Clone;

    /// The parameters required by the prover to compute a proof for a specific
    /// circuit.
    type ProvingKey: Clone;

    /// The parameters required by the verifier to validate a proof for a
    /// specific circuit.
    type VerifyingKey: Clone;

    /// Universal Structured Reference String from `universal_setup`, used for
    /// all subsequent circuit-specific preprocessing
    type UniversalSRS: Clone + Debug;

    /// SNARK related error
    type Error: 'static + Error;

    /// Generate the universal SRS for the argument system.
    /// This setup is for trusted party to run, and mostly only used for
    /// testing purpose. In practice, a MPC flavor of the setup will be carried
    /// out to have higher assurance on the "toxic waste"/trapdoor being thrown
    /// away to ensure soundness of the argument system.
    fn universal_setup<R: RngCore + CryptoRng>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<Self::UniversalSRS, Self::Error>;

    /// Circuit-specific preprocessing to compute the proving/verifying keys.
    fn preprocess<C: Arithmetization<E::ScalarField>>(
        srs: &Self::UniversalSRS,
        circuit: &C,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error>;

    /// Compute a SNARK proof of a circuit `circuit`, using the corresponding
    /// proving key `prove_key`. The witness used to
    /// generate the proof can be obtained from `circuit`.
    ///
    /// `extra_transcript_init_msg` is the optional message to be
    /// appended to the transcript during its initialization before obtaining
    /// any challenges. This field allows application-specific data bound to the
    /// resulting proof without any check on the data. It does not incur any
    /// additional cost in proof size or prove time.
    fn prove<C, R, T>(
        rng: &mut R,
        circuit: &C,
        prove_key: &Self::ProvingKey,
        extra_transcript_init_msg: Option<Vec<u8>>,
    ) -> Result<Self::Proof, Self::Error>
    where
        C: Arithmetization<E::ScalarField>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<E::BaseField>;

    /// Verify a SNARK proof `proof` of the circuit `circuit`, with respect to
    /// the public input `pub_input`.
    ///
    /// `extra_transcript_init_msg`: refer to documentation of `prove`
    fn verify<T: PlonkTranscript<E::BaseField>>(
        verify_key: &Self::VerifyingKey,
        public_input: &[E::ScalarField],
        proof: &Self::Proof,
        extra_transcript_init_msg: Option<Vec<u8>>,
    ) -> Result<(), Self::Error>;
}
