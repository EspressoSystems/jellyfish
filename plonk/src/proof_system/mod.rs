// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Interfaces for Plonk-based proof systems
use crate::{circuit::Arithmetization, errors::PlonkError};
use ark_ec::PairingEngine;
use ark_std::rand::{CryptoRng, RngCore};
pub(crate) mod prover;
pub(crate) mod snark;
pub mod structs;
pub(crate) mod verifier;
use crate::transcript::PlonkTranscript;
pub use snark::PlonkKzgSnark;

/// An interface for SNARKs.
pub trait Snark<E: PairingEngine> {
    /// The SNARK proof computed by the prover.
    type Proof: Clone;

    /// The parameters required by the prover to compute a proof for a specific
    /// circuit.
    type ProvingKey: Clone;

    /// The parameters required by the verifier to validate a proof for a
    /// specific circuit.
    type VerifyingKey: Clone;

    // TODO: (alex) add back when `trait PolynomialCommitment` is implemented for
    // KZG10, and the following can be compiled so that the Snark trait can be
    // generic over prime field F.
    // pub type UniversalSrs<F, PC> = <PC as PolynomialCommitment<F,
    // DensePolynomial<F>>>::UniversalParams;
    //
    // /// Compute the proving/verifying keys from the circuit `circuit`.
    // fn preprocess<C: Arithmetization<F>>(
    //     &self,
    //     srs: &UniversalSrs<F, PC>,
    //     circuit: &C,
    // ) -> Result<(Self::ProvingKey, Self::VerifyingKey), PlonkError>;

    /// Compute a SNARK proof of a circuit `circuit`, using the corresponding
    /// proving key `prove_key`. The witness used to
    /// generate the proof can be obtained from `circuit`.
    fn prove<C, R, T>(
        rng: &mut R,
        circuit: &C,
        prove_key: &Self::ProvingKey,
    ) -> Result<Self::Proof, PlonkError>
    where
        C: Arithmetization<E::Fr>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<E::Fq>;

    /// Verify a SNARK proof `proof` of the circuit `circuit`, with respect to
    /// the public input `pub_input`.
    fn verify<T: PlonkTranscript<E::Fq>>(
        verify_key: &Self::VerifyingKey,
        public_input: &[E::Fr],
        proof: &Self::Proof,
    ) -> Result<(), PlonkError>;
}
