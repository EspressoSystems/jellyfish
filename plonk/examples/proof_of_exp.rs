// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This file contains an example showing how to build a proof of knowledge
//! of the exponent over a native field.
//!
//! - secret input `x`;
//! - public generator `G`;
//! - public group element `X := xG`

use ark_bls12_381::Bls12_381;
use ark_ec::{
    twisted_edwards_extended::GroupAffine as TEAffine, AffineCurve, ModelParameters, PairingEngine,
    ProjectiveCurve, TEModelParameters,
};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsParameters, Fr};
use ark_ff::PrimeField;
use ark_std::{rand::SeedableRng, UniformRand};
use jf_plonk::{
    circuit::{customized::ecc::Point, Arithmetization, Circuit, PlonkCircuit},
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, Snark},
    transcript::StandardTranscript,
};
use jf_utils::fr_to_fq;
use rand_chacha::ChaCha20Rng;

// The following example proves knowledge of exponent.
#[allow(non_snake_case)]
fn main() -> Result<(), PlonkError> {
    // set up the inputs and parameters
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let x = Fr::rand(&mut rng);
    let G = EdwardsAffine::prime_subgroup_generator();
    let X = G.mul(x).into_affine();

    // Our first step is to build a circuit for the following statements.
    // - secret input `x`;
    // - public generator `G`;
    // - public group element `X := xG`
    // This circuit does not need to have real inputs.
    // We can simply use a dummy data set.
    let circuit = proof_of_exponent_circuit::<EdwardsParameters, Bls12_381>(x, X)?;

    // Knowing the circuit size, we are able to simulate the universal
    // setup and obtain the structured reference string (SRS).
    //
    // The required SRS size can be obtained from the circuit.
    let srs_size = circuit.srs_size()?;
    let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng)?;

    // Then, we generate the proving key and verification key from the SRS and
    // circuit.
    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit)?;

    // Next, we generate the proof.
    // The proof generation will need an internal transcript for Fiat-Shamir
    // transformation. For this example we use a `StandardTranscript`.
    let proof =
        PlonkKzgSnark::<Bls12_381>::prove::<_, _, StandardTranscript>(&mut rng, &circuit, &pk)?;

    // Last step, verify the proof against the public inputs.
    let public_inputs = circuit.public_input().unwrap();
    assert!(
        PlonkKzgSnark::<Bls12_381>::verify::<StandardTranscript>(&vk, &public_inputs, &proof,)
            .is_ok()
    );

    Ok(())
}

// This function build the PoE circuit.
//
// We write the code with generics so that is can be adapted to
// multiple curves.
// Specifically, the PoE is associated with
// - an embedded curve with param `EmbedCurve` that defined twisted-edwards
//   parameters for a curve
// - a pairing engine
// - the native field F for the prove system
#[allow(non_snake_case)]
fn proof_of_exponent_circuit<EmbedCurve, PairingCurve>(
    x: EmbedCurve::ScalarField,
    X: TEAffine<EmbedCurve>,
) -> Result<PlonkCircuit<EmbedCurve::BaseField>, PlonkError>
where
    EmbedCurve: TEModelParameters + Clone,
    <EmbedCurve as ModelParameters>::BaseField: PrimeField,
    PairingCurve: PairingEngine,
{
    // Let's check that the inputs are indeed correct before we build a circuit.
    let G = TEAffine::<EmbedCurve>::prime_subgroup_generator();
    assert_eq!(X, G.mul(x), "the inputs are incorrect: X != xG");

    // Step 1:
    // We instantiate a turbo plonk circuit.
    //
    // Here we only need turbo plonk since we are not using plookups.
    let mut circuit = PlonkCircuit::<EmbedCurve::BaseField>::new();

    // Step 2:
    // now we create variables for each input to the circuit.

    // First variable is x which is an field element over P::ScalarField.
    // We will need to lift it to P::BaseField.
    let x_fq = fr_to_fq::<_, EmbedCurve>(&x);
    let x_var = circuit.create_variable(x_fq)?;

    // The next variable is a public constant: generator `G`.
    // We need to convert the point to Jellyfish's own `Point` struct.
    let G_jf: Point<EmbedCurve::BaseField> = G.into();
    let G_var = circuit.create_constant_point_variable(G_jf)?;

    // The last variable is a public variable `X`.
    let X_jf: Point<EmbedCurve::BaseField> = X.into();
    let X_var = circuit.create_public_point_variable(X_jf)?;

    // Step 3:
    // Connect the wires.
    let X_var_computed = circuit.variable_base_scalar_mul::<EmbedCurve>(x_var, &G_var)?;
    circuit.point_equal_gate(&X_var_computed, &X_var)?;

    // Sanity check: the circuit must be satisfied.
    assert!(circuit
        .check_circuit_satisfiability(&[X_jf.get_x(), X_jf.get_y()])
        .is_ok());

    // And we are done!
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}
