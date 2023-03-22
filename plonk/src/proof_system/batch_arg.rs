// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! An argument system that proves/verifies multiple instances in a batch.
use crate::{
    errors::{PlonkError, SnarkError::ParameterError},
    proof_system::{
        structs::{BatchProof, OpenKey, ProvingKey, ScalarsAndBases, UniversalSrs, VerifyingKey},
        verifier::Verifier,
        PlonkKzgSnark, UniversalSNARK,
    },
    transcript::PlonkTranscript,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
};
use ark_ff::One;
use ark_std::{
    format,
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{gadgets::ecc::SWToTEConParam, Circuit, MergeableCircuitType, PlonkCircuit};
use jf_utils::multi_pairing;

/// A batching argument.
pub struct BatchArgument<E: Pairing>(PhantomData<E>);

/// A circuit instance that consists of the corresponding proving
/// key/verification key/circuit.
#[derive(Clone)]
pub struct Instance<E: Pairing> {
    // TODO: considering giving instance an ID
    prove_key: ProvingKey<E>, // the verification key can be obtained inside the proving key.
    circuit: PlonkCircuit<E::ScalarField>,
    _circuit_type: MergeableCircuitType,
}

impl<E: Pairing> Instance<E> {
    /// Get verification key by reference.
    pub fn verify_key_ref(&self) -> &VerifyingKey<E> {
        &self.prove_key.vk
    }

    /// Get mutable circuit by reference.
    pub fn circuit_mut_ref(&mut self) -> &mut PlonkCircuit<E::ScalarField> {
        &mut self.circuit
    }
}

impl<E, F, P> BatchArgument<E>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
{
    /// Setup the circuit and the proving key for a (mergeable) instance.
    pub fn setup_instance(
        srs: &UniversalSrs<E>,
        mut circuit: PlonkCircuit<E::ScalarField>,
        circuit_type: MergeableCircuitType,
    ) -> Result<Instance<E>, PlonkError> {
        circuit.finalize_for_mergeable_circuit(circuit_type)?;
        let (prove_key, _) = PlonkKzgSnark::preprocess(srs, &circuit)?;
        Ok(Instance {
            prove_key,
            circuit,
            _circuit_type: circuit_type,
        })
    }

    /// Prove satisfiability of multiple instances in a batch.
    pub fn batch_prove<R, T>(
        prng: &mut R,
        instances_type_a: &[Instance<E>],
        instances_type_b: &[Instance<E>],
    ) -> Result<BatchProof<E>, PlonkError>
    where
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
        if instances_type_a.len() != instances_type_b.len() {
            return Err(ParameterError(format!(
                "the number of type A instances {} is different from the number of type B instances {}.", 
                instances_type_a.len(),
                instances_type_b.len())
            ).into());
        }
        let pks = instances_type_a
            .iter()
            .zip(instances_type_b.iter())
            .map(|(pred_a, pred_b)| pred_a.prove_key.merge(&pred_b.prove_key))
            .collect::<Result<Vec<_>, _>>()?;

        let circuits = instances_type_a
            .iter()
            .zip(instances_type_b.iter())
            .map(|(pred_a, pred_b)| pred_a.circuit.merge(&pred_b.circuit))
            .collect::<Result<Vec<_>, _>>()?;
        let pks_ref: Vec<&ProvingKey<E>> = pks.iter().collect();
        let circuits_ref: Vec<&PlonkCircuit<E::ScalarField>> = circuits.iter().collect();

        PlonkKzgSnark::batch_prove::<_, _, T>(prng, &circuits_ref, &pks_ref)
    }

    /// Partially verify a batched proof without performing the pairing. Return
    /// the two group elements used in the final pairing.
    pub fn partial_verify<T>(
        beta_g: &E::G1Affine,
        generator_g: &E::G1Affine,
        merged_vks: &[VerifyingKey<E>],
        shared_public_input: &[E::ScalarField],
        batch_proof: &BatchProof<E>,
        blinding_factor: E::ScalarField,
    ) -> Result<(E::G1, E::G1), PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        if merged_vks.is_empty() {
            return Err(ParameterError("empty merged verification keys".to_string()).into());
        }
        if merged_vks.len() != batch_proof.len() {
            return Err(ParameterError(format!(
                "the number of verification keys {} is different from the number of instances {}.",
                merged_vks.len(),
                batch_proof.len()
            ))
            .into());
        }
        let domain_size = merged_vks[0].domain_size;
        for (i, vk) in merged_vks.iter().skip(1).enumerate() {
            if vk.domain_size != domain_size {
                return Err(ParameterError(format!(
                    "the {}-th verification key's domain size {} is different from {}.",
                    i, vk.domain_size, domain_size
                ))
                .into());
            }
        }
        let verifier = Verifier::new(domain_size)?;
        // we need to copy the public input once after merging the circuit
        let shared_public_input = [shared_public_input, shared_public_input].concat();
        let public_inputs = vec![&shared_public_input[..]; merged_vks.len()];
        let merged_vks_ref: Vec<&VerifyingKey<E>> = merged_vks.iter().collect();
        let pcs_info =
            verifier.prepare_pcs_info::<T>(&merged_vks_ref, &public_inputs, batch_proof, &None)?;

        // inner1 = [open_proof] + u * [shifted_open_proof] + blinding_factor * [1]1
        let mut scalars_and_bases = ScalarsAndBases::<E>::new();
        scalars_and_bases.push(E::ScalarField::one(), pcs_info.opening_proof.0);
        scalars_and_bases.push(pcs_info.u, pcs_info.shifted_opening_proof.0);
        scalars_and_bases.push(blinding_factor, *generator_g);
        let inner1 = scalars_and_bases.multi_scalar_mul();

        // inner2 = eval_point * [open_proof] + next_eval_point * u *
        // [shifted_open_proof] + [aggregated_comm] - aggregated_eval * [1]1 +
        // blinding_factor * [beta]1
        let mut scalars_and_bases = pcs_info.comm_scalars_and_bases;
        scalars_and_bases.push(pcs_info.eval_point, pcs_info.opening_proof.0);
        scalars_and_bases.push(
            pcs_info.next_eval_point * pcs_info.u,
            pcs_info.shifted_opening_proof.0,
        );
        scalars_and_bases.push(-pcs_info.eval, *generator_g);
        scalars_and_bases.push(blinding_factor, *beta_g);
        let inner2 = scalars_and_bases.multi_scalar_mul();

        Ok((inner1, inner2))
    }
}

impl<E> BatchArgument<E>
where
    E: Pairing,
{
    /// Aggregate verification keys
    pub fn aggregate_verify_keys(
        vks_type_a: &[&VerifyingKey<E>],
        vks_type_b: &[&VerifyingKey<E>],
    ) -> Result<Vec<VerifyingKey<E>>, PlonkError> {
        if vks_type_a.len() != vks_type_b.len() {
            return Err(ParameterError(format!(
                "the number of type A verification keys {} is different from the number of type B verification keys {}.", 
                vks_type_a.len(),
                vks_type_b.len())
            ).into());
        }
        vks_type_a
            .iter()
            .zip(vks_type_b.iter())
            .map(|(vk_a, vk_b)| vk_a.merge(vk_b))
            .collect::<Result<Vec<_>, PlonkError>>()
    }

    /// Perform the final pairing to verify the proof.
    pub fn decide(open_key: &OpenKey<E>, inner1: E::G1, inner2: E::G1) -> Result<bool, PlonkError> {
        // check e(elem1, [beta]2) ?= e(elem2, [1]2)
        let g1_elems: Vec<<E as Pairing>::G1Affine> = vec![inner1.into(), (-inner2).into()];
        let g2_elems = vec![open_key.beta_h, open_key.h];
        Ok(multi_pairing::<E>(&g1_elems, &g2_elems).0 == E::TargetField::one())
    }
}

pub(crate) fn new_mergeable_circuit_for_test<E: Pairing>(
    shared_public_input: E::ScalarField,
    i: usize,
    circuit_type: MergeableCircuitType,
) -> Result<PlonkCircuit<E::ScalarField>, PlonkError> {
    let mut circuit = PlonkCircuit::new_turbo_plonk();
    let shared_pub_var = circuit.create_public_variable(shared_public_input)?;
    let mut var = shared_pub_var;
    if circuit_type == MergeableCircuitType::TypeA {
        // compute type A instances: add `shared_public_input` by i times
        for _ in 0..i {
            var = circuit.add(var, shared_pub_var)?;
        }
    } else {
        // compute type B instances: mul `shared_public_input` by i times
        for _ in 0..i {
            var = circuit.mul(var, shared_pub_var)?;
        }
    }
    Ok(circuit)
}

/// Create `num_instances` type A/B instance verifying keys and
/// compute the corresponding batch proof. Only used for testing.
#[allow(clippy::type_complexity)]
pub fn build_batch_proof_and_vks_for_test<E, F, P, R, T>(
    rng: &mut R,
    srs: &UniversalSrs<E>,
    num_instances: usize,
    shared_public_input: E::ScalarField,
) -> Result<(BatchProof<E>, Vec<VerifyingKey<E>>, Vec<VerifyingKey<E>>), PlonkError>
where
    E: Pairing<BaseField = F, G1Affine = Affine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWCurveConfig<BaseField = F>,
    R: CryptoRng + RngCore,
    T: PlonkTranscript<F>,
{
    let mut instances_type_a = vec![];
    let mut instances_type_b = vec![];
    let mut vks_type_a = vec![];
    let mut vks_type_b = vec![];
    for i in 10..10 + num_instances {
        let circuit = new_mergeable_circuit_for_test::<E>(
            shared_public_input,
            i,
            MergeableCircuitType::TypeA,
        )?;
        let instance = BatchArgument::setup_instance(srs, circuit, MergeableCircuitType::TypeA)?;
        vks_type_a.push(instance.verify_key_ref().clone());
        instances_type_a.push(instance);

        let circuit = new_mergeable_circuit_for_test::<E>(
            shared_public_input,
            i,
            MergeableCircuitType::TypeB,
        )?;
        let instance = BatchArgument::setup_instance(srs, circuit, MergeableCircuitType::TypeB)?;
        vks_type_b.push(instance.verify_key_ref().clone());
        instances_type_b.push(instance);
    }

    let batch_proof =
        BatchArgument::batch_prove::<_, T>(rng, &instances_type_a, &instances_type_b)?;
    Ok((batch_proof, vks_type_a, vks_type_b))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transcript::RescueTranscript;
    use ark_bls12_377::{Bls12_377, Fq as Fq377};
    use ark_std::UniformRand;
    use jf_utils::test_rng;

    #[test]
    fn test_batch_argument() -> Result<(), PlonkError> {
        test_batch_argument_helper::<Bls12_377, Fq377, _, RescueTranscript<_>>()
    }

    fn test_batch_argument_helper<E, F, P, T>() -> Result<(), PlonkError>
    where
        E: Pairing<BaseField = F, G1Affine = Affine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWCurveConfig<BaseField = F>,
        T: PlonkTranscript<F>,
    {
        // 1. Simulate universal setup
        let rng = &mut test_rng();
        let n = 128;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        // 2. Setup instances
        let shared_public_input = E::ScalarField::rand(rng);
        let mut instances_type_a = vec![];
        let mut instances_type_b = vec![];
        for i in 32..50 {
            let circuit = new_mergeable_circuit_for_test::<E>(
                shared_public_input,
                i,
                MergeableCircuitType::TypeA,
            )?;
            let instance =
                BatchArgument::setup_instance(&srs, circuit, MergeableCircuitType::TypeA)?;
            instances_type_a.push(instance);

            let circuit = new_mergeable_circuit_for_test::<E>(
                shared_public_input,
                i,
                MergeableCircuitType::TypeB,
            )?;
            let instance =
                BatchArgument::setup_instance(&srs, circuit, MergeableCircuitType::TypeB)?;
            instances_type_b.push(instance);
        }

        // 3. Batch Proving
        let batch_proof =
            BatchArgument::batch_prove::<_, T>(rng, &instances_type_a, &instances_type_b)?;
        // error path: inconsistent length between instances_type_a and
        // instances_type_b
        assert!(
            BatchArgument::batch_prove::<_, T>(rng, &instances_type_a[1..], &instances_type_b)
                .is_err()
        );

        // 4. Aggregate verification keys
        let vks_type_a: Vec<&VerifyingKey<E>> = instances_type_a
            .iter()
            .map(|pred| pred.verify_key_ref())
            .collect();
        let vks_type_b: Vec<&VerifyingKey<E>> = instances_type_b
            .iter()
            .map(|pred| pred.verify_key_ref())
            .collect();
        let merged_vks = BatchArgument::aggregate_verify_keys(&vks_type_a, &vks_type_b)?;
        // error path: inconsistent length between vks_type_a and vks_type_b
        assert!(BatchArgument::aggregate_verify_keys(&vks_type_a[1..], &vks_type_b).is_err());

        // 5. Verification
        let open_key_ref = &vks_type_a[0].open_key;
        let beta_g_ref = &srs.powers_of_g[1];
        let blinding_factor = E::ScalarField::rand(rng);
        let (inner1, inner2) = BatchArgument::partial_verify::<T>(
            beta_g_ref,
            &open_key_ref.g,
            &merged_vks,
            &[shared_public_input],
            &batch_proof,
            blinding_factor,
        )?;
        assert!(BatchArgument::decide(open_key_ref, inner1, inner2)?);
        // error paths
        // empty merged_vks
        assert!(BatchArgument::partial_verify::<T>(
            beta_g_ref,
            &open_key_ref.g,
            &[],
            &[shared_public_input],
            &batch_proof,
            blinding_factor
        )
        .is_err());
        // the number of vks is different the number of instances
        assert!(BatchArgument::partial_verify::<T>(
            beta_g_ref,
            &open_key_ref.g,
            &merged_vks[1..],
            &[shared_public_input],
            &batch_proof,
            blinding_factor
        )
        .is_err());
        // inconsistent domain size between verification keys
        let mut bad_merged_vks = merged_vks;
        bad_merged_vks[0].domain_size /= 2;
        assert!(BatchArgument::partial_verify::<T>(
            beta_g_ref,
            &open_key_ref.g,
            &bad_merged_vks,
            &[shared_public_input],
            &batch_proof,
            blinding_factor
        )
        .is_err());

        Ok(())
    }
}
