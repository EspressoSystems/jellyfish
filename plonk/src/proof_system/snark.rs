// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Instantiations of Plonk-based proof systems
use super::{
    prover::Prover,
    structs::{trim, BatchProof, Challenges, Oracles, Proof, ProvingKey, VerifyingKey},
    verifier::Verifier,
    Snark,
};
use crate::{
    circuit::{customized::ecc::SWToTEConParam, Arithmetization},
    constants::compute_coset_representatives,
    errors::{PlonkError, SnarkError::ParameterError},
    proof_system::structs::UniversalSrs,
    transcript::*,
};
use ark_ec::{short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters};
use ark_ff::{Field, One};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{kzg10::KZG10, PCUniversalParams};
use ark_std::{
    format,
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    string::ToString,
    vec,
    vec::Vec,
};
use jf_rescue::RescueParameter;
use rayon::prelude::*;

/// A Plonk instantiated with KZG PCS
pub struct PlonkKzgSnark<'a, E: PairingEngine>(PhantomData<&'a E>);

impl<'a, E, F, P> PlonkKzgSnark<'a, E>
where
    E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWModelParameters<BaseField = F> + Clone,
{
    #[allow(clippy::new_without_default)]
    /// A new Plonk KZG SNARK
    pub fn new() -> Self {
        Self(PhantomData)
    }

    /// Generate the universal SRS for the argument system.
    /// This setup is for trusted party to run, and mostly only used for
    /// testing purpose. In practice, a MPC flavor of the setup will be carried
    /// out to have higher assurance on the "toxic waste"/trapdoor being thrown
    /// away to ensure soundness of the argument system.
    pub fn universal_setup<R: RngCore>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<UniversalSrs<E>, PlonkError> {
        let srs = KZG10::<E, DensePolynomial<E::Fr>>::setup(max_degree, false, rng)?;
        Ok(UniversalSrs(srs))
    }

    // TODO: (alex) move back to Snark trait when `trait PolynomialCommitment` is
    // implemented for KZG10
    /// Input a circuit and the SRS, precompute the proving key and verification
    /// key.
    pub fn preprocess<C: Arithmetization<E::Fr>>(
        srs: &'a UniversalSrs<E>,
        circuit: &C,
    ) -> Result<(ProvingKey<'a, E>, VerifyingKey<E>), PlonkError> {
        // Make sure the SRS can support the circuit (with hiding degree of 2 for zk)
        let domain_size = circuit.eval_domain_size()?;
        let srs_size = circuit.srs_size()?;
        let num_inputs = circuit.num_inputs();
        if srs.0.max_degree() < circuit.srs_size()? {
            return Err(PlonkError::IndexTooLarge);
        }
        // 1. Compute selector and permutation polynomials.
        let selectors_polys = circuit.compute_selector_polynomials()?;
        let sigma_polys = circuit.compute_extended_permutation_polynomials()?;

        // 2. Compute VerifyingKey
        let (commit_key, open_key) = trim(&srs.0, srs_size);
        let selector_comms: Vec<_> = selectors_polys
            .par_iter()
            .map(|poly| {
                let (comm, _) = KZG10::commit(&commit_key, poly, None, None)?;
                Ok(comm)
            })
            .collect::<Result<Vec<_>, PlonkError>>()?
            .into_iter()
            .collect();
        let sigma_comms: Vec<_> = sigma_polys
            .par_iter()
            .map(|poly| {
                let (comm, _) = KZG10::commit(&commit_key, poly, None, None)?;
                Ok(comm)
            })
            .collect::<Result<Vec<_>, PlonkError>>()?
            .into_iter()
            .collect();

        let vk = VerifyingKey {
            domain_size,
            num_inputs,
            selector_comms,
            sigma_comms,
            k: compute_coset_representatives(circuit.num_wire_types(), Some(domain_size)),
            open_key,
        };

        // Compute ProvingKey (which includes the VerifyingKey)
        let pk = ProvingKey {
            sigmas: sigma_polys,
            selectors: selectors_polys,
            commit_key,
            vk: vk.clone(),
        };

        Ok((pk, vk))
    }

    /// Generate an aggregated Plonk proof for multiple instances.
    pub fn batch_prove<C, R, T>(
        prng: &mut R,
        circuits: &[&C],
        prove_keys: &[&ProvingKey<'a, E>],
    ) -> Result<BatchProof<E>, PlonkError>
    where
        C: Arithmetization<E::Fr>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
        let (batch_proof, ..) = Self::batch_prove_internal::<_, _, T>(prng, circuits, prove_keys)?;
        Ok(batch_proof)
    }

    /// Verify a single aggregated Plonk proof.
    pub fn verify_batch_proof<T>(
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        batch_proof: &BatchProof<E>,
    ) -> Result<(), PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        if verify_keys.is_empty() {
            return Err(ParameterError("empty verification keys".to_string()).into());
        }
        let verifier = Verifier::new(verify_keys[0].domain_size)?;
        let pcs_info = verifier.prepare_pcs_info::<T>(verify_keys, public_inputs, batch_proof)?;
        if !Verifier::batch_verify_opening_proofs::<T>(
            &verify_keys[0].open_key, // all open_key are the same
            &[pcs_info],
        )? {
            return Err(PlonkError::WrongProof);
        }
        Ok(())
    }

    /// Batch verify multiple SNARK proofs (w.r.t. different verifying keys).
    pub fn batch_verify<T>(
        verify_keys: &[&VerifyingKey<E>],
        public_inputs: &[&[E::Fr]],
        proofs: &[&Proof<E>],
    ) -> Result<(), PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        if public_inputs.len() != proofs.len() || verify_keys.len() != proofs.len() {
            return Err(ParameterError(format!(
                "verify_keys.len: {}, public_inputs.len: {}, proofs.len: {}",
                verify_keys.len(),
                public_inputs.len(),
                proofs.len(),
            ))
            .into());
        }
        if verify_keys.is_empty() {
            return Err(
                ParameterError("the number of instances cannot be zero".to_string()).into(),
            );
        }

        let pcs_infos = verify_keys
            .par_iter()
            .zip(proofs.par_iter())
            .zip(public_inputs.par_iter())
            .map(|((&vk, &proof), &pub_input)| {
                let verifier = Verifier::new(vk.domain_size)?;
                verifier.prepare_pcs_info::<T>(&[vk], &[pub_input], &(*proof).clone().into())
            })
            .collect::<Result<Vec<_>, PlonkError>>()?;

        if !Verifier::batch_verify_opening_proofs::<T>(
            &verify_keys[0].open_key, // all open_key are the same
            &pcs_infos,
        )? {
            return Err(PlonkError::WrongProof);
        }
        Ok(())
    }

    /// An internal private API for ease of testing
    ///
    /// Batchly compute a Plonk proof for multiple instances. Return the batch
    /// proof and the corresponding online polynomial oracles and
    /// challenges. Refer to Sec 8.4 of https://eprint.iacr.org/2019/953.pdf
    ///
    /// `circuit` and `prove_key` has to be consistent (with the same evaluation
    /// domain etc.), otherwise return error.
    #[allow(clippy::type_complexity)]
    fn batch_prove_internal<C, R, T>(
        prng: &mut R,
        circuits: &[&C],
        prove_keys: &[&ProvingKey<'a, E>],
    ) -> Result<(BatchProof<E>, Vec<Oracles<E::Fr>>, Challenges<E::Fr>), PlonkError>
    where
        C: Arithmetization<E::Fr>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
        if circuits.is_empty() {
            return Err(ParameterError("zero number of circuits/proving keys".to_string()).into());
        }
        if circuits.len() != prove_keys.len() {
            return Err(ParameterError(format!(
                "the number of circuits {} != the number of proving keys {}",
                circuits.len(),
                prove_keys.len()
            ))
            .into());
        }
        let n = circuits[0].eval_domain_size()?;
        let num_wire_types = circuits[0].num_wire_types();
        for (circuit, pk) in circuits.iter().zip(prove_keys.iter()) {
            if circuit.eval_domain_size()? != n {
                return Err(ParameterError(format!(
                    "circuit domain size {} != expected domain size {}",
                    circuit.eval_domain_size()?,
                    n
                ))
                .into());
            }
            if pk.domain_size() != n {
                return Err(ParameterError(format!(
                    "proving key domain size {} != expected domain size {}",
                    pk.domain_size(),
                    n
                ))
                .into());
            }
            if circuit.num_inputs() != pk.vk.num_inputs {
                return Err(ParameterError(format!(
                    "circuit.num_inputs {} != prove_key.num_inputs {}",
                    circuit.num_inputs(),
                    pk.vk.num_inputs
                ))
                .into());
            }

            if circuit.num_wire_types() != num_wire_types {
                return Err(ParameterError("inconsistent plonk circuit types".to_string()).into());
            }
        }

        // Initialize transcript
        let mut transcript = T::new(b"PlonkProof");
        for (pk, circuit) in prove_keys.iter().zip(circuits.iter()) {
            transcript.append_vk_and_pub_input(&pk.vk, &circuit.public_input()?)?;
        }
        // Initialize verifier challenges and online polynomial oracles.
        let mut challenges = Challenges::default();
        let mut online_oracles = vec![Oracles::default(); circuits.len()];
        let prover = Prover::new(n, num_wire_types)?;

        // Round 1
        let mut wires_poly_comms_vec = vec![];
        for i in 0..circuits.len() {
            let ((wires_poly_comms, wire_polys), pi_poly) =
                prover.run_1st_round(prng, &prove_keys[i].commit_key, circuits[i])?;
            online_oracles[i].wire_polys = wire_polys;
            online_oracles[i].pub_inp_poly = pi_poly;
            transcript.append_commitments(b"witness_poly_comms", &wires_poly_comms)?;
            wires_poly_comms_vec.push(wires_poly_comms);
        }

        // Round 2
        challenges.beta = transcript.get_and_append_challenge::<E>(b"beta")?;
        challenges.gamma = transcript.get_and_append_challenge::<E>(b"gamma")?;
        let mut prod_perm_poly_comms_vec = vec![];
        for i in 0..circuits.len() {
            let (prod_perm_poly_comm, prod_perm_poly) =
                prover.run_2nd_round(prng, &prove_keys[i].commit_key, circuits[i], &challenges)?;
            online_oracles[i].prod_perm_poly = prod_perm_poly;
            transcript.append_commitment(b"perm_poly_comms", &prod_perm_poly_comm)?;
            prod_perm_poly_comms_vec.push(prod_perm_poly_comm);
        }

        // Round 3
        challenges.alpha = transcript.get_and_append_challenge::<E>(b"alpha")?;
        let (split_quot_poly_comms, split_quot_polys) = prover.run_3rd_round(
            &prove_keys[0].commit_key,
            prove_keys,
            &challenges,
            &online_oracles,
            num_wire_types,
        )?;
        transcript.append_commitments(b"quot_poly_comms", &split_quot_poly_comms)?;

        // Round 4
        challenges.zeta = transcript.get_and_append_challenge::<E>(b"zeta")?;
        let mut poly_evals_vec = vec![];
        for i in 0..circuits.len() {
            let poly_evals = prover.compute_evaluations(
                prove_keys[i],
                &challenges,
                &online_oracles[i],
                num_wire_types,
            );
            transcript.append_proof_evaluations::<E>(&poly_evals)?;
            poly_evals_vec.push(poly_evals);
        }

        let mut lin_poly = Prover::<E>::compute_quotient_component_for_lin_poly(
            n,
            challenges.zeta,
            &split_quot_polys,
        )?;
        let mut alpha_base = E::Fr::one();
        let alpha_3 = challenges.alpha.square() * challenges.alpha;
        for i in 0..circuits.len() {
            lin_poly = lin_poly
                + prover.compute_non_quotient_component_for_lin_poly(
                    alpha_base,
                    prove_keys[i],
                    &challenges,
                    &online_oracles[i],
                    &poly_evals_vec[i],
                )?;

            alpha_base *= alpha_3;
        }

        // Round 5
        challenges.v = transcript.get_and_append_challenge::<E>(b"v")?;
        let (opening_proof, shifted_opening_proof) = prover.compute_opening_proofs(
            &prove_keys[0].commit_key,
            prove_keys,
            &challenges.zeta,
            &challenges.v,
            &online_oracles,
            &lin_poly,
        )?;

        Ok((
            BatchProof {
                wires_poly_comms_vec,
                prod_perm_poly_comms_vec,
                poly_evals_vec,
                split_quot_poly_comms,
                opening_proof,
                shifted_opening_proof,
            },
            online_oracles,
            challenges,
        ))
    }
}

impl<'a, E, F, P> Snark<E> for PlonkKzgSnark<'a, E>
where
    E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
    F: RescueParameter + SWToTEConParam,
    P: SWModelParameters<BaseField = F> + Clone,
{
    type Proof = Proof<E>;

    type ProvingKey = ProvingKey<'a, E>;

    type VerifyingKey = VerifyingKey<E>;

    /// Compute a Plonk proof.
    /// Refer to Sec 8.4 of <https://eprint.iacr.org/2019/953.pdf>
    ///
    /// `circuit` and `prove_key` has to be consistent (with the same evaluation
    /// domain etc.), otherwise return error.
    fn prove<C, R, T>(
        prng: &mut R,
        circuit: &C,
        prove_key: &Self::ProvingKey,
    ) -> Result<Self::Proof, PlonkError>
    where
        C: Arithmetization<E::Fr>,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
        let (batch_proof, ..) =
            Self::batch_prove_internal::<_, _, T>(prng, &[circuit], &[prove_key])?;
        Ok(Proof {
            wires_poly_comms: batch_proof.wires_poly_comms_vec[0].clone(),
            prod_perm_poly_comm: batch_proof.prod_perm_poly_comms_vec[0],
            split_quot_poly_comms: batch_proof.split_quot_poly_comms,
            opening_proof: batch_proof.opening_proof,
            shifted_opening_proof: batch_proof.shifted_opening_proof,
            poly_evals: batch_proof.poly_evals_vec[0].clone(),
        })
    }

    fn verify<T>(
        verify_key: &Self::VerifyingKey,
        public_input: &[E::Fr],
        proof: &Self::Proof,
    ) -> Result<(), PlonkError>
    where
        T: PlonkTranscript<F>,
    {
        Self::batch_verify::<T>(&[verify_key], &[public_input], &[proof])
    }
}

#[cfg(test)]
pub mod test {
    use crate::{
        circuit::{customized::ecc::SWToTEConParam, Arithmetization, Circuit, PlonkCircuit},
        constants::GATE_WIDTH,
        errors::PlonkError,
        proof_system::{
            structs::{Challenges, Oracles, Proof, ProvingKey, UniversalSrs, VerifyingKey},
            PlonkKzgSnark, Snark,
        },
        transcript::{PlonkTranscript, StandardTranscript},
    };
    use ark_bls12_377::{Bls12_377, Fq as Fq377};
    use ark_bls12_381::{Bls12_381, Fq as Fq381};
    use ark_bn254::{Bn254, Fq as Fq254};
    use ark_bw6_761::{Fq as Fq761, BW6_761};
    use ark_ec::{short_weierstrass_jacobian::GroupAffine, PairingEngine, SWModelParameters};
    use ark_ff::{One, PrimeField, Zero};
    use ark_poly::{
        univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain,
        UVPolynomial,
    };
    use ark_poly_commit::kzg10::{Commitment, KZG10};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{
        convert::TryInto,
        rand::{CryptoRng, RngCore},
        test_rng, vec,
        vec::Vec,
    };
    use core::ops::{Mul, Neg};
    use jf_rescue::RescueParameter;

    // Different `m`s lead to different circuits.
    // Different `a0`s lead to different witness values.
    // For UltraPlonk circuits, `a0` should be less than or equal to `m+1`
    pub(crate) fn gen_circuit_for_test<F: PrimeField>(
        m: usize,
        a0: usize,
    ) -> Result<PlonkCircuit<F>, PlonkError> {
        let mut cs: PlonkCircuit<F> = PlonkCircuit::new();
        // Create variables
        let mut a = vec![];
        for i in a0..(a0 + 4 * m) {
            a.push(cs.create_variable(F::from(i as u64))?);
        }
        let b = vec![
            cs.create_public_variable(F::from(m as u64 * 2))?,
            cs.create_public_variable(F::from(a0 as u64 * 2 + m as u64 * 4 - 1))?,
        ];
        let c = cs.create_public_variable(
            (cs.witness(b[1])? + cs.witness(a[0])?) * (cs.witness(b[1])? - cs.witness(a[0])?),
        )?;

        // Create gates:
        // 1. a0 + ... + a_{4*m-1} = b0 * b1
        // 2. (b1 + a0) * (b1 - a0) = c
        // 3. b0 = 2 * m
        let mut acc = cs.zero();
        a.iter().for_each(|&elem| acc = cs.add(acc, elem).unwrap());
        let b_mul = cs.mul(b[0], b[1])?;
        cs.equal_gate(acc, b_mul)?;
        let b1_plus_a0 = cs.add(b[1], a[0])?;
        let b1_minus_a0 = cs.sub(b[1], a[0])?;
        cs.mul_gate(b1_plus_a0, b1_minus_a0, c)?;
        cs.constant_gate(b[0], F::from(m as u64 * 2))?;

        // Finalize the circuit.
        cs.finalize_for_arithmetization()?;

        Ok(cs)
    }

    #[test]
    fn test_preprocessing() -> Result<(), PlonkError> {
        test_preprocessing_helper::<Bn254, Fq254, _>()?;
        test_preprocessing_helper::<Bls12_377, Fq377, _>()?;
        test_preprocessing_helper::<Bls12_381, Fq381, _>()?;
        test_preprocessing_helper::<BW6_761, Fq761, _>()
    }
    fn test_preprocessing_helper<E, F, P>() -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = F> + Clone,
    {
        let rng = &mut ark_std::test_rng();
        let circuit = gen_circuit_for_test(5, 6)?;
        let domain_size = circuit.eval_domain_size()?;
        let num_inputs = circuit.num_inputs();
        let selectors = circuit.compute_selector_polynomials()?;
        let sigmas = circuit.compute_extended_permutation_polynomials()?;

        let max_degree = 64 + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;
        let (pk, vk) = PlonkKzgSnark::<E>::preprocess(&srs, &circuit)?;

        // check proving key
        assert_eq!(pk.selectors, selectors);
        assert_eq!(pk.sigmas, sigmas);
        assert_eq!(pk.domain_size(), domain_size);
        assert_eq!(pk.num_inputs(), num_inputs);
        let num_wire_types = GATE_WIDTH + 1;
        assert_eq!(pk.sigmas.len(), num_wire_types);

        // check verifying key
        assert_eq!(vk.domain_size, domain_size);
        assert_eq!(vk.num_inputs, num_inputs);
        assert_eq!(vk.selector_comms.len(), selectors.len());
        assert_eq!(vk.sigma_comms.len(), sigmas.len());
        assert_eq!(vk.sigma_comms.len(), num_wire_types);
        selectors
            .iter()
            .zip(vk.selector_comms.iter())
            .for_each(|(p, &p_comm)| {
                let (expected_comm, _) = KZG10::commit(&pk.commit_key, p, None, None).unwrap();
                assert_eq!(expected_comm, p_comm);
            });
        sigmas
            .iter()
            .zip(vk.sigma_comms.iter())
            .for_each(|(p, &p_comm)| {
                let (expected_comm, _) = KZG10::commit(&pk.commit_key, p, None, None).unwrap();
                assert_eq!(expected_comm, p_comm);
            });

        Ok(())
    }

    #[test]
    fn test_plonk_proof_system() -> Result<(), PlonkError> {
        // merlin transcripts
        test_plonk_proof_system_helper::<Bn254, Fq254, _, StandardTranscript>()?;

        test_plonk_proof_system_helper::<Bls12_377, Fq377, _, StandardTranscript>()?;

        test_plonk_proof_system_helper::<Bls12_381, Fq381, _, StandardTranscript>()?;

        test_plonk_proof_system_helper::<BW6_761, Fq761, _, StandardTranscript>()?;

        Ok(())
    }

    fn test_plonk_proof_system_helper<E, F, P, T>() -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = F> + Clone,
        T: PlonkTranscript<F>,
    {
        // 1. Simulate universal setup
        let rng = &mut test_rng();
        let n = 64;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        // 2. Create circuits
        let circuits = (0..6)
            .map(|i| {
                let m = 2 + i / 3;
                let a0 = 1 + i % 3;
                gen_circuit_for_test(m, a0)
            })
            .collect::<Result<Vec<_>, PlonkError>>()?;
        // 3. Preprocessing
        let (pk1, vk1) = PlonkKzgSnark::<E>::preprocess(&srs, &circuits[0])?;
        let (pk2, vk2) = PlonkKzgSnark::<E>::preprocess(&srs, &circuits[3])?;
        // 4. Proving
        let mut proofs = vec![];
        for (i, cs) in circuits.iter().enumerate() {
            let pk_ref = if i < 3 { &pk1 } else { &pk2 };
            proofs.push(PlonkKzgSnark::<E>::prove::<_, _, T>(rng, cs, pk_ref).unwrap());
        }

        // 5. Verification
        let public_inputs: Vec<Vec<E::Fr>> = circuits
            .iter()
            .map(|cs| cs.public_input())
            .collect::<Result<Vec<Vec<E::Fr>>, PlonkError>>()?;
        for (i, proof) in proofs.iter().enumerate() {
            let vk_ref = if i < 3 { &vk1 } else { &vk2 };
            assert!(PlonkKzgSnark::<E>::verify::<T>(vk_ref, &public_inputs[i], proof,).is_ok());
            // Inconsistent proof should fail the verification.
            let mut bad_pub_input = public_inputs[i].clone();
            bad_pub_input[0] = E::Fr::from(0u8);
            assert!(PlonkKzgSnark::<E>::verify::<T>(vk_ref, &bad_pub_input, proof,).is_err());

            // Incorrect proof [W_z] = 0, [W_z*g] = 0
            // attack against some vulnerable implementation described in:
            // https://cryptosubtlety.medium.com/00-8d4adcf4d255
            let mut bad_proof = proof.clone();
            bad_proof.opening_proof = Commitment::default();
            bad_proof.shifted_opening_proof = Commitment::default();
            assert!(
                PlonkKzgSnark::<E>::verify::<T>(vk_ref, &public_inputs[i], &bad_proof,).is_err()
            );
        }

        // 6. Batch verification
        let vks = vec![&vk1, &vk1, &vk1, &vk2, &vk2, &vk2];
        let mut public_inputs_ref: Vec<&[E::Fr]> = public_inputs
            .iter()
            .map(|pub_input| &pub_input[..])
            .collect();
        let mut proofs_ref: Vec<&Proof<E>> = proofs.iter().collect();
        assert!(
            PlonkKzgSnark::<E>::batch_verify::<T>(&vks, &public_inputs_ref, &proofs_ref,).is_ok()
        );

        // Inconsistent params
        assert!(
            PlonkKzgSnark::<E>::batch_verify::<T>(&vks[..5], &public_inputs_ref, &proofs_ref,)
                .is_err()
        );

        assert!(
            PlonkKzgSnark::<E>::batch_verify::<T>(&vks, &public_inputs_ref[..5], &proofs_ref,)
                .is_err()
        );

        assert!(
            PlonkKzgSnark::<E>::batch_verify::<T>(&vks, &public_inputs_ref, &proofs_ref[..5],)
                .is_err()
        );

        // Empty params
        assert!(PlonkKzgSnark::<E>::batch_verify::<T>(&vec![], &vec![], &vec![]).is_err());

        // Error paths
        let tmp_pi_ref = public_inputs_ref[0];
        public_inputs_ref[0] = public_inputs_ref[1];
        assert!(
            PlonkKzgSnark::<E>::batch_verify::<T>(&vks, &public_inputs_ref, &proofs_ref,).is_err()
        );
        public_inputs_ref[0] = tmp_pi_ref;

        proofs_ref[0] = proofs_ref[1];
        assert!(
            PlonkKzgSnark::<E>::batch_verify::<T>(&vks, &public_inputs_ref, &proofs_ref,).is_err()
        );

        Ok(())
    }

    #[test]
    fn test_inconsistent_pub_input_len() -> Result<(), PlonkError> {
        // merlin transcripts
        test_inconsistent_pub_input_len_helper::<Bn254, Fq254, _, StandardTranscript>()?;
        test_inconsistent_pub_input_len_helper::<Bls12_377, Fq377, _, StandardTranscript>()?;
        test_inconsistent_pub_input_len_helper::<Bls12_381, Fq381, _, StandardTranscript>()?;
        test_inconsistent_pub_input_len_helper::<BW6_761, Fq761, _, StandardTranscript>()?;

        Ok(())
    }

    fn test_inconsistent_pub_input_len_helper<E, F, P, T>() -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = F> + Clone,
        T: PlonkTranscript<F>,
    {
        // 1. Simulate universal setup
        let rng = &mut test_rng();
        let n = 8;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        // 2. Create circuits
        let mut cs1: PlonkCircuit<E::Fr> = PlonkCircuit::new();
        let var = cs1.create_variable(E::Fr::from(1u8))?;
        cs1.constant_gate(var, E::Fr::from(1u8))?;
        cs1.finalize_for_arithmetization()?;
        let mut cs2: PlonkCircuit<E::Fr> = PlonkCircuit::new();
        cs2.create_public_variable(E::Fr::from(1u8))?;
        cs2.finalize_for_arithmetization()?;

        // 3. Preprocessing
        let (pk1, vk1) = PlonkKzgSnark::<E>::preprocess(&srs, &cs1)?;
        let (pk2, vk2) = PlonkKzgSnark::<E>::preprocess(&srs, &cs2)?;

        // 4. Proving
        assert!(PlonkKzgSnark::<E>::prove::<_, _, T>(rng, &cs2, &pk1).is_err());
        let proof2 = PlonkKzgSnark::<E>::prove::<_, _, T>(rng, &cs2, &pk2)?;

        // 5. Verification
        assert!(PlonkKzgSnark::<E>::verify::<T>(&vk2, &[E::Fr::from(1u8)], &proof2).is_ok());
        // wrong verification key
        assert!(PlonkKzgSnark::<E>::verify::<T>(&vk1, &[E::Fr::from(1u8)], &proof2).is_err());
        // wrong public input
        assert!(PlonkKzgSnark::<E>::verify::<T>(&vk2, &[], &proof2).is_err());

        Ok(())
    }

    #[test]
    fn test_plonk_prover_polynomials() -> Result<(), PlonkError> {
        // merlin transcripts
        test_plonk_prover_polynomials_helper::<Bn254, Fq254, _, StandardTranscript>()?;
        test_plonk_prover_polynomials_helper::<Bls12_377, Fq377, _, StandardTranscript>()?;
        test_plonk_prover_polynomials_helper::<Bls12_381, Fq381, _, StandardTranscript>()?;
        test_plonk_prover_polynomials_helper::<BW6_761, Fq761, _, StandardTranscript>()?;

        Ok(())
    }

    fn test_plonk_prover_polynomials_helper<E, F, P, T>() -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = F> + Clone,
        T: PlonkTranscript<F>,
    {
        // 1. Simulate universal setup
        let rng = &mut test_rng();
        let n = 64;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        // 2. Create the circuit
        let circuit = gen_circuit_for_test(10, 3)?;
        assert!(circuit.num_gates() <= n);

        // 3. Preprocessing
        let (pk, _) = PlonkKzgSnark::<E>::preprocess(&srs, &circuit)?;

        // 4. Proving
        let (_, oracles, challenges) =
            PlonkKzgSnark::<E>::batch_prove_internal::<_, _, T>(rng, &[&circuit], &[&pk])?;

        // 5. Check that the targeted polynomials evaluate to zero on the vanishing set.
        check_plonk_prover_polynomials(&oracles[0], &pk, &challenges)?;

        Ok(())
    }

    fn check_plonk_prover_polynomials<E: PairingEngine>(
        oracles: &Oracles<E::Fr>,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
    ) -> Result<(), PlonkError> {
        check_circuit_polynomial_on_vanishing_set(&oracles, &pk)?;
        check_perm_polynomials_on_vanishing_set(&oracles, &pk, &challenges)?;

        Ok(())
    }

    fn check_circuit_polynomial_on_vanishing_set<E: PairingEngine>(
        oracles: &Oracles<E::Fr>,
        pk: &ProvingKey<E>,
    ) -> Result<(), PlonkError> {
        let q_lc: Vec<&DensePolynomial<E::Fr>> =
            (0..GATE_WIDTH).map(|j| &pk.selectors[j]).collect();
        let q_mul: Vec<&DensePolynomial<E::Fr>> = (GATE_WIDTH..GATE_WIDTH + 2)
            .map(|j| &pk.selectors[j])
            .collect();
        let q_hash: Vec<&DensePolynomial<E::Fr>> = (GATE_WIDTH + 2..2 * GATE_WIDTH + 2)
            .map(|j| &pk.selectors[j])
            .collect();
        let q_o = &pk.selectors[2 * GATE_WIDTH + 2];
        let q_c = &pk.selectors[2 * GATE_WIDTH + 3];
        let q_ecc = &pk.selectors[2 * GATE_WIDTH + 4];
        let circuit_poly = q_c
            + &oracles.pub_inp_poly
            + oracles.wire_polys[0].mul(q_lc[0])
            + oracles.wire_polys[1].mul(q_lc[1])
            + oracles.wire_polys[2].mul(q_lc[2])
            + oracles.wire_polys[3].mul(q_lc[3])
            + oracles.wire_polys[0]
                .mul(&oracles.wire_polys[1])
                .mul(q_mul[0])
            + oracles.wire_polys[2]
                .mul(&oracles.wire_polys[3])
                .mul(q_mul[1])
            + oracles.wire_polys[0]
                .mul(&oracles.wire_polys[1])
                .mul(&oracles.wire_polys[2])
                .mul(&oracles.wire_polys[3])
                .mul(&oracles.wire_polys[4])
                .mul(q_ecc)
            + oracles.wire_polys[0]
                .mul(&oracles.wire_polys[0])
                .mul(&oracles.wire_polys[0])
                .mul(&oracles.wire_polys[0])
                .mul(&oracles.wire_polys[0])
                .mul(q_hash[0])
            + oracles.wire_polys[1]
                .mul(&oracles.wire_polys[1])
                .mul(&oracles.wire_polys[1])
                .mul(&oracles.wire_polys[1])
                .mul(&oracles.wire_polys[1])
                .mul(q_hash[1])
            + oracles.wire_polys[2]
                .mul(&oracles.wire_polys[2])
                .mul(&oracles.wire_polys[2])
                .mul(&oracles.wire_polys[2])
                .mul(&oracles.wire_polys[2])
                .mul(q_hash[2])
            + oracles.wire_polys[3]
                .mul(&oracles.wire_polys[3])
                .mul(&oracles.wire_polys[3])
                .mul(&oracles.wire_polys[3])
                .mul(&oracles.wire_polys[3])
                .mul(q_hash[3])
            + oracles.wire_polys[4].mul(q_o).neg();

        // check that the polynomial evaluates to zero on the vanishing set
        let domain = Radix2EvaluationDomain::<E::Fr>::new(pk.domain_size())
            .ok_or(PlonkError::DomainCreationError)?;
        for i in 0..domain.size() {
            assert_eq!(circuit_poly.evaluate(&domain.element(i)), E::Fr::zero());
        }

        Ok(())
    }

    fn check_perm_polynomials_on_vanishing_set<E: PairingEngine>(
        oracles: &Oracles<E::Fr>,
        pk: &ProvingKey<E>,
        challenges: &Challenges<E::Fr>,
    ) -> Result<(), PlonkError> {
        let beta = challenges.beta;
        let gamma = challenges.gamma;

        // check that \prod_i [w_i(X) + beta * k_i * X + gamma] * z(X) = \prod_i [w_i(X)
        // + beta * sigma_i(X) + gamma] * z(wX) on the vanishing set
        let one_poly = DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
        let poly_1 = oracles
            .wire_polys
            .iter()
            .enumerate()
            .fold(one_poly.clone(), |acc, (j, w)| {
                let poly =
                    &DensePolynomial::from_coefficients_vec(vec![gamma, beta * pk.k()[j]]) + w;
                acc.mul(&poly)
            });
        let poly_2 =
            oracles
                .wire_polys
                .iter()
                .zip(pk.sigmas.iter())
                .fold(one_poly, |acc, (w, sigma)| {
                    let poly = w.clone()
                        + sigma.mul(beta)
                        + DensePolynomial::from_coefficients_vec(vec![gamma]);
                    acc.mul(&poly)
                });

        let domain = Radix2EvaluationDomain::<E::Fr>::new(pk.domain_size())
            .ok_or(PlonkError::DomainCreationError)?;
        for i in 0..domain.size() {
            let point = domain.element(i);
            let eval_1 = poly_1.evaluate(&point) * oracles.prod_perm_poly.evaluate(&point);
            let eval_2 = poly_2.evaluate(&point)
                * oracles.prod_perm_poly.evaluate(&(point * domain.group_gen));
            assert_eq!(eval_1, eval_2);
        }

        // check z(X) = 1 at point 1
        assert_eq!(
            oracles.prod_perm_poly.evaluate(&domain.element(0)),
            E::Fr::one()
        );

        Ok(())
    }
    #[test]
    fn test_proof_from_to_fields() -> Result<(), PlonkError> {
        test_proof_from_to_fields_helper::<Bn254, _>()?;
        test_proof_from_to_fields_helper::<Bls12_381, _>()?;
        test_proof_from_to_fields_helper::<Bls12_377, _>()?;
        test_proof_from_to_fields_helper::<BW6_761, _>()?;
        Ok(())
    }

    fn test_proof_from_to_fields_helper<E, P>() -> Result<(), PlonkError>
    where
        E: PairingEngine<G1Affine = GroupAffine<P>>,
        E::Fq: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = E::Fq, ScalarField = E::Fr> + Clone,
    {
        let rng = &mut ark_std::test_rng();
        let circuit = gen_circuit_for_test(3, 4)?;
        let max_degree = 80;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        let (pk, _) = PlonkKzgSnark::<E>::preprocess(&srs, &circuit)?;
        let proof = PlonkKzgSnark::<E>::prove::<_, _, StandardTranscript>(rng, &circuit, &pk)?;

        let base_fields: Vec<E::Fq> = proof.clone().into();
        let res: Proof<E> = base_fields.try_into()?;
        assert_eq!(res, proof);

        Ok(())
    }

    #[test]
    fn test_serde() -> Result<(), PlonkError> {
        // merlin transcripts
        test_serde_helper::<Bn254, Fq254, _, StandardTranscript>()?;
        test_serde_helper::<Bls12_377, Fq377, _, StandardTranscript>()?;
        test_serde_helper::<Bls12_381, Fq381, _, StandardTranscript>()?;
        test_serde_helper::<BW6_761, Fq761, _, StandardTranscript>()?;

        Ok(())
    }

    fn test_serde_helper<E, F, P, T>() -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = F> + Clone,
        T: PlonkTranscript<F>,
    {
        let rng = &mut ark_std::test_rng();
        let circuit = gen_circuit_for_test(3, 4)?;
        let max_degree = 80;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        let (pk, vk) = PlonkKzgSnark::<E>::preprocess(&srs, &circuit)?;
        let proof = PlonkKzgSnark::<E>::prove::<_, _, T>(rng, &circuit, &pk)?;

        let mut ser_bytes = Vec::new();
        srs.serialize(&mut ser_bytes)?;
        let de = UniversalSrs::<E>::deserialize(&ser_bytes[..])?;
        assert_eq!(de, srs);

        let mut ser_bytes = Vec::new();
        pk.serialize(&mut ser_bytes)?;
        let de = ProvingKey::<E>::deserialize(&ser_bytes[..])?;
        assert_eq!(de, pk);

        let mut ser_bytes = Vec::new();
        vk.serialize(&mut ser_bytes)?;
        let de = VerifyingKey::<E>::deserialize(&ser_bytes[..])?;
        assert_eq!(de, vk);

        let mut ser_bytes = Vec::new();
        proof.serialize(&mut ser_bytes)?;
        let de = Proof::<E>::deserialize(&ser_bytes[..])?;
        assert_eq!(de, proof);

        Ok(())
    }

    #[test]
    fn test_batch_prove() -> Result<(), PlonkError> {
        // merlin transcripts
        test_batch_prove_helper::<Bn254, Fq254, _, StandardTranscript>()?;
        test_batch_prove_helper::<Bls12_377, Fq377, _, StandardTranscript>()?;
        test_batch_prove_helper::<Bls12_381, Fq381, _, StandardTranscript>()?;
        test_batch_prove_helper::<BW6_761, Fq761, _, StandardTranscript>()?;
        Ok(())
    }

    fn test_batch_prove_helper<E, F, P, T>() -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = F> + Clone,
        T: PlonkTranscript<F>,
    {
        // 1. Simulate universal setup
        let rng = &mut test_rng();
        let n = 128;
        let max_degree = n + 2;
        let srs = PlonkKzgSnark::<E>::universal_setup(max_degree, rng)?;

        // 2. Create many circuits with same domain size
        let circuits = (6..13)
            .map(|i| gen_circuit_for_test::<E::Fr>(i, i))
            .collect::<Result<Vec<_>, PlonkError>>()?; // the number of gates = 4m + 11
        let cs_ref: Vec<&PlonkCircuit<E::Fr>> = circuits.iter().collect();

        // 3. Preprocessing
        let mut prove_keys = vec![];
        let mut verify_keys = vec![];
        for circuit in circuits.iter() {
            let (pk, vk) = PlonkKzgSnark::<E>::preprocess(&srs, circuit)?;
            prove_keys.push(pk);
            verify_keys.push(vk);
        }
        let pks_ref: Vec<&ProvingKey<E>> = prove_keys.iter().collect();
        let vks_ref: Vec<&VerifyingKey<E>> = verify_keys.iter().collect();

        // 4. Batch Proving and verification
        check_batch_prove_and_verify::<_, _, _, _, T>(rng, &cs_ref, &pks_ref, &vks_ref)?;

        Ok(())
    }

    fn check_batch_prove_and_verify<E, F, P, R, T>(
        rng: &mut R,
        cs_ref: &[&PlonkCircuit<E::Fr>],
        pks_ref: &[&ProvingKey<E>],
        vks_ref: &[&VerifyingKey<E>],
    ) -> Result<(), PlonkError>
    where
        E: PairingEngine<Fq = F, G1Affine = GroupAffine<P>>,
        F: RescueParameter + SWToTEConParam,
        P: SWModelParameters<BaseField = F> + Clone,
        R: CryptoRng + RngCore,
        T: PlonkTranscript<F>,
    {
        // Batch Proving
        let batch_proof = PlonkKzgSnark::<E>::batch_prove::<_, _, T>(rng, cs_ref, pks_ref)?;

        // Verification
        let public_inputs: Vec<Vec<E::Fr>> = cs_ref
            .iter()
            .map(|&cs| cs.public_input())
            .collect::<Result<Vec<Vec<E::Fr>>, PlonkError>>()?;
        let pi_ref: Vec<&[E::Fr]> = public_inputs
            .iter()
            .map(|pub_input| &pub_input[..])
            .collect();
        assert!(
            PlonkKzgSnark::<E>::verify_batch_proof::<T>(&vks_ref, &pi_ref, &batch_proof,).is_ok()
        );
        let mut bad_pi_ref = pi_ref.clone();
        bad_pi_ref[0] = bad_pi_ref[1];
        assert!(
            PlonkKzgSnark::<E>::verify_batch_proof::<T>(&vks_ref, &bad_pi_ref, &batch_proof,)
                .is_err()
        );

        Ok(())
    }
}
