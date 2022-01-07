use crate::{
    constants::{challenge_bit_len, field_bit_len},
    schnorr_dsa::{Signature, VerKey, DOMAIN_SEPARATION},
};
use ark_ec::{twisted_edwards_extended::GroupAffine, AffineCurve, TEModelParameters as Parameters};
use ark_ff::PrimeField;
use ark_std::{vec, vec::Vec};
use jf_plonk::{
    circuit::{
        customized::{
            ecc::{Point, PointVariable},
            rescue::RescueGadget,
        },
        Circuit, PlonkCircuit, Variable,
    },
    errors::PlonkError,
};
use jf_rescue::RescueParameter;
use jf_utils::fr_to_fq;

#[derive(Debug, Clone)]
/// Signature verification key variable
pub struct VerKeyVar(pub PointVariable);

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
/// Signature variable
pub struct SignatureVar {
    pub s: Variable,
    pub R: PointVariable,
}

/// Plonk circuit gadget for EdDSA signatures.
/// TODO: check the parameters and the security level of the signature scheme.
pub trait SignatureGadget<F, P>
where
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
{
    /// Signature verification circuit
    /// * `vk` - signature verification key variable.
    /// * `msg` - message variables that have been signed.
    /// * `sig` - signature variable.
    fn verify_signature(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<(), PlonkError>;

    /// Obtain the result bit of a signature verification.
    /// * `vk` - signature verification key variable.
    /// * `msg` - message variables that have been signed.
    /// * `sig` - signature variable.
    /// * `returns` - a bool variable indicating whether the signature is valid.
    fn is_valid_signature(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<Variable, PlonkError>;

    /// Create a signature variable from a signature `sig`.
    fn create_signature_variable(&mut self, sig: &Signature<P>)
        -> Result<SignatureVar, PlonkError>;

    /// Create a signature verification key variable from a key `vk`.
    fn create_signature_vk_variable(&mut self, vk: &VerKey<P>) -> Result<VerKeyVar, PlonkError>;
}

impl<F, P> SignatureGadget<F, P> for PlonkCircuit<F>
where
    Self: SignatureHelperGadget<F, P>,
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
{
    fn verify_signature(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<(), PlonkError> {
        // p1 = s * G, p2 = sig.R + c * VK
        let (p1, p2) = self.verify_sig_internal(vk, msg, sig)?;
        self.point_equal_gate(&p1, &p2)?;
        Ok(())
    }

    fn is_valid_signature(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<Variable, PlonkError> {
        let (p1, p2) = self.verify_sig_internal(vk, msg, sig)?;
        self.is_equal_point(&p1, &p2)
    }

    fn create_signature_variable(
        &mut self,
        sig: &Signature<P>,
    ) -> Result<SignatureVar, PlonkError> {
        let sig_var = SignatureVar {
            s: self.create_variable(fr_to_fq::<F, P>(&sig.s))?,
            R: self.create_point_variable(Point::from(sig.R))?,
        };
        Ok(sig_var)
    }

    fn create_signature_vk_variable(&mut self, vk: &VerKey<P>) -> Result<VerKeyVar, PlonkError> {
        let vk_var = VerKeyVar(self.create_point_variable(Point::from(vk.0))?);
        Ok(vk_var)
    }
}
pub trait SignatureHelperGadget<F, P>
where
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
{
    // Compute the two point variables to be compared in the signature verification
    // circuit.
    fn verify_sig_internal(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<(PointVariable, PointVariable), PlonkError>;

    // Return signature hash challenge in little-endian binary form.
    fn challenge_bits(
        &mut self,
        vk: &VerKeyVar,
        sig_point: &PointVariable,
        msg: &[Variable],
    ) -> Result<Vec<Variable>, PlonkError>;
}

impl<F, P> SignatureHelperGadget<F, P> for PlonkCircuit<F>
where
    F: RescueParameter,
    P: Parameters<BaseField = F> + Clone,
{
    fn verify_sig_internal(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<(PointVariable, PointVariable), PlonkError> {
        let c_bits_le =
            <Self as SignatureHelperGadget<F, P>>::challenge_bits(self, vk, &sig.R, msg)?;
        let base = GroupAffine::<P>::prime_subgroup_generator();
        let x = self.fixed_base_scalar_mul(sig.s, &base)?;
        let z = self.variable_base_binary_scalar_mul::<P>(&c_bits_le, &vk.0)?;
        let y = self.ecc_add::<P>(&sig.R, &z)?;

        Ok((x, y))
    }

    fn challenge_bits(
        &mut self,
        vk: &VerKeyVar,
        sig_point: &PointVariable,
        msg: &[Variable],
    ) -> Result<Vec<Variable>, PlonkError> {
        let instance_description = F::from_be_bytes_mod_order(DOMAIN_SEPARATION);
        // TODO: create `inst_desc_var` and the constant gate *only once* during the
        // entire circuit construction.
        let inst_desc_var = self.create_variable(instance_description)?;
        self.constant_gate(inst_desc_var, instance_description)?;
        let mut chal_input = vec![
            inst_desc_var,
            vk.0.get_x(),
            vk.0.get_y(),
            sig_point.get_x(),
            sig_point.get_y(),
        ];
        chal_input.extend(msg);

        let challenge = self.rescue_sponge_with_padding(&chal_input, 1)?[0];
        let c_bits = self.unpack(challenge, field_bit_len::<F>() as usize)?;
        Ok(c_bits[..challenge_bit_len::<F>()].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        circuit::schnorr_dsa::*,
        schnorr_dsa::{KeyPair, Signature, VerKey},
    };
    use ark_ed_on_bls12_377::EdwardsParameters as Param377;
    use ark_ed_on_bls12_381::EdwardsParameters as Param381;
    use ark_ed_on_bls12_381_bandersnatch::EdwardsParameters as Param381b;
    use ark_ed_on_bn254::EdwardsParameters as Param254;
    use jf_plonk::{
        circuit::{Circuit, PlonkCircuit, Variable},
        errors::PlonkError,
    };

    #[test]
    fn test_dsa_circuit() -> Result<(), PlonkError> {
        test_dsa_circuit_helper::<_, Param377>()?;
        test_dsa_circuit_helper::<_, Param381>()?;
        test_dsa_circuit_helper::<_, Param381b>()?;
        test_dsa_circuit_helper::<_, Param254>()
    }

    fn test_dsa_circuit_helper<F, P>() -> Result<(), PlonkError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F> + Clone,
    {
        let mut rng = ark_std::test_rng();
        let keypair = KeyPair::<P>::generate(&mut rng);
        let vk = keypair.ver_key_ref();
        let vk_bad: VerKey<P> = KeyPair::<P>::generate(&mut rng).ver_key_ref().clone();
        let msg: Vec<F> = (0..20).map(|i| F::from(i as u64)).collect();
        let mut msg_bad = msg.clone();
        msg_bad[0] = F::from(2 as u64);
        let sig = keypair.sign(&msg);
        let sig_bad = keypair.sign(&msg_bad);
        vk.verify(&msg, &sig).unwrap();

        // Test `verify_signature()`
        // Good path
        let circuit = build_verify_sig_circuit(vk, &msg, &sig)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // Bad verification key
        let bad_circuit = build_verify_sig_circuit(&vk_bad, &msg, &sig)?;
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_err());
        // Bad signature
        let bad_circuit = build_verify_sig_circuit(vk, &msg, &sig_bad)?;
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_err());
        // Bad message
        let bad_circuit = build_verify_sig_circuit(vk, &msg_bad, &sig)?;
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_err());

        // Test `is_valid_signature()`
        // Good path
        let (mut circuit, bit) = build_is_valid_signature_circuit(vk, &msg, &sig)?;
        assert_eq!(circuit.witness(bit)?, F::one());
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        // Bad output bit
        *circuit.witness_mut(bit) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        // Bad verification key
        let (mut bad_circuit, bit) = build_is_valid_signature_circuit(&vk_bad, &msg, &sig)?;
        assert_eq!(bad_circuit.witness(bit)?, F::zero());
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_ok());
        *bad_circuit.witness_mut(bit) = F::one();
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_err());
        // Bad signature
        let (mut bad_circuit, bit) = build_is_valid_signature_circuit(vk, &msg, &sig_bad)?;
        assert_eq!(bad_circuit.witness(bit)?, F::zero());
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_ok());
        *bad_circuit.witness_mut(bit) = F::one();
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_err());
        // Bad message
        let (mut bad_circuit, bit) = build_is_valid_signature_circuit(vk, &msg_bad, &sig)?;
        assert_eq!(bad_circuit.witness(bit)?, F::zero());
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_ok());
        *bad_circuit.witness_mut(bit) = F::one();
        assert!(bad_circuit.check_circuit_satisfiability(&[]).is_err());

        Ok(())
    }

    fn build_verify_sig_circuit<F, P>(
        vk: &VerKey<P>,
        msg: &[F],
        sig: &Signature<P>,
    ) -> Result<PlonkCircuit<F>, PlonkError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F> + Clone,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let vk_var = circuit.create_signature_vk_variable(vk)?;
        let sig_var = circuit.create_signature_variable(sig)?;
        let msg_var: Vec<Variable> = msg
            .iter()
            .map(|m| circuit.create_variable(*m))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        SignatureGadget::<F, P>::verify_signature(&mut circuit, &vk_var, &msg_var, &sig_var)?;
        Ok(circuit)
    }

    fn build_is_valid_signature_circuit<P, F>(
        vk: &VerKey<P>,
        msg: &[F],
        sig: &Signature<P>,
    ) -> Result<(PlonkCircuit<F>, Variable), PlonkError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F> + Clone,
    {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let vk_var = circuit.create_signature_vk_variable(vk)?;
        let sig_var = circuit.create_signature_variable(sig)?;
        let msg_var: Vec<Variable> = msg
            .iter()
            .map(|m| circuit.create_variable(*m))
            .collect::<Result<Vec<_>, PlonkError>>()?;
        let bit =
            SignatureGadget::<_, P>::is_valid_signature(&mut circuit, &vk_var, &msg_var, &sig_var)?;
        Ok((circuit, bit))
    }
}
