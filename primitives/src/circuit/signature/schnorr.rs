// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of a Schnorr signature scheme.

use crate::{
    circuit::rescue::RescueNativeGadget,
    constants::CS_ID_SCHNORR,
    rescue::RescueParameter,
    signatures::schnorr::{Signature, VerKey},
    utils::{challenge_bit_len, field_bit_len},
};
use ark_ec::{twisted_edwards::Affine, AffineRepr, TECurveConfig as Parameters};
use ark_ff::PrimeField;
use ark_std::{vec, vec::Vec};
use jf_relation::{
    errors::CircuitError,
    gadgets::ecc::{Point, PointVariable},
    BoolVar, Circuit, PlonkCircuit, Variable,
};
use jf_utils::fr_to_fq;

#[derive(Debug, Clone)]
/// Signature verification key variable
pub struct VerKeyVar(pub PointVariable);

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
/// Signature variable
pub struct SignatureVar {
    /// s component.
    pub s: Variable,
    /// R component.
    pub R: PointVariable,
}

/// Plonk circuit gadget for EdDSA signatures.
// FIXME -- clear this todo
// TODO: check the parameters and the security level of the signature scheme.
pub trait SignatureGadget<F, P>
where
    F: RescueParameter,
    P: Parameters<BaseField = F>,
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
    ) -> Result<(), CircuitError>;

    /// Obtain the result bit of a signature verification.
    /// * `vk` - signature verification key variable.
    /// * `msg` - message variables that have been signed.
    /// * `sig` - signature variable.
    /// * `returns` - a bool variable indicating whether the signature is valid.
    fn check_signature_validity(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<BoolVar, CircuitError>;

    /// Create a signature variable from a signature `sig`.
    fn create_signature_variable(
        &mut self,
        sig: &Signature<P>,
    ) -> Result<SignatureVar, CircuitError>;

    /// Create a signature verification key variable from a key `vk`.
    fn create_signature_vk_variable(&mut self, vk: &VerKey<P>) -> Result<VerKeyVar, CircuitError>;

    /// Compute the two point variables to be compared in the signature
    /// verification circuit.
    fn verify_sig_core(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<(PointVariable, PointVariable), CircuitError>;
}

impl<F, P> SignatureGadget<F, P> for PlonkCircuit<F>
where
    F: RescueParameter,
    P: Parameters<BaseField = F>,
{
    fn verify_signature(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<(), CircuitError> {
        // p1 = s * G, p2 = sig.R + c * VK
        let (p1, p2) = <Self as SignatureGadget<F, P>>::verify_sig_core(self, vk, msg, sig)?;
        self.enforce_point_equal(&p1, &p2)?;
        Ok(())
    }

    fn check_signature_validity(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<BoolVar, CircuitError> {
        let (p1, p2) = <Self as SignatureGadget<F, P>>::verify_sig_core(self, vk, msg, sig)?;
        self.is_point_equal(&p1, &p2)
    }

    fn create_signature_variable(
        &mut self,
        sig: &Signature<P>,
    ) -> Result<SignatureVar, CircuitError> {
        let sig_var = SignatureVar {
            s: self.create_variable(fr_to_fq::<F, P>(&sig.s))?,
            R: self.create_point_variable(Point::from(sig.R))?,
        };
        Ok(sig_var)
    }

    fn create_signature_vk_variable(&mut self, vk: &VerKey<P>) -> Result<VerKeyVar, CircuitError> {
        let vk_var = VerKeyVar(self.create_point_variable(Point::from(vk.0))?);
        Ok(vk_var)
    }

    fn verify_sig_core(
        &mut self,
        vk: &VerKeyVar,
        msg: &[Variable],
        sig: &SignatureVar,
    ) -> Result<(PointVariable, PointVariable), CircuitError> {
        let c_bits_le =
            <Self as SignatureHelperGadget<F, P>>::challenge_bits(self, vk, &sig.R, msg)?;
        let base = Affine::<P>::generator();
        let x = self.fixed_base_scalar_mul(sig.s, &base)?;
        let z = self.variable_base_binary_scalar_mul::<P>(&c_bits_le, &vk.0)?;
        let y = self.ecc_add::<P>(&sig.R, &z)?;

        Ok((x, y))
    }
}
trait SignatureHelperGadget<F, P>
where
    F: PrimeField,
    P: Parameters<BaseField = F>,
{
    // Return signature hash challenge in little-endian binary form.
    fn challenge_bits(
        &mut self,
        vk: &VerKeyVar,
        sig_point: &PointVariable,
        msg: &[Variable],
    ) -> Result<Vec<BoolVar>, CircuitError>;
}

impl<F, P> SignatureHelperGadget<F, P> for PlonkCircuit<F>
where
    F: RescueParameter,
    P: Parameters<BaseField = F>,
{
    fn challenge_bits(
        &mut self,
        vk: &VerKeyVar,
        sig_point: &PointVariable,
        msg: &[Variable],
    ) -> Result<Vec<BoolVar>, CircuitError> {
        let instance_description = F::from_be_bytes_mod_order(CS_ID_SCHNORR.as_ref());
        // TODO: create `inst_desc_var` and the constant gate *only once* during the
        // entire circuit construction.
        let inst_desc_var = self.create_variable(instance_description)?;
        self.enforce_constant(inst_desc_var, instance_description)?;
        let mut chal_input = vec![
            inst_desc_var,
            vk.0.get_x(),
            vk.0.get_y(),
            sig_point.get_x(),
            sig_point.get_y(),
        ];
        chal_input.extend(msg);

        let challenge =
            RescueNativeGadget::<F>::rescue_sponge_with_padding(self, &chal_input, 1)?[0];
        let c_bits = self.unpack(challenge, field_bit_len::<F>())?;
        Ok(c_bits[..challenge_bit_len::<F>()].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::schnorr::{KeyPair, Signature, VerKey};
    use ark_ed_on_bls12_377::EdwardsConfig as Param377;
    use ark_ed_on_bls12_381::EdwardsConfig as Param381;
    use ark_ed_on_bls12_381_bandersnatch::EdwardsConfig as Param381b;
    use ark_ed_on_bn254::EdwardsConfig as Param254;
    use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit, Variable};

    #[test]
    fn test_dsa_circuit() -> Result<(), CircuitError> {
        test_dsa_circuit_helper::<_, Param377>()?;
        test_dsa_circuit_helper::<_, Param381>()?;
        test_dsa_circuit_helper::<_, Param381b>()?;
        test_dsa_circuit_helper::<_, Param254>()
    }

    fn test_dsa_circuit_helper<F, P>() -> Result<(), CircuitError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F>,
    {
        let mut rng = ark_std::test_rng();
        let keypair = KeyPair::<P>::generate(&mut rng);
        let vk = keypair.ver_key_ref();
        let vk_bad: VerKey<P> = KeyPair::<P>::generate(&mut rng).ver_key_ref().clone();
        let msg: Vec<F> = (0..20).map(|i| F::from(i as u64)).collect();
        let mut msg_bad = msg.clone();
        msg_bad[0] = F::from(2u64);
        let sig = keypair.sign(&msg, CS_ID_SCHNORR);
        let sig_bad = keypair.sign(&msg_bad, CS_ID_SCHNORR);
        vk.verify(&msg, &sig, CS_ID_SCHNORR).unwrap();

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
    ) -> Result<PlonkCircuit<F>, CircuitError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F>,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let vk_var = circuit.create_signature_vk_variable(vk)?;
        let sig_var = circuit.create_signature_variable(sig)?;
        let msg_var: Vec<Variable> = msg
            .iter()
            .map(|m| circuit.create_variable(*m))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        SignatureGadget::<F, P>::verify_signature(&mut circuit, &vk_var, &msg_var, &sig_var)?;
        Ok(circuit)
    }

    fn build_is_valid_signature_circuit<P, F>(
        vk: &VerKey<P>,
        msg: &[F],
        sig: &Signature<P>,
    ) -> Result<(PlonkCircuit<F>, Variable), CircuitError>
    where
        F: RescueParameter,
        P: Parameters<BaseField = F>,
    {
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let vk_var = circuit.create_signature_vk_variable(vk)?;
        let sig_var = circuit.create_signature_variable(sig)?;
        let msg_var: Vec<Variable> = msg
            .iter()
            .map(|m| circuit.create_variable(*m))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let bit = SignatureGadget::<_, P>::check_signature_validity(
            &mut circuit,
            &vk_var,
            &msg_var,
            &sig_var,
        )?;
        Ok((circuit, bit.into()))
    }
}
