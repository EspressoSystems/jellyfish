// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of the ElGamal scheme.

use crate::{Ciphertext, EncKey};
use ark_ec::{
    twisted_edwards::{Affine, TECurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use ark_std::{vec, vec::Vec};
use jf_relation::{
    gadgets::ecc::{PointVariable, TEPoint},
    Circuit, CircuitError, PlonkCircuit, Variable,
};
use jf_rescue::{
    gadgets::{RescueGadget, RescueStateVar},
    RescueParameter, PRP, STATE_SIZE,
};

/// Variables holding an encryption key.
#[derive(Debug)]
pub struct EncKeyVars(pub PointVariable);

/// Variables holding a ciphertext.
#[derive(Debug)]
pub struct ElGamalHybridCtxtVars {
    /// r*G component
    pub ephemeral: PointVariable,
    /// Ciphertext under hybrid encryption.
    pub symm_ctxts: Vec<Variable>,
}

/// Helper methods for counter-mode encryption.
trait ElGamalEncryptionHelperGadget<F>
where
    F: PrimeField,
{
    /// Counter mode encryption with no padding.
    fn apply_counter_mode_stream_no_padding(
        &mut self,
        key_var: &RescueStateVar,
        data_vars: &[RescueStateVar],
    ) -> Result<Vec<RescueStateVar>, CircuitError>;

    /// Counter mode encryption with padding.
    fn apply_counter_mode_stream(
        &mut self,
        key_var: &RescueStateVar,
        data_vars: &[Variable],
    ) -> Result<Vec<Variable>, CircuitError>;
}

impl<F> ElGamalEncryptionHelperGadget<F> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn apply_counter_mode_stream_no_padding(
        &mut self,
        key_var: &RescueStateVar,
        data_vars: &[RescueStateVar],
    ) -> Result<Vec<RescueStateVar>, CircuitError> {
        let zero_var = self.zero();
        let prp_instance = PRP::default();
        let mds_states = prp_instance.mds_matrix_ref();
        let round_keys_var = self.key_schedule(mds_states, key_var, &prp_instance)?;
        let mut counter_var = zero_var;

        data_vars
            .iter()
            .map(|output_chunk_vars| {
                let stream_chunk_vars = self.prp_with_round_keys(
                    &RescueStateVar::from([counter_var, zero_var, zero_var, zero_var]),
                    mds_states,
                    &round_keys_var,
                )?;
                counter_var = self.add_constant(counter_var, &F::one())?;

                output_chunk_vars
                    .array()
                    .iter()
                    .zip(stream_chunk_vars.array())
                    .map(|(output_var, stream_var)| self.add(*output_var, *stream_var))
                    .collect()
            })
            .collect()
    }

    fn apply_counter_mode_stream(
        &mut self,
        key_var: &RescueStateVar,
        data_vars: &[Variable],
    ) -> Result<Vec<Variable>, CircuitError> {
        let zero_var = self.zero();
        let mut data_vars_vec = data_vars.to_vec();
        let len = data_vars_vec.len();
        let new_len = compute_len_to_next_multiple(len, STATE_SIZE);

        while data_vars_vec.len() < new_len {
            data_vars_vec.push(zero_var);
        }

        let mut data_vars_states = vec![];
        for block in data_vars_vec.chunks(STATE_SIZE) {
            let state = RescueStateVar::from([block[0], block[1], block[2], block[3]]);
            data_vars_states.push(state);
        }

        let encrypted_output_var_states =
            self.apply_counter_mode_stream_no_padding(key_var, data_vars_states.as_slice())?;

        let mut output_vars: Vec<Variable> = vec![];
        let mut num_vars = 0;
        for state in encrypted_output_var_states {
            let state_array = state.array();
            for variable in state_array.iter().take(STATE_SIZE) {
                if num_vars == len {
                    break;
                }
                output_vars.push(*variable);
                num_vars += 1;
            }
        }
        Ok(output_vars)
    }
}

/// Circuit implementation of the ElGamal scheme.
pub trait ElGamalEncryptionGadget<F, P>
where
    F: PrimeField,
    P: TECurveConfig<BaseField = F>,
{
    fn elgamal_encrypt(
        &mut self,
        pk_vars: &EncKeyVars,
        data_vars: &[Variable],
        r: Variable,
    ) -> Result<ElGamalHybridCtxtVars, CircuitError>;

    fn create_enc_key_variable(&mut self, pk: &EncKey<P>) -> Result<EncKeyVars, CircuitError>;

    fn create_ciphertext_variable(
        &mut self,
        ctxts: &Ciphertext<P>,
    ) -> Result<ElGamalHybridCtxtVars, CircuitError>;
}

impl<F, P> ElGamalEncryptionGadget<F, P> for PlonkCircuit<F>
where
    F: RescueParameter,
    P: TECurveConfig<BaseField = F>,
{
    fn elgamal_encrypt(
        &mut self,
        pk_var: &EncKeyVars,
        data_vars: &[Variable],
        r: Variable,
    ) -> Result<ElGamalHybridCtxtVars, CircuitError> {
        let shared_pk_var = self.variable_base_scalar_mul::<P>(r, &pk_var.0)?;
        let zero_var = self.zero();
        let key_perm_input_var = RescueStateVar::from([
            shared_pk_var.get_x(),
            shared_pk_var.get_y(),
            zero_var,
            zero_var,
        ]);
        let symm_key_vars = self.rescue_permutation(key_perm_input_var)?;

        let symm_ctxts = self.apply_counter_mode_stream(&symm_key_vars, data_vars)?;
        let base = Affine::<P>::generator();
        let ephemeral = self.fixed_base_scalar_mul(r, &base)?;
        Ok(ElGamalHybridCtxtVars {
            ephemeral,
            symm_ctxts,
        })
    }

    fn create_enc_key_variable(&mut self, pk: &EncKey<P>) -> Result<EncKeyVars, CircuitError> {
        let point = TEPoint::from(pk.key.into_affine());
        let point_variable = self.create_point_variable(point)?;
        Ok(EncKeyVars(point_variable))
    }

    fn create_ciphertext_variable(
        &mut self,
        ctxts: &Ciphertext<P>,
    ) -> Result<ElGamalHybridCtxtVars, CircuitError> {
        let ephemeral =
            self.create_point_variable(TEPoint::from(ctxts.ephemeral.key.into_affine()))?;
        let symm_ctxts = ctxts
            .data
            .iter()
            .map(|&msg| self.create_variable(msg))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        Ok(ElGamalHybridCtxtVars {
            ephemeral,
            symm_ctxts,
        })
    }
}

#[inline]
fn compute_len_to_next_multiple(len: usize, multiple: usize) -> usize {
    if len % multiple == 0 {
        len
    } else {
        len + multiple - len % multiple
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{twisted_edwards::TECurveConfig, CurveGroup};
    use ark_ed_on_bls12_377::{EdwardsConfig as ParamEd377, Fq as FqEd377};
    use ark_ed_on_bls12_381::{EdwardsConfig as ParamEd381, Fq as FqEd381};
    use ark_ff::UniformRand;
    use ark_std::vec;
    use jf_relation::{Circuit, PlonkCircuit, Variable};
    use jf_rescue::{RescueParameter, STATE_SIZE};

    #[test]
    fn test_elgamal_hybrid_encrypt_circuit() {
        // Example for one curve type; repeat for other curve types
        let mut circuit = PlonkCircuit::<FqEd377>::new_turbo_plonk();
        let mut prng = jf_utils::test_rng();

        let keypair = KeyPair::<ParamEd377>::generate(&mut prng);
        let pk_var = circuit.create_enc_key_variable(keypair.enc_key_ref()).unwrap();

        let data: Vec<FqEd377> = (0..10).map(FqEd377::from).collect();
        let data_vars: Vec<Variable> = data
            .iter()
            .map(|x| circuit.create_variable(*x).unwrap())
            .collect();

        let r = ParamEd377::ScalarField::rand(&mut prng);
        let enc_rand_var = circuit.create_variable(r.into()).unwrap();

        let ctxts_vars = ElGamalEncryptionGadget::<_, ParamEd377>::elgamal_encrypt(
            &mut circuit,
            &pk_var,
            data_vars.as_slice(),
            enc_rand_var,
        )
        .unwrap();

        assert_eq!(ctxts_vars.symm_ctxts.len(), data_vars.len());
    }
}
