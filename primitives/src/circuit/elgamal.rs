// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Circuit implementation of the ElGamal scheme.

use crate::{
    circuit::rescue::{RescueGadget, RescueStateVar},
    elgamal::{Ciphertext, EncKey},
    rescue::{RescueParameter, PRP, STATE_SIZE},
};
use ark_ec::{
    twisted_edwards::{Affine, TECurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use ark_std::{vec, vec::Vec};
use jf_relation::{
    errors::CircuitError,
    gadgets::ecc::{Point, PointVariable},
    Circuit, PlonkCircuit, Variable,
};
use jf_utils::compute_len_to_next_multiple;

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

trait ElGamalEncryptionHelperGadget<F>
where
    F: PrimeField,
{
    /// Rescue counter mode encryption with no padding
    /// The key should be a fresh one in each call, and the nonce is initialized
    /// to zero.
    /// * `key_var` - variables corresponding to the symmetric key
    /// * `data_vars` - the variables for the data to be encrypted. The format
    ///   of this input is a list of rescue states.
    /// * `returns` - the variables that map to the ciphertext contents
    fn apply_counter_mode_stream_no_padding(
        &mut self,
        key_var: &RescueStateVar,
        data_vars: &[RescueStateVar],
    ) -> Result<Vec<RescueStateVar>, CircuitError>;

    /// Rescue counter mode encryption with padding
    /// The function pads the input data and then calls
    /// apply_counter_mode_stream_no_padding The key should be a fresh one
    /// in each call, and the nonce is initialized to zero.
    /// * `key_var` - variables corresponding to the symmetric key
    /// * `data_vars` - the variables for the data to be encrypted. The format
    ///   of this input is a list of variable of arbitrary length
    /// * `returns` - the variables that map to the ciphertext contents. The
    ///   output size is the same as the length of data_vars
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

        let mut output_vars = data_vars.to_vec();

        // Schedule the keys
        let prp_instance = PRP::default();
        let mds_states = prp_instance.mds_matrix_ref();
        let round_keys_var = self.key_schedule(mds_states, key_var, &prp_instance)?;

        // Compute stream

        // nonce == 0
        let mut counter_var = zero_var;

        output_vars
            .iter_mut()
            .try_for_each(|output_chunk_vars| -> Result<(), CircuitError> {
                let stream_chunk_vars = self.prp_with_round_keys(
                    &RescueStateVar::from([counter_var, zero_var, zero_var, zero_var]),
                    mds_states,
                    &round_keys_var,
                )?;

                // Increment the counter
                counter_var = self.add_constant(counter_var, &F::one())?;

                for (output_chunk_var, stream_chunk_var) in output_chunk_vars
                    .array_mut()
                    .iter_mut()
                    .zip(stream_chunk_vars.array().iter())
                {
                    *output_chunk_var = self.add(*output_chunk_var, *stream_chunk_var)?;
                }
                Ok(())
            })?;

        Ok(output_vars)
    }

    fn apply_counter_mode_stream(
        &mut self,
        key_var: &RescueStateVar,
        data_vars: &[Variable],
    ) -> Result<Vec<Variable>, CircuitError> {
        let zero_var = self.zero();

        // Compute the length of padded input
        let mut data_vars_vec = data_vars.to_vec();
        let len = data_vars_vec.len();
        let new_len = compute_len_to_next_multiple(len, STATE_SIZE);

        // Pad the input
        while data_vars_vec.len() < new_len {
            data_vars_vec.push(zero_var);
        }

        // Group data_vars in chunks of state size
        let mut data_vars_states = vec![];
        for block in data_vars_vec.chunks(STATE_SIZE) {
            let state = RescueStateVar::from([block[0], block[1], block[2], block[3]]);
            data_vars_states.push(state);
        }
        let encrypted_output_var_states =
            self.apply_counter_mode_stream_no_padding(key_var, data_vars_states.as_slice())?;

        // Rebuild the output getting rid of the extra variables
        let mut output_vars: Vec<Variable> = vec![];
        let mut num_vars = 0;
        for state in encrypted_output_var_states {
            let state_array = state.array();
            for variable in state_array.iter().take(STATE_SIZE) {
                if num_vars == len {
                    // We are not interested in the padding variables
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
    /// Compute the gadget that check a correct Elgamal encryption
    /// * `pk_vars` - variables corresponding to the encryption public key
    /// * `data_vars` - variables corresponding to the plaintext. Can be of
    ///   arbitrary length.
    /// * `r` - variable corresponding to the encryption randomness
    /// * `returns` - variables corresponding to the ciphertext
    fn elgamal_encrypt(
        &mut self,
        pk_vars: &EncKeyVars,
        data_vars: &[Variable],
        r: Variable,
    ) -> Result<ElGamalHybridCtxtVars, CircuitError>;

    /// Helper function to create encryption key variables struct
    /// * `pk` - encryption public key
    /// * `returns` - struct containing the variables corresponding to `p`
    fn create_enc_key_variable(&mut self, pk: &EncKey<P>) -> Result<EncKeyVars, CircuitError>;

    /// Helper function to create a ciphertext variable
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
        let point = Point::from(pk.key.into_affine());
        let point_variable = self.create_point_variable(point)?;
        Ok(EncKeyVars(point_variable))
    }

    fn create_ciphertext_variable(
        &mut self,
        ctxts: &Ciphertext<P>,
    ) -> Result<ElGamalHybridCtxtVars, CircuitError> {
        let ephemeral =
            self.create_point_variable(Point::from(ctxts.ephemeral.key.into_affine()))?;
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

#[cfg(test)]
mod tests {
    use crate::{
        circuit::{
            elgamal::{ElGamalEncryptionGadget, ElGamalEncryptionHelperGadget},
            rescue::RescueGadget,
        },
        elgamal::{apply_counter_mode_stream, Direction::Encrypt, KeyPair},
        rescue::{RescueParameter, RescueVector, STATE_SIZE},
    };
    use ark_ec::{twisted_edwards::TECurveConfig, CurveGroup};
    use ark_ed_on_bls12_377::{EdwardsConfig as ParamEd377, Fq as FqEd377};
    use ark_ed_on_bls12_381::{EdwardsConfig as ParamEd381, Fq as FqEd381};
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsConfig as ParamEd381b, Fq as FqEd381b};
    use ark_ed_on_bn254::{EdwardsConfig as ParamEd254, Fq as FqEd254};
    use ark_ff::UniformRand;
    use ark_std::{vec, vec::Vec};
    use jf_relation::{gadgets::ecc::Point, Circuit, PlonkCircuit, Variable};
    use jf_utils::fr_to_fq;

    #[test]
    fn apply_counter_mode_stream_no_padding() {
        apply_counter_mode_stream_no_padding_helper::<FqEd254, ParamEd254>();
        apply_counter_mode_stream_no_padding_helper::<FqEd377, ParamEd377>();
        apply_counter_mode_stream_no_padding_helper::<FqEd381, ParamEd381>();
        apply_counter_mode_stream_no_padding_helper::<FqEd381b, ParamEd381b>();
    }

    fn apply_counter_mode_stream_no_padding_helper<F, P>()
    where
        F: RescueParameter,
        P: TECurveConfig<BaseField = F>,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let mut prng = jf_utils::test_rng();
        let key = RescueVector::from(&[
            F::rand(&mut prng),
            F::rand(&mut prng),
            F::rand(&mut prng),
            F::rand(&mut prng),
        ]);

        let key_var = circuit.create_rescue_state_variable(&key).unwrap();
        let mut data_vars = vec![];
        let mut data = vec![];

        let n_blocks = 10;
        for i in 0..n_blocks * STATE_SIZE {
            data.push(F::from(i as u32));
        }

        for block in data.chunks(STATE_SIZE) {
            let block_vector = RescueVector::from(block);
            data_vars.push(circuit.create_rescue_state_variable(&block_vector).unwrap());
        }

        let ctxts_vars = circuit
            .apply_counter_mode_stream_no_padding(&key_var, data_vars.as_slice())
            .unwrap();

        let encrypted_data = apply_counter_mode_stream::<F>(&key, &data, &F::zero(), Encrypt);

        let mut blocks = vec![];

        // Transfer updated data into blocks
        for block in encrypted_data.chunks(STATE_SIZE) {
            let block_vector = RescueVector::from(block);
            blocks.push(block_vector);
        }

        // Check ciphertext consistency
        for (ctxt, ctxt_var) in blocks.iter().zip(ctxts_vars.iter()) {
            for (val, var) in ctxt.elems().iter().zip(ctxt_var.array().iter()) {
                assert_eq!(*val, circuit.witness(*var).unwrap());
            }
        }

        // Check constraints
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        *circuit.witness_mut(ctxts_vars[0].array()[0]) = F::from(1_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]
    fn test_elgamal_hybrid_encrypt_circuit() {
        test_elgamal_hybrid_encrypt_circuit_helper::<FqEd254, ParamEd254>();
        test_elgamal_hybrid_encrypt_circuit_helper::<FqEd377, ParamEd377>();
        test_elgamal_hybrid_encrypt_circuit_helper::<FqEd381, ParamEd381>();
        test_elgamal_hybrid_encrypt_circuit_helper::<FqEd381b, ParamEd381b>();
    }
    fn test_elgamal_hybrid_encrypt_circuit_helper<F, P>()
    where
        F: RescueParameter,
        P: TECurveConfig<BaseField = F>,
    {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();

        let mut prng = jf_utils::test_rng();

        // Prepare data and keys
        let keypair = KeyPair::<P>::generate(&mut prng);
        let pub_key = keypair.enc_key_ref();
        let pk_var = circuit.create_enc_key_variable(pub_key).unwrap();

        // the input size is a non multiple of STATE_SIZE
        let data: Vec<F> = (0..5 * STATE_SIZE + 1).map(|i| F::from(i as u32)).collect();
        let input_len = data.len();
        let data_vars: Vec<Variable> = data
            .iter()
            .map(|x| circuit.create_variable(*x).unwrap())
            .collect();

        let r = P::ScalarField::rand(&mut prng);
        let enc_rand_var = circuit.create_variable(fr_to_fq::<F, P>(&r)).unwrap();

        // Encrypt
        let pub_key = keypair.enc_key();
        let ctxts = pub_key.deterministic_encrypt(r, &data);

        let ctxts_vars = ElGamalEncryptionGadget::<_, P>::elgamal_encrypt(
            &mut circuit,
            &pk_var,
            data_vars.as_slice(),
            enc_rand_var,
        )
        .unwrap();

        // The plaintext and ciphertext must have the same length
        assert_eq!(input_len, ctxts_vars.symm_ctxts.len());

        // Check ciphertexts
        assert_eq!(
            Point::from(ctxts.ephemeral.key.into_affine()),
            circuit.point_witness(&ctxts_vars.ephemeral).unwrap()
        );

        for (ctxt, ctxt_var) in ctxts.data.iter().zip(ctxts_vars.symm_ctxts.clone()) {
            assert_eq!(*ctxt, circuit.witness(ctxt_var).unwrap());
        }

        // Check circuit satisfiability
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter public key
        let old_pk_var_0 = circuit.witness(pk_var.0.get_x()).unwrap();
        *circuit.witness_mut(pk_var.0.get_x()) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(pk_var.0.get_x()) = old_pk_var_0;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter encryption randomness
        let old_ephemeral_point_x = circuit.witness(ctxts_vars.ephemeral.get_x()).unwrap();
        *circuit.witness_mut(ctxts_vars.ephemeral.get_x()) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(ctxts_vars.ephemeral.get_x()) = old_ephemeral_point_x;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Alter ciphertext
        *circuit.witness_mut(ctxts_vars.symm_ctxts[0]) = F::from(0_u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
    }

    #[test]

    fn test_create_ciphertext_variable() {
        test_create_ciphertext_variable_helper::<FqEd254, ParamEd254>();
        test_create_ciphertext_variable_helper::<FqEd377, ParamEd377>();
        test_create_ciphertext_variable_helper::<FqEd381, ParamEd381>();
        test_create_ciphertext_variable_helper::<FqEd381b, ParamEd381b>();
    }
    fn test_create_ciphertext_variable_helper<F, P>()
    where
        F: RescueParameter,
        P: TECurveConfig<BaseField = F>,
    {
        // Prepare ciphertext
        let rng = &mut jf_utils::test_rng();
        let data: Vec<F> = (0..5 * STATE_SIZE + 1).map(|i| F::from(i as u32)).collect();
        let ctxts = KeyPair::<P>::generate(rng)
            .enc_key_ref()
            .encrypt(rng, &data);
        // Create circuit
        let mut circuit = PlonkCircuit::new_turbo_plonk();
        let ctxts_var = circuit.create_ciphertext_variable(&ctxts).unwrap();
        // Check ciphertexts
        assert_eq!(
            Point::from(ctxts.ephemeral.key.into_affine()),
            circuit.point_witness(&ctxts_var.ephemeral).unwrap()
        );
        for (ctxt, ctxt_var) in ctxts.data.iter().zip(ctxts_var.symm_ctxts) {
            assert_eq!(*ctxt, circuit.witness(ctxt_var).unwrap());
        }
        // The circuit is always satisfied.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
    }
}
