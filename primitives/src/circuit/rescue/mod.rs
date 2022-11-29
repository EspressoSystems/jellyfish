// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Rescue hash related gates and gadgets. Including both native and non-native
//! fields.

#![allow(missing_docs)]

mod native;
mod non_native;

use ark_std::vec::Vec;
use jf_relation::errors::CircuitError;
pub use native::RescueStateVar;
pub use non_native::{RescueNonNativeGadget, RescueNonNativeStateVar};

use crate::rescue::{RescueMatrix, RescueVector, PRP};

pub trait RescueStateVarGen<T, F> {
    type Native;
    type NonNative;
    type Var;
}

/// Trait for rescue circuit over native field.
pub trait RescueGadget<R, T, F>
where
    R: RescueStateVarGen<T, F>,
{
    /// Given an input state st_0 and an output state st_1, ensure that st_1 =
    /// rescue_permutation(st_0)  where rescue_permutation is the instance
    /// of the Rescue permutation defined by its respective constants
    /// * `input_var` - variables corresponding to the input state
    /// * `returns` - variables corresponding to the output state
    fn rescue_permutation(&mut self, input_var: R) -> Result<R, CircuitError>;

    /// Rescue based Pseudo Random Permutation (PRP)
    /// * `key_var` - rescue state variable corresponding to the cipher key
    /// * `input_var` - rescue state variable corresponding to the plaintext
    /// * `returns` - state variable corresponding to the cipher text
    fn prp(&mut self, key_var: &R, input_var: &R) -> Result<R, CircuitError>;

    /// Sponge-based hashes from Rescue permutations
    /// * `data_vars` - sponge input variables, `data_vars.len()` should be a
    ///   positive integer that is a multiple of the sponge rate (i.e. 3)
    /// * `num_output` - number of output variables
    /// * `returns` - a vector of variables that refers to the sponge hash
    ///   output
    fn rescue_sponge_no_padding(
        &mut self,
        data_vars: &[R::Var],
        num_output: usize,
    ) -> Result<Vec<R::Var>, CircuitError>;

    /// Sponge-based hashes from Rescue permutations
    /// * `data_vars` - sponge input variables,
    /// * `num_output` - number of output variables
    /// * `returns` - a vector of variables that refers to the sponge hash
    ///   output
    fn rescue_sponge_with_padding(
        &mut self,
        data_vars: &[R::Var],
        num_output: usize,
    ) -> Result<Vec<R::Var>, CircuitError>;

    /// Full-State-Keyed-Sponge with a single output
    /// * `key` - key variable
    /// * `input` - input variables,
    /// * `returns` a variable that refers to the output
    fn rescue_full_state_keyed_sponge_no_padding(
        &mut self,
        key: R::Var,
        data_vars: &[R::Var],
    ) -> Result<R::Var, CircuitError>;

    /// Return the round keys variables for the Rescue block cipher
    /// * `mds_states` - Rescue MDS matrix
    /// * `key_var` - state variable representing the cipher key
    /// * `returns` - state variables corresponding to the scheduled keys
    fn key_schedule(
        &mut self,
        mds_states: &RescueMatrix<R::Native>,
        key_var: &R,
        prp_instance: &PRP<R::Native>,
    ) -> Result<Vec<R>, CircuitError>;

    /// Create a variable representing a rescue state
    /// * `state` - Rescue state
    /// * `returns` - state variables corresponding to the state
    fn create_rescue_state_variable(
        &mut self,
        state: &RescueVector<R::Native>,
    ) -> Result<R, CircuitError>;

    /// Return the variable corresponding to the output of the of the Rescue
    /// PRP where the rounds keys have already been computed "dynamically"
    /// * `input_var` - variable corresponding to the plain text
    /// * `mds_states` - Rescue MDS matrix
    /// * `key_vars` - variables corresponding to the scheduled keys
    /// * `returns` -
    fn prp_with_round_keys(
        &mut self,
        input_var: &R,
        mds: &RescueMatrix<R::Native>,
        keys_vars: &[R],
    ) -> Result<R, CircuitError>;
}
