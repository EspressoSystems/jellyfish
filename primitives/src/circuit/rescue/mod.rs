// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Rescue hash related gates and gadgets. Including both native and non-native
//! fields.

mod native;
mod non_native;

use ark_ff::PrimeField;
use ark_std::vec::Vec;
use jf_relation::{errors::CircuitError, Circuit};
pub use native::{RescueNativeGadget, RescueStateVar};
pub use non_native::{RescueNonNativeGadget, RescueNonNativeStateVar};

use crate::rescue::{RescueMatrix, RescueVector, PRP};

/// Variable to represent the state of the sponge.
pub trait SpongeStateVar<T, F> {
    /// The native field.
    type Native;
    /// Non-native field.
    type NonNative;
    /// How variable is represented in this Rescue(NonNative)StateVar.
    type Var;
}

/// Trait for rescue circuit over native field.
pub trait RescueGadget<R, T, F>
where
    R: SpongeStateVar<T, F>,
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

    /// Similar to [`Self::rescue_full_state_keyed_sponge_no_padding`] except
    /// `data_var` are padded with "zero_var"
    fn rescue_full_state_keyed_sponge_with_zero_padding(
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

pub(crate) trait PermutationGadget<R, T, F>: Circuit<F>
where
    R: SpongeStateVar<T, F>,
    F: PrimeField,
{
    fn check_var_bound_rescue_state(&self, rescue_state: &R) -> Result<(), CircuitError>;

    fn add_constant_state(
        &mut self,
        input_var: &R,
        constant: &RescueVector<R::Native>,
    ) -> Result<R, CircuitError>;

    fn add_state(&mut self, left_state_var: &R, right_state_var: &R) -> Result<R, CircuitError>;

    /// Given a state st_0=(x_1,...,x_w) and st_1=(y_1,...,y_w),
    /// add the constraints that ensure we have y_i=x_i ^{1/5} for i in
    /// [1,...,w]
    /// * `input_var` - rescue state variables st_0
    /// * `returns` - rescue state variables st_1
    fn pow_alpha_inv_state(&mut self, input_var: &R) -> Result<R, CircuitError>;

    /// Given an input state st_0 and an output state st_1, ensure that st_1 = M
    /// st_0 + C where M is a Rescue matrix and c is a constant vector
    /// * `input_var` - variables corresponding to the input state
    /// * `matrix` - matrix M in the description above
    /// * `constant` - constant c in the description above
    /// * `returns` - variables corresponding to the output state
    fn affine_transform(
        &mut self,
        input_var: &R,
        matrix: &RescueMatrix<R::Native>,
        constant: &RescueVector<R::Native>,
    ) -> Result<R, CircuitError>;

    /// Given an input state st_0=(x_1,...,x_w) and an output state
    /// st_1=(y_1,...,y_m) y_i = \sum_{j=1}^w M_{i,j}x_j^alpha+c_i for all i in
    /// [1,..,w] where M is a Rescue matrix and c=(c_1,...,c_w) is a
    /// constant vector
    /// * `input_var` - variables corresponding to the input state
    /// * `matrix` - matrix M in the description above
    /// * `constant` - constant c in the description above
    /// * `returns` - variables corresponding to the output state
    fn non_linear_transform(
        &mut self,
        input_var: &R,
        matrix: &RescueMatrix<R::Native>,
        constant: &RescueVector<R::Native>,
    ) -> Result<R, CircuitError>;

    /// Define a constraint such that y = x^(1/alpha).
    /// It is implemented by setting q_{H1} y^alpha = q_O x
    /// * `input_var`  - variable id corresponding to x in the equation above
    /// * `returns` - the variable id corresponding to y
    fn pow_alpha_inv(&mut self, input_var: R::Var) -> Result<R::Var, CircuitError>;

    /// Given an input state st_0 and an output state st_1, ensure that st_1 is
    /// obtained by applying the rescue permutation with a specific  list of
    /// round keys (i.e. the keys are constants) and a matrix
    /// * `input_var` - variables corresponding to the input state
    /// * `mds` - Rescue matrix
    /// * `round_keys` - list of round keys
    /// * `returns` - variables corresponding to the output state
    fn permutation_with_const_round_keys(
        &mut self,
        input_var: R,
        mds: &RescueMatrix<R::Native>,
        round_keys: &[RescueVector<R::Native>],
    ) -> Result<R, CircuitError>;
}
