// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Interfaces for Plonk-based constraint systems
use crate::errors::{CircuitError::LookupUnsupported, PlonkError};
use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_std::vec::Vec;

pub mod basic;
pub mod customized;
pub mod gates;

pub use basic::PlonkCircuit;

/// An index to one of the witness values.
pub type Variable = usize;
/// An index to a witness value of boolean type.
#[derive(Debug, Clone, Copy)]
pub struct BoolVar(usize);

impl From<BoolVar> for Variable {
    fn from(bv: BoolVar) -> Self {
        bv.0
    }
}

impl BoolVar {
    /// Create a `BoolVar` without any check. Be careful!
    /// This is an internal API, shouldn't be used unless you know what you are
    /// doing. Normally you should only construct `BoolVar` through
    /// `Circuit::create_bool_variable()`.
    pub(crate) fn new_unchecked(inner: usize) -> Self {
        Self(inner)
    }
}

/// An index to a gate in circuit.
pub type GateId = usize;
/// An index to the type of gate wires.
/// There are 4 different types of input gate wires (with indices 0..3),
/// 1 type of output gate wires (with index 4), and 1 type of lookup gate wires
/// (with index 5).
pub type WireId = usize;

/// An interface for Plonk constraint systems.
pub trait Circuit<F: Field> {
    /// The number of constraints.
    fn num_gates(&self) -> usize;

    /// The number of variables.
    fn num_vars(&self) -> usize;

    /// The number of public input variables.
    fn num_inputs(&self) -> usize;

    /// The number of wire types of the circuit.
    /// E.g., UltraPlonk has 4 different types of input wires, 1 type of output
    /// wires, and 1 type of lookup wires.
    fn num_wire_types(&self) -> usize;

    /// The list of public input values.
    fn public_input(&self) -> Result<Vec<F>, PlonkError>;

    /// Check circuit satisfiability against a public input.
    fn check_circuit_satisfiability(&self, pub_input: &[F]) -> Result<(), PlonkError>;

    /// Add a constant variable to the circuit; return the index of the
    /// variable.
    fn create_constant_variable(&mut self, val: F) -> Result<Variable, PlonkError>;

    /// Add a variable to the circuit; return the index of the variable.
    fn create_variable(&mut self, val: F) -> Result<Variable, PlonkError>;

    /// Add a bool variable to the circuit; return the index of the variable.
    fn create_bool_variable(&mut self, val: bool) -> Result<BoolVar, PlonkError> {
        let val_scalar = if val { F::one() } else { F::zero() };
        let var = self.create_variable(val_scalar)?;
        self.bool_gate(var)?;
        Ok(BoolVar(var))
    }

    /// Add a public input variable; return the index of the variable.
    fn create_public_variable(&mut self, val: F) -> Result<Variable, PlonkError>;

    /// Set a variable to a public variable
    fn set_variable_public(&mut self, var: Variable) -> Result<(), PlonkError>;

    /// Return a default variable with value zero.
    fn zero(&self) -> Variable;

    /// Return a default variable with value one.
    fn one(&self) -> Variable;

    /// Return a default variable with value `false` (namely zero).
    fn false_var(&self) -> BoolVar {
        BoolVar::new_unchecked(self.zero())
    }

    /// Return a default variable with value `true` (namely one).
    fn true_var(&self) -> BoolVar {
        BoolVar::new_unchecked(self.one())
    }

    /// Return the witness value of variable `idx`.
    /// Return error if the input variable is invalid.
    fn witness(&self, idx: Variable) -> Result<F, PlonkError>;

    /// Common gates that should be implemented in any constraint systems.
    ///
    /// Constrain a variable to a constant.
    /// Return error if `var` is an invalid variable.
    fn constant_gate(&mut self, var: Variable, constant: F) -> Result<(), PlonkError>;

    /// Constrain variable `c` to the addition of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn add_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError>;

    /// Obtain a variable representing an addition.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn add(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError>;

    /// Constrain variable `c` to the subtraction of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn sub_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError>;

    /// Obtain a variable representing a subtraction.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn sub(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError>;

    /// Constrain variable `c` to the multiplication of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn mul_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), PlonkError>;

    /// Obtain a variable representing a multiplication.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn mul(&mut self, a: Variable, b: Variable) -> Result<Variable, PlonkError>;

    /// Constrain a variable to a bool.
    /// Return error if the input is invalid.
    fn bool_gate(&mut self, a: Variable) -> Result<(), PlonkError>;

    /// Constrain two variables to have the same value.
    /// Return error if the input variables are invalid.
    fn equal_gate(&mut self, a: Variable, b: Variable) -> Result<(), PlonkError>;

    /// Pad the circuit with n dummy gates
    fn pad_gate(&mut self, n: usize);

    /// Plookup-related methods.
    /// Return true if the circuit support lookup gates.
    fn support_lookup(&self) -> bool;
}

// The sorted concatenation of the lookup table and the witness values to be
// checked in lookup gates. It also includes 2 polynomials that interpolate the
// sorted vector.
pub(crate) type SortedLookupVecAndPolys<F> = (Vec<F>, DensePolynomial<F>, DensePolynomial<F>);

/// An interface that transforms Plonk circuits to polynomial used by
/// Plonk-based SNARKs.
pub trait Arithmetization<F: FftField>: Circuit<F> {
    /// The required SRS size for the circuit.
    fn srs_size(&self) -> Result<usize, PlonkError>;

    /// Get the size of the evaluation domain for arithmetization (after circuit
    /// has been finalized).
    fn eval_domain_size(&self) -> Result<usize, PlonkError>;

    /// Compute and return selector polynomials.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_selector_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, PlonkError>;

    /// Compute and return extended permutation polynomials.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_extended_permutation_polynomials(
        &self,
    ) -> Result<Vec<DensePolynomial<F>>, PlonkError>;

    /// Compute and return the product polynomial for permutation arguments.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_prod_permutation_polynomial(
        &self,
        beta: &F,
        gamma: &F,
    ) -> Result<DensePolynomial<F>, PlonkError>;

    /// Compute and return the list of wiring witness polynomials.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_wire_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, PlonkError>;

    /// Compute and return the public input polynomial.
    /// Return an error if the circuit has not been finalized yet.
    /// The IO gates of the circuit are guaranteed to be in the front.
    fn compute_pub_input_polynomial(&self) -> Result<DensePolynomial<F>, PlonkError>;

    /// Plookup-related methods
    /// Return default errors if the constraint system does not support lookup
    /// gates.
    ///
    /// Compute and return the polynomial that interpolates the range table
    /// elements. Return an error if the circuit does not support lookup or
    /// has not been finalized yet.
    fn compute_range_table_polynomial(&self) -> Result<DensePolynomial<F>, PlonkError> {
        Err(LookupUnsupported.into())
    }

    /// Compute and return the polynomial that interpolates the key table
    /// elements. Return an error if the circuit does not support lookup or
    /// has not been finalized yet.
    fn compute_key_table_polynomial(&self) -> Result<DensePolynomial<F>, PlonkError> {
        Err(LookupUnsupported.into())
    }

    /// Compute and return the polynomial that interpolates the table domain
    /// sepration ids. Return an error if the circuit does not support
    /// lookup or has not been finalized.
    fn compute_table_dom_sep_polynomial(&self) -> Result<DensePolynomial<F>, PlonkError> {
        Err(LookupUnsupported.into())
    }

    /// Compute and return the polynomial that interpolates the lookup domain
    /// sepration selectors for the lookup gates. Return an error if the
    /// circuit does not support lookup or has not been finalized.
    fn compute_q_dom_sep_polynomial(&self) -> Result<DensePolynomial<F>, PlonkError> {
        Err(LookupUnsupported.into())
    }

    /// Compute and return the combined lookup table vector given random
    /// challenge `tau`.
    fn compute_merged_lookup_table(&self, _tau: F) -> Result<Vec<F>, PlonkError> {
        Err(LookupUnsupported.into())
    }

    /// Compute the sorted concatenation of the (merged) lookup table and the
    /// witness values to be checked in lookup gates. Return the sorted
    /// vector and 2 polynomials that interpolate the vector. Return an
    /// error if the circuit does not support lookup or has not been
    /// finalized yet.
    fn compute_lookup_sorted_vec_polynomials(
        &self,
        _tau: F,
        _lookup_table: &[F],
    ) -> Result<SortedLookupVecAndPolys<F>, PlonkError> {
        Err(LookupUnsupported.into())
    }

    /// Compute and return the product polynomial for Plookup arguments.
    /// `beta` and `gamma` are random challenges, `sorted_vec` is the sorted
    /// concatenation of the lookup table and the lookup witnesses.
    /// Return an error if the circuit does not support lookup or
    /// has not been finalized yet.
    fn compute_lookup_prod_polynomial(
        &self,
        _tau: &F,
        _beta: &F,
        _gamma: &F,
        _lookup_table: &[F],
        _sorted_vec: &[F],
    ) -> Result<DensePolynomial<F>, PlonkError> {
        Err(LookupUnsupported.into())
    }
}
