// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Definitions and constructions of plonk constraint system
use crate::{
    constants::{compute_coset_representatives, GATE_WIDTH, N_MUL_SELECTORS},
    errors::{CircuitError, CircuitError::*},
    gates::*,
};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{
    domain::Radix2EvaluationDomain, univariate::DensePolynomial, EvaluationDomain, DenseUVPolynomial,
};
use ark_std::{boxed::Box, cmp::max, format, string::ToString, vec, vec::Vec};
use hashbrown::{HashMap, HashSet};
use jf_utils::par_utils::parallelizable_slice_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// An index to a gate in circuit.
pub type GateId = usize;
/// An index to the type of gate wires.
/// There are 4 different types of input gate wires (with indices 0..3),
/// 1 type of output gate wires (with index 4), and 1 type of lookup gate wires
/// (with index 5).
pub type WireId = usize;
/// An index to one of the witness values.
pub type Variable = usize;
/// An index to a witness value of boolean type.
#[derive(Debug, Clone, Copy)]
pub struct BoolVar(pub usize);

impl From<BoolVar> for Variable {
    fn from(bv: BoolVar) -> Self {
        bv.0
    }
}

impl BoolVar {
    /// Create a `BoolVar` without any check. Be careful!
    /// This is an internal API, shouldn't be used unless you know what you are
    /// doing. Normally you should only construct `BoolVar` through
    /// `Circuit::create_boolean_variable()`.
    pub(crate) fn new_unchecked(inner: usize) -> Self {
        Self(inner)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Enum for each type of Plonk scheme.
pub enum PlonkType {
    /// TurboPlonk
    TurboPlonk,
    /// TurboPlonk that supports Plookup
    UltraPlonk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Enum for each type of mergeable circuit. We can only merge circuits from
/// different types.
pub enum MergeableCircuitType {
    /// First type
    TypeA,
    /// Second type
    TypeB,
}

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
    fn public_input(&self) -> Result<Vec<F>, CircuitError>;

    /// Check circuit satisfiability against a public input.
    fn check_circuit_satisfiability(&self, pub_input: &[F]) -> Result<(), CircuitError>;

    /// Add a constant variable to the circuit; return the index of the
    /// variable.
    fn create_constant_variable(&mut self, val: F) -> Result<Variable, CircuitError>;

    /// Add a variable to the circuit; return the index of the variable.
    fn create_variable(&mut self, val: F) -> Result<Variable, CircuitError>;

    /// Add a bool variable to the circuit; return the index of the variable.
    fn create_boolean_variable(&mut self, val: bool) -> Result<BoolVar, CircuitError> {
        let val_scalar = if val { F::one() } else { F::zero() };
        let var = self.create_variable(val_scalar)?;
        self.enforce_bool(var)?;
        Ok(BoolVar(var))
    }

    /// Add a public input variable; return the index of the variable.
    fn create_public_variable(&mut self, val: F) -> Result<Variable, CircuitError>;

    /// Set a variable to a public variable
    fn set_variable_public(&mut self, var: Variable) -> Result<(), CircuitError>;

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
    fn witness(&self, idx: Variable) -> Result<F, CircuitError>;

    /// Common gates that should be implemented in any constraint systems.
    ///
    /// Constrain a variable to a constant.
    /// Return error if `var` is an invalid variable.
    fn enforce_constant(&mut self, var: Variable, constant: F) -> Result<(), CircuitError>;

    /// Constrain variable `c` to the addition of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn add_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError>;

    /// Obtain a variable representing an addition.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn add(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError>;

    /// Constrain variable `c` to the subtraction of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn sub_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError>;

    /// Obtain a variable representing a subtraction.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn sub(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError>;

    /// Constrain variable `c` to the multiplication of `a` and `b`.
    /// Return error if the input variables are invalid.
    fn mul_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError>;

    /// Obtain a variable representing a multiplication.
    /// Return the index of the variable.
    /// Return error if the input variables are invalid.
    fn mul(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError>;

    /// Constrain a variable to a bool.
    /// Return error if the input is invalid.
    fn enforce_bool(&mut self, a: Variable) -> Result<(), CircuitError>;

    /// Constrain two variables to have the same value.
    /// Return error if the input variables are invalid.
    fn enforce_equal(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError>;

    /// Pad the circuit with n dummy gates
    fn pad_gates(&mut self, n: usize);

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
    fn srs_size(&self) -> Result<usize, CircuitError>;

    /// Get the size of the evaluation domain for arithmetization (after circuit
    /// has been finalized).
    fn eval_domain_size(&self) -> Result<usize, CircuitError>;

    /// Compute and return selector polynomials.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_selector_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, CircuitError>;

    /// Compute and return extended permutation polynomials.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_extended_permutation_polynomials(
        &self,
    ) -> Result<Vec<DensePolynomial<F>>, CircuitError>;

    /// Compute and return the product polynomial for permutation arguments.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_prod_permutation_polynomial(
        &self,
        beta: &F,
        gamma: &F,
    ) -> Result<DensePolynomial<F>, CircuitError>;

    /// Compute and return the list of wiring witness polynomials.
    /// Return an error if the circuit has not been finalized yet.
    fn compute_wire_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, CircuitError>;

    /// Compute and return the public input polynomial.
    /// Return an error if the circuit has not been finalized yet.
    /// The IO gates of the circuit are guaranteed to be in the front.
    fn compute_pub_input_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError>;

    /// Plookup-related methods
    /// Return default errors if the constraint system does not support lookup
    /// gates.
    ///
    /// Compute and return the polynomial that interpolates the range table
    /// elements. Return an error if the circuit does not support lookup or
    /// has not been finalized yet.
    fn compute_range_table_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        Err(CircuitError::LookupUnsupported)
    }

    /// Compute and return the polynomial that interpolates the key table
    /// elements. Return an error if the circuit does not support lookup or
    /// has not been finalized yet.
    fn compute_key_table_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        Err(CircuitError::LookupUnsupported)
    }

    /// Compute and return the polynomial that interpolates the table domain
    /// sepration ids. Return an error if the circuit does not support
    /// lookup or has not been finalized.
    fn compute_table_dom_sep_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        Err(CircuitError::LookupUnsupported)
    }

    /// Compute and return the polynomial that interpolates the lookup domain
    /// sepration selectors for the lookup gates. Return an error if the
    /// circuit does not support lookup or has not been finalized.
    fn compute_q_dom_sep_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        Err(CircuitError::LookupUnsupported)
    }

    /// Compute and return the combined lookup table vector given random
    /// challenge `tau`.
    fn compute_merged_lookup_table(&self, _tau: F) -> Result<Vec<F>, CircuitError> {
        Err(CircuitError::LookupUnsupported)
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
    ) -> Result<SortedLookupVecAndPolys<F>, CircuitError> {
        Err(CircuitError::LookupUnsupported)
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
    ) -> Result<DensePolynomial<F>, CircuitError> {
        Err(CircuitError::LookupUnsupported)
    }
}

/// The wire type identifier for range gates.
const RANGE_WIRE_ID: usize = 5;
/// The wire type identifier for the key index in a lookup gate
const LOOKUP_KEY_WIRE_ID: usize = 0;
/// The wire type identifiers for the searched pair values in a lookup gate
const LOOKUP_VAL_1_WIRE_ID: usize = 1;
const LOOKUP_VAL_2_WIRE_ID: usize = 2;
/// The wire type identifiers for the pair values in the lookup table
const TABLE_VAL_1_WIRE_ID: usize = 3;
const TABLE_VAL_2_WIRE_ID: usize = 4;

/// Hardcoded parameters for Plonk systems.
#[derive(Debug, Clone, Copy)]
struct PlonkParams {
    /// The Plonk type of the circuit.
    plonk_type: PlonkType,

    /// The bit length of a range-check. None for TurboPlonk.
    range_bit_len: Option<usize>,
}

impl PlonkParams {
    fn init(plonk_type: PlonkType, range_bit_len: Option<usize>) -> Result<Self, CircuitError> {
        if plonk_type == PlonkType::TurboPlonk {
            return Ok(Self {
                plonk_type,
                range_bit_len: None,
            });
        }
        if range_bit_len.is_none() {
            return Err(ParameterError(
                "range bit len cannot be none for UltraPlonk".to_string(),
            ));
        }

        Ok(Self {
            plonk_type,
            range_bit_len,
        })
    }
}

/// A specific Plonk circuit instantiation.
#[derive(Debug, Clone)]
pub struct PlonkCircuit<F>
where
    F: FftField,
{
    /// The number of variables.
    num_vars: usize,

    /// The gate of each (algebraic) constraint
    gates: Vec<Box<dyn Gate<F>>>,
    /// The map from arithmetic/lookup gate wires to variables.
    wire_variables: [Vec<Variable>; GATE_WIDTH + 2],
    /// The IO gates for the list of public input variables.
    pub_input_gate_ids: Vec<GateId>,
    /// The actual values of variables.
    witness: Vec<F>,

    /// The permutation over wires.
    /// Each algebraic gate has 5 wires, i.e., 4 input wires and an output
    /// wire; each lookup gate has a single wire that maps to a witness to
    /// be checked over the lookup table. In total there are 6 * n wires
    /// where n is the (padded) number of arithmetic/lookup gates.  
    /// We build a permutation over the set of wires so that each set of wires
    /// that map to the same witness forms a cycle.
    ///
    /// Each wire is represented by a pair (`WireId, GateId`) so that the wire
    /// is in the `GateId`-th arithmetic/lookup gate and `WireId` represents
    /// the wire type (e.g., 0 represents 1st input wires, 4 represents
    /// output wires, and 5 represents lookup wires).
    wire_permutation: Vec<(WireId, GateId)>,
    /// The extended identity permutation.
    extended_id_permutation: Vec<F>,
    /// The number of wire types. 5 for TurboPlonk and 6 for UltraPlonk.
    num_wire_types: usize,

    /// The evaluation domain for arithmetization of the circuit into various
    /// polynomials. This is only relevant after the circuit is finalized for
    /// arithmetization, by default it is a domain with size 1 (only with
    /// element 0).
    eval_domain: Radix2EvaluationDomain<F>,

    /// The Plonk parameters.
    plonk_params: PlonkParams,

    /// The number of key-value table elements being inserted.
    num_table_elems: usize,

    /// The lookup gates indices for the inserted tables.
    /// For each inserted table, the 1st value is the start id of the table,
    /// the 2nd values is the length of the table.
    table_gate_ids: Vec<(GateId, usize)>,
}

impl<F: FftField> Default for PlonkCircuit<F> {
    fn default() -> Self {
        let params = PlonkParams::init(PlonkType::TurboPlonk, None).unwrap();
        Self::new(params)
    }
}

impl<F: FftField> PlonkCircuit<F> {
    /// Construct a new circuit with type `plonk_type`.
    fn new(plonk_params: PlonkParams) -> Self {
        let zero = F::zero();
        let one = F::one();
        let mut circuit = Self {
            num_vars: 2,
            witness: vec![zero, one],
            gates: vec![],
            // size is `num_wire_types`
            wire_variables: [vec![], vec![], vec![], vec![], vec![], vec![]],
            pub_input_gate_ids: vec![],

            wire_permutation: vec![],
            extended_id_permutation: vec![],
            num_wire_types: GATE_WIDTH
                + 1
                + match plonk_params.plonk_type {
                    PlonkType::TurboPlonk => 0,
                    PlonkType::UltraPlonk => 1,
                },
            eval_domain: Radix2EvaluationDomain::new(1).unwrap(),
            plonk_params,
            num_table_elems: 0,
            table_gate_ids: vec![],
        };
        // Constrain variables `0`/`1` to have value 0/1.
        circuit.enforce_constant(0, zero).unwrap(); // safe unwrap
        circuit.enforce_constant(1, one).unwrap(); // safe unwrap
        circuit
    }

    /// Construct a new TurboPlonk circuit.
    pub fn new_turbo_plonk() -> Self {
        let plonk_params = PlonkParams::init(PlonkType::TurboPlonk, None).unwrap(); // safe unwrap
        Self::new(plonk_params)
    }

    /// Construct a new UltraPlonk circuit.
    pub fn new_ultra_plonk(range_bit_len: usize) -> Self {
        let plonk_params = PlonkParams::init(PlonkType::UltraPlonk, Some(range_bit_len)).unwrap(); // safe unwrap
        Self::new(plonk_params)
    }

    /// Insert a general (algebraic) gate
    /// * `wire_vars` - wire variables. Each of these variables must be in range
    /// * `gate` - specific gate to be inserted
    /// * `returns` - an error if some verification fails
    pub fn insert_gate(
        &mut self,
        wire_vars: &[Variable; GATE_WIDTH + 1],
        gate: Box<dyn Gate<F>>,
    ) -> Result<(), CircuitError> {
        self.check_finalize_flag(false)?;

        for (wire_var, wire_variable) in wire_vars
            .iter()
            .zip(self.wire_variables.iter_mut().take(GATE_WIDTH + 1))
        {
            wire_variable.push(*wire_var)
        }

        self.gates.push(gate);
        Ok(())
    }

    /// Add a range_check gate that checks whether a variable is in the range
    /// [0, range_size). Return an error if the circuit does not support
    /// lookup.
    pub fn add_range_check_variable(&mut self, var: Variable) -> Result<(), CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        self.check_finalize_flag(false)?;
        self.check_var_bound(var)?;
        self.wire_variables[RANGE_WIRE_ID].push(var);
        Ok(())
    }

    #[inline]
    /// Checks if a variable is strictly less than the number of variables.
    /// This function must be invoked for each gate as this check is not applied
    /// in the function `insert_gate`
    /// * `var` - variable to check
    /// * `returns` - Error if the variable is out of bound (i.e. >= number of
    ///   variables)
    pub fn check_var_bound(&self, var: Variable) -> Result<(), CircuitError> {
        if var >= self.num_vars {
            return Err(VarIndexOutOfBound(var, self.num_vars));
        }
        Ok(())
    }

    /// Check if a list of variables are strictly less than the number of
    /// variables.
    /// * `vars` - variables to check
    /// * `returns` - Error if the variable is out of bound (i.e. >= number of
    ///   variables)
    pub fn check_vars_bound(&self, vars: &[Variable]) -> Result<(), CircuitError> {
        for &var in vars {
            self.check_var_bound(var)?
        }
        Ok(())
    }

    /// Change the value of a variable. Only used for testing.
    // TODO: make this function test only.
    pub fn witness_mut(&mut self, idx: Variable) -> &mut F {
        &mut self.witness[idx]
    }

    /// Get the mutable reference of the inserted table ids.
    pub(crate) fn table_gate_ids_mut(&mut self) -> &mut Vec<(GateId, usize)> {
        &mut self.table_gate_ids
    }

    /// Get the mutable reference of the number of inserted table elements.
    pub(crate) fn num_table_elems_mut(&mut self) -> &mut usize {
        &mut self.num_table_elems
    }

    /// Get the number of inserted table elements.
    pub(crate) fn num_table_elems(&self) -> usize {
        self.num_table_elems
    }

    /// The bit length of UltraPlonk range gates.
    pub fn range_bit_len(&self) -> Result<usize, CircuitError> {
        if self.plonk_params.plonk_type != PlonkType::UltraPlonk {
            return Err(ParameterError(
                "call range_bit_len() with non-ultraplonk circuit".to_string(),
            ));
        }
        Ok(self.plonk_params.range_bit_len.unwrap()) // safe unwrap
    }

    /// The range size of UltraPlonk range gates.
    pub fn range_size(&self) -> Result<usize, CircuitError> {
        Ok(1 << self.range_bit_len()?)
    }

    /// creating a `BoolVar` without checking if `v` is a boolean value!
    /// You should absolutely sure about what you are doing.
    /// You should normally only use this API if you already enforce `v` to be a
    /// boolean value using other constraints.
    pub(crate) fn create_boolean_variable_unchecked(
        &mut self,
        a: F,
    ) -> Result<BoolVar, CircuitError> {
        let var = self.create_variable(a)?;
        Ok(BoolVar::new_unchecked(var))
    }
}

impl<F: FftField> Circuit<F> for PlonkCircuit<F> {
    fn num_gates(&self) -> usize {
        self.gates.len()
    }

    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn num_inputs(&self) -> usize {
        self.pub_input_gate_ids.len()
    }

    fn num_wire_types(&self) -> usize {
        self.num_wire_types
    }

    fn public_input(&self) -> Result<Vec<F>, CircuitError> {
        self.pub_input_gate_ids
            .iter()
            .map(|&gate_id| -> Result<F, CircuitError> {
                let var = self.wire_variables[GATE_WIDTH][gate_id];
                self.witness(var)
            })
            .collect::<Result<Vec<F>, CircuitError>>()
    }

    fn check_circuit_satisfiability(&self, pub_input: &[F]) -> Result<(), CircuitError> {
        if pub_input.len() != self.num_inputs() {
            return Err(PubInputLenMismatch(
                pub_input.len(),
                self.pub_input_gate_ids.len(),
            ));
        }
        // Check public I/O gates
        for (i, gate_id) in self.pub_input_gate_ids.iter().enumerate() {
            let pi = pub_input[i];
            self.check_gate(*gate_id, &pi)?;
        }
        // Check rest of the gates
        for gate_id in 0..self.num_gates() {
            if !self.is_io_gate(gate_id) {
                let pi = F::zero();
                self.check_gate(gate_id, &pi)?;
            }
        }
        // Check range/lookup gates if the circuit supports lookup
        if self.plonk_params.plonk_type == PlonkType::UltraPlonk {
            // range gates
            for idx in 0..self.wire_variables[RANGE_WIRE_ID].len() {
                self.check_range_gate(idx)?
            }
            // key-value map lookup gates
            let mut key_val_table = HashSet::new();
            key_val_table.insert((F::zero(), F::zero(), F::zero(), F::zero()));
            let q_lookup_vec = self.q_lookup();
            let q_dom_sep_vec = self.q_dom_sep();
            let table_key_vec = self.table_key_vec();
            let table_dom_sep_vec = self.table_dom_sep_vec();
            // insert table elements
            for (gate_id, ((&q_lookup, &table_dom_sep), &table_key)) in q_lookup_vec
                .iter()
                .zip(table_dom_sep_vec.iter())
                .zip(table_key_vec.iter())
                .enumerate()
            {
                if q_lookup != F::zero() {
                    let val0 = self.witness(self.wire_variable(TABLE_VAL_1_WIRE_ID, gate_id))?;
                    let val1 = self.witness(self.wire_variable(TABLE_VAL_2_WIRE_ID, gate_id))?;
                    key_val_table.insert((table_dom_sep, table_key, val0, val1));
                }
            }
            // check lookups
            for (gate_id, (&q_lookup, &q_dom_sep)) in
                q_lookup_vec.iter().zip(q_dom_sep_vec.iter()).enumerate()
            {
                if q_lookup != F::zero() {
                    let key = self.witness(self.wire_variable(LOOKUP_KEY_WIRE_ID, gate_id))?;
                    let val0 = self.witness(self.wire_variable(LOOKUP_VAL_1_WIRE_ID, gate_id))?;
                    let val1 = self.witness(self.wire_variable(LOOKUP_VAL_2_WIRE_ID, gate_id))?;
                    if !key_val_table.contains(&(q_dom_sep, key, val0, val1)) {
                        return Err(GateCheckFailure(
                            gate_id,
                            format!(
                                "Lookup gate failed: ({q_dom_sep}, {key}, {val0}, {val1}) not in the table",
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn create_constant_variable(&mut self, val: F) -> Result<Variable, CircuitError> {
        let var = self.create_variable(val)?;
        self.enforce_constant(var, val)?;
        Ok(var)
    }

    fn create_variable(&mut self, val: F) -> Result<Variable, CircuitError> {
        self.check_finalize_flag(false)?;
        self.witness.push(val);
        self.num_vars += 1;
        // the index is from `0` to `num_vars - 1`
        Ok(self.num_vars - 1)
    }

    fn create_public_variable(&mut self, val: F) -> Result<Variable, CircuitError> {
        let var = self.create_variable(val)?;
        self.set_variable_public(var)?;
        Ok(var)
    }

    fn set_variable_public(&mut self, var: Variable) -> Result<(), CircuitError> {
        self.check_finalize_flag(false)?;
        self.pub_input_gate_ids.push(self.num_gates());

        // Create an io gate that forces `witness[var] = public_input`.
        let wire_vars = &[0, 0, 0, 0, var];
        self.insert_gate(wire_vars, Box::new(IoGate))?;
        Ok(())
    }

    /// Default zero variable
    fn zero(&self) -> Variable {
        0
    }

    /// Default one variable
    fn one(&self) -> Variable {
        1
    }

    fn witness(&self, idx: Variable) -> Result<F, CircuitError> {
        self.check_var_bound(idx)?;
        Ok(self.witness[idx])
    }

    fn enforce_constant(&mut self, var: Variable, constant: F) -> Result<(), CircuitError> {
        self.check_var_bound(var)?;

        let wire_vars = &[0, 0, 0, 0, var];
        self.insert_gate(wire_vars, Box::new(ConstantGate(constant)))?;
        Ok(())
    }

    fn add_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(AdditionGate))?;
        Ok(())
    }

    fn add(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? + self.witness(b)?;
        let c = self.create_variable(val)?;
        self.add_gate(a, b, c)?;
        Ok(c)
    }

    fn sub_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(SubtractionGate))?;
        Ok(())
    }

    fn sub(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? - self.witness(b)?;
        let c = self.create_variable(val)?;
        self.sub_gate(a, b, c)?;
        Ok(c)
    }

    fn mul_gate(&mut self, a: Variable, b: Variable, c: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        self.check_var_bound(c)?;

        let wire_vars = &[a, b, 0, 0, c];
        self.insert_gate(wire_vars, Box::new(MultiplicationGate))?;
        Ok(())
    }

    fn mul(&mut self, a: Variable, b: Variable) -> Result<Variable, CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;
        let val = self.witness(a)? * self.witness(b)?;
        let c = self.create_variable(val)?;
        self.mul_gate(a, b, c)?;
        Ok(c)
    }

    fn enforce_bool(&mut self, a: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;

        let wire_vars = &[a, a, 0, 0, a];
        self.insert_gate(wire_vars, Box::new(BoolGate))?;
        Ok(())
    }

    fn enforce_equal(&mut self, a: Variable, b: Variable) -> Result<(), CircuitError> {
        self.check_var_bound(a)?;
        self.check_var_bound(b)?;

        let wire_vars = &[a, b, 0, 0, 0];
        self.insert_gate(wire_vars, Box::new(EqualityGate))?;
        Ok(())
    }

    fn pad_gates(&mut self, n: usize) {
        // TODO: FIXME
        // this is interesting...
        // if we insert a PaddingGate
        // the padded gate does not have a gate_id, and will bug
        // when we check circuit satisfiability
        // we temporarily insert equality gate to by pass the issue
        let wire_vars = &[self.zero(), self.zero(), 0, 0, 0];
        for _ in 0..n {
            self.insert_gate(wire_vars, Box::new(EqualityGate)).unwrap();
        }
    }

    // Plookup-related methods
    //
    fn support_lookup(&self) -> bool {
        self.plonk_params.plonk_type == PlonkType::UltraPlonk
    }
}

/// Private helper methods
impl<F: FftField> PlonkCircuit<F> {
    /// Check correctness of the idx-th range gate. Return an error if the
    /// circuit does not support lookup.
    fn check_range_gate(&self, idx: usize) -> Result<(), CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        if idx >= self.wire_variables[RANGE_WIRE_ID].len() {
            return Err(IndexError);
        }
        let range_size = self.range_size()?;
        if self.witness[self.wire_variables[RANGE_WIRE_ID][idx]] >= F::from(range_size as u32) {
            return Err(GateCheckFailure(
                idx,
                format!(
                    "Range gate failed: {} >= {}",
                    self.witness[self.wire_variables[RANGE_WIRE_ID][idx]], range_size
                ),
            ));
        }
        Ok(())
    }

    fn is_finalized(&self) -> bool {
        self.eval_domain.size() != 1
    }

    /// Re-arrange the order of the gates so that
    /// 1. io gates are in the front.
    /// 2. variable table lookup gate are at the rear so that they do not affect
    /// the range gates when merging the lookup tables.
    ///
    /// Remember to pad gates before calling the method.
    fn rearrange_gates(&mut self) -> Result<(), CircuitError> {
        self.check_finalize_flag(true)?;
        for (gate_id, io_gate_id) in self.pub_input_gate_ids.iter_mut().enumerate() {
            if *io_gate_id > gate_id {
                // Swap gate types
                self.gates.swap(gate_id, *io_gate_id);
                // Swap wire variables
                for i in 0..GATE_WIDTH + 1 {
                    self.wire_variables[i].swap(gate_id, *io_gate_id);
                }
                // Update io gate index
                *io_gate_id = gate_id;
            }
        }
        if self.support_lookup() {
            // move lookup gates to the rear, the relative order of the lookup gates
            // should not change
            let n = self.eval_domain.size();
            // be careful that we can't put a lookup gates at the very last slot.
            let mut cur_gate_id = n - 2;
            for &(table_gate_id, table_size) in self.table_gate_ids.iter().rev() {
                for gate_id in (table_gate_id..table_gate_id + table_size).rev() {
                    if gate_id < cur_gate_id {
                        // Swap gate types
                        self.gates.swap(gate_id, cur_gate_id);
                        // Swap wire variables
                        for j in 0..GATE_WIDTH + 1 {
                            self.wire_variables[j].swap(gate_id, cur_gate_id);
                        }
                        cur_gate_id -= 1;
                    }
                }
            }
        }
        Ok(())
    }
    // use downcast to check whether a gate is of IoGate type
    fn is_io_gate(&self, gate_id: GateId) -> bool {
        self.gates[gate_id].as_any().is::<IoGate>()
    }

    // pad a finalized circuit to match the evaluation domain, prepared for
    // arithmetization.
    fn pad(&mut self) -> Result<(), CircuitError> {
        self.check_finalize_flag(true)?;
        let n = self.eval_domain.size();
        for _ in self.num_gates()..n {
            self.gates.push(Box::new(PaddingGate));
        }
        for wire_id in 0..self.num_wire_types() {
            self.wire_variables[wire_id].resize(n, self.zero());
        }
        Ok(())
    }

    /// Check that the `gate_id`-th gate is satisfied by the circuit's witness
    /// and the public input value `pub_input`. `gate_id` is guaranteed to
    /// be in the range. The gate equation:
    /// qo * wo = pub_input + q_c +
    ///           q_mul0 * w0 * w1 + q_mul1 * w2 * w3 +
    ///           q_lc0 * w0 + q_lc1 * w1 + q_lc2 * w2 + q_lc3 * w3 +
    ///           q_hash0 * w0 + q_hash1 * w1 + q_hash2 * w2 + q_hash3 * w3 +
    ///           q_ecc * w0 * w1 * w2 * w3 * wo
    fn check_gate(&self, gate_id: Variable, pub_input: &F) -> Result<(), CircuitError> {
        // Compute wire values

        let w_vals: Vec<F> = (0..GATE_WIDTH + 1)
            .map(|i| self.witness[self.wire_variables[i][gate_id]])
            .collect();
        // Compute selector values.
        let q_lc: [F; GATE_WIDTH] = self.gates[gate_id].q_lc();
        let q_mul: [F; N_MUL_SELECTORS] = self.gates[gate_id].q_mul();
        let q_hash: [F; GATE_WIDTH] = self.gates[gate_id].q_hash();
        let q_c = self.gates[gate_id].q_c();
        let q_o = self.gates[gate_id].q_o();
        let q_ecc = self.gates[gate_id].q_ecc();

        // Compute the gate output
        let expected_gate_output = *pub_input
            + q_lc[0] * w_vals[0]
            + q_lc[1] * w_vals[1]
            + q_lc[2] * w_vals[2]
            + q_lc[3] * w_vals[3]
            + q_mul[0] * w_vals[0] * w_vals[1]
            + q_mul[1] * w_vals[2] * w_vals[3]
            + q_ecc * w_vals[0] * w_vals[1] * w_vals[2] * w_vals[3] * w_vals[4]
            + q_hash[0] * w_vals[0].pow([5])
            + q_hash[1] * w_vals[1].pow([5])
            + q_hash[2] * w_vals[2].pow([5])
            + q_hash[3] * w_vals[3].pow([5])
            + q_c;
        let gate_output = q_o * w_vals[4];
        if expected_gate_output != gate_output {
            return Err(
                GateCheckFailure(
                    gate_id,
                    format!(
                        "gate: {:?}, wire values: {:?}, pub_input: {}, expected_gate_output: {}, gate_output: {}",
                        self.gates[gate_id],
                        w_vals,
                        pub_input,
                        expected_gate_output,
                        gate_output
                    )
                ));
        }
        Ok(())
    }

    // Compute the permutation over wires.
    // The circuit is guaranteed to be padded before calling the method.
    #[inline]
    fn compute_wire_permutation(&mut self) {
        assert!(self.is_finalized());
        let n = self.eval_domain.size();
        let m = self.num_vars();

        // Compute the mapping from variables to wires.
        // NOTE: we can use a vector as a map because our variable (the intended "key"
        // value type of the Map) is sorted and match exactly as the
        // non-negative integer ranged from 0 to m. Our current implementation should be
        // slightly faster than using a `HashMap<Variable, Vec<(WireId, GateId)>>` as we
        // avoid any constant overhead from the hashmap read/write.
        let mut variable_wires_map = vec![vec![]; m];
        for (gate_wire_id, variables) in self
            .wire_variables
            .iter()
            .take(self.num_wire_types())
            .enumerate()
        {
            for (gate_id, &var) in variables.iter().enumerate() {
                variable_wires_map[var].push((gate_wire_id, gate_id));
            }
        }

        // Compute the wire permutation
        self.wire_permutation = vec![(0usize, 0usize); self.num_wire_types * n];
        for wires_vec in variable_wires_map.iter_mut() {
            // The list of wires that map to the same variable forms a cycle.
            if !wires_vec.is_empty() {
                // push the first item so that window iterator will visit the last item
                // paired with the first item, forming a cycle
                wires_vec.push(wires_vec[0]);
                for window in wires_vec.windows(2) {
                    self.wire_permutation[window[0].0 * n + window[0].1] = window[1];
                }
                // remove the extra first item pushed at the beginning of the iterator
                wires_vec.pop();
            }
        }
    }

    // Check whether the circuit is finalized. Return an error if the finalizing
    // status is different from the expected status.
    #[inline]
    fn check_finalize_flag(&self, expect_finalized: bool) -> Result<(), CircuitError> {
        if !self.is_finalized() && expect_finalized {
            return Err(UnfinalizedCircuit);
        }
        if self.is_finalized() && !expect_finalized {
            return Err(ModifyFinalizedCircuit);
        }
        Ok(())
    }

    // Check whether the Plonk type is the expected Plonk type. Return an error if
    // not.
    #[inline]
    fn check_plonk_type(&self, expect_type: PlonkType) -> Result<(), CircuitError> {
        if self.plonk_params.plonk_type != expect_type {
            return Err(WrongPlonkType);
        }
        Ok(())
    }

    // Return the variable that maps to a wire `(i, j)` where i is the wire type and
    // j is the gate index. If gate `j` is a padded dummy gate, return zero
    // variable.
    #[inline]
    fn wire_variable(&self, i: WireId, j: GateId) -> Variable {
        match j < self.wire_variables[i].len() {
            true => self.wire_variables[i][j],
            false => self.zero(),
        }
    }

    // getter for all linear combination selector
    #[inline]
    fn q_lc(&self) -> [Vec<F>; GATE_WIDTH] {
        let mut result = [vec![], vec![], vec![], vec![]];
        for gate in &self.gates {
            let q_lc_vec = gate.q_lc();
            result[0].push(q_lc_vec[0]);
            result[1].push(q_lc_vec[1]);
            result[2].push(q_lc_vec[2]);
            result[3].push(q_lc_vec[3]);
        }
        result
    }
    // getter for all multiplication selector
    #[inline]
    fn q_mul(&self) -> [Vec<F>; N_MUL_SELECTORS] {
        let mut result = [vec![], vec![]];
        for gate in &self.gates {
            let q_mul_vec = gate.q_mul();
            result[0].push(q_mul_vec[0]);
            result[1].push(q_mul_vec[1]);
        }
        result
    }
    // getter for all hash selector
    #[inline]
    fn q_hash(&self) -> [Vec<F>; GATE_WIDTH] {
        let mut result = [vec![], vec![], vec![], vec![]];
        for gate in &self.gates {
            let q_hash_vec = gate.q_hash();
            result[0].push(q_hash_vec[0]);
            result[1].push(q_hash_vec[1]);
            result[2].push(q_hash_vec[2]);
            result[3].push(q_hash_vec[3]);
        }
        result
    }
    // getter for all output selector
    #[inline]
    fn q_o(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_o()).collect()
    }
    // getter for all constant selector
    #[inline]
    fn q_c(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_c()).collect()
    }
    // getter for all ecc selector
    #[inline]
    fn q_ecc(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_ecc()).collect()
    }
    // getter for all lookup selector
    #[inline]
    fn q_lookup(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_lookup()).collect()
    }
    // getter for all lookup domain separation selector
    #[inline]
    fn q_dom_sep(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.q_dom_sep()).collect()
    }
    // getter for the vector of table keys
    #[inline]
    fn table_key_vec(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.table_key()).collect()
    }
    // getter for the vector of table domain separation ids
    #[inline]
    fn table_dom_sep_vec(&self) -> Vec<F> {
        self.gates.iter().map(|g| g.table_dom_sep()).collect()
    }
    // TODO: (alex) try return reference instead of expensive clone
    // getter for all selectors in the following order:
    // q_lc, q_mul, q_hash, q_o, q_c, q_ecc, [q_lookup (if support lookup)]
    #[inline]
    fn all_selectors(&self) -> Vec<Vec<F>> {
        let mut selectors = vec![];
        self.q_lc()
            .as_ref()
            .iter()
            .chain(self.q_mul().as_ref().iter())
            .chain(self.q_hash().as_ref().iter())
            .for_each(|s| selectors.push(s.clone()));
        selectors.push(self.q_o());
        selectors.push(self.q_c());
        selectors.push(self.q_ecc());
        if self.support_lookup() {
            selectors.push(self.q_lookup());
        }
        selectors
    }
}

/// Private permutation related methods
impl<F: PrimeField> PlonkCircuit<F> {
    /// Copy constraints: precompute the extended permutation over circuit
    /// wires. Refer to Sec 5.2 and Sec 8.1 of https://eprint.iacr.org/2019/953.pdf for more details.
    #[inline]
    fn compute_extended_id_permutation(&mut self) {
        assert!(self.is_finalized());
        let n = self.eval_domain.size();

        // Compute the extended identity permutation
        // id[i*n+j] = k[i] * g^j
        let k: Vec<F> = compute_coset_representatives(self.num_wire_types, Some(n));
        // Precompute domain elements
        let group_elems: Vec<F> = self.eval_domain.elements().collect();
        // Compute extended identity permutation
        self.extended_id_permutation = vec![F::zero(); self.num_wire_types * n];
        for (i, &coset_repr) in k.iter().enumerate() {
            for (j, &group_elem) in group_elems.iter().enumerate() {
                self.extended_id_permutation[i * n + j] = coset_repr * group_elem;
            }
        }
    }

    #[inline]
    fn compute_extended_permutation(&self) -> Result<Vec<F>, CircuitError> {
        assert!(self.is_finalized());
        let n = self.eval_domain.size();

        // The extended wire permutation can be computed as
        // extended_perm[i] = id[wire_perm[i].into() * n + wire_perm[i].1]
        let extended_perm: Vec<F> = self
            .wire_permutation
            .iter()
            .map(|&(wire_id, gate_id)| {
                // if permutation value undefined, return 0
                if wire_id >= self.num_wire_types {
                    F::zero()
                } else {
                    self.extended_id_permutation[wire_id * n + gate_id]
                }
            })
            .collect();
        if extended_perm.len() != self.num_wire_types * n {
            return Err(ParameterError(
                "Length of the extended permutation vector should be number of gate \
                         (including padded dummy gates) * number of wire types"
                    .to_string(),
            ));
        }
        Ok(extended_perm)
    }
}

/// Methods for finalizing and merging the circuits.
impl<F: PrimeField> PlonkCircuit<F> {
    /// Finalize the setup of the circuit before arithmetization.
    pub fn finalize_for_arithmetization(&mut self) -> Result<(), CircuitError> {
        if self.is_finalized() {
            return Ok(());
        }
        let num_slots_needed = match self.support_lookup() {
            false => self.num_gates(),
            true => max(
                self.num_gates(),
                max(self.range_size()?, self.wire_variables[RANGE_WIRE_ID].len())
                    + self.num_table_elems()
                    + 1,
            ), // range gates and lookup gates need to have separate slots
        };
        self.eval_domain = Radix2EvaluationDomain::new(num_slots_needed)
            .ok_or(CircuitError::DomainCreationError)?;
        self.pad()?;
        self.rearrange_gates()?;
        self.compute_wire_permutation();
        self.compute_extended_id_permutation();
        Ok(())
    }

    /// Finalize the setup of a mergeable circuit.
    /// Two circuits can be merged only if they are with different circuit types
    /// The method only supports TurboPlonk circuits.
    pub fn finalize_for_mergeable_circuit(
        &mut self,
        circuit_type: MergeableCircuitType,
    ) -> Result<(), CircuitError> {
        if self.plonk_params.plonk_type != PlonkType::TurboPlonk {
            return Err(WrongPlonkType);
        }
        self.finalize_for_arithmetization()?;
        // double the domain size
        let n = self.eval_domain_size()?;
        self.eval_domain =
            Radix2EvaluationDomain::new(2 * n).ok_or(CircuitError::DomainCreationError)?;
        // pad dummy gates/wires in slots [n..2n)
        for _ in 0..n {
            self.gates.push(Box::new(PaddingGate));
        }
        for wire_id in 0..self.num_wire_types() {
            self.wire_variables[wire_id].resize(2 * n, self.zero());
        }
        if circuit_type == MergeableCircuitType::TypeA {
            // update wire permutation
            let mut wire_perm = vec![(self.num_wire_types, 0usize); self.num_wire_types * 2 * n];
            for i in 0..self.num_wire_types {
                for j in 0..n {
                    wire_perm[i * 2 * n + j] = self.wire_permutation[i * n + j];
                }
            }
            self.wire_permutation = wire_perm;
        } else {
            // reverse the gate indices.
            self.gates.reverse();
            for wire_id in 0..self.num_wire_types() {
                self.wire_variables[wire_id].reverse();
            }
            for io_gate in self.pub_input_gate_ids.iter_mut() {
                *io_gate = 2 * n - 1 - *io_gate;
            }
            // update wire_permutation
            let mut wire_perm = vec![(self.num_wire_types, 0usize); self.num_wire_types * 2 * n];
            for i in 0..self.num_wire_types {
                for j in 0..n {
                    let (wire_id, gate_id) = self.wire_permutation[i * n + j];
                    // the new gate index is the reverse of the original gate index
                    let gate_id = 2 * n - 1 - gate_id;
                    wire_perm[i * 2 * n + 2 * n - 1 - j] = (wire_id, gate_id);
                }
            }
            self.wire_permutation = wire_perm;
        }
        // need to recompute extended_id_permutation because the domain has changed.
        self.compute_extended_id_permutation();
        Ok(())
    }

    /// Merge a type A circuit with a type B circuit.
    /// Both circuits should have been finalized before.
    /// The method only supports TurboPlonk circuits.
    #[allow(dead_code)]
    pub fn merge(&self, other: &Self) -> Result<Self, CircuitError> {
        self.check_finalize_flag(true)?;
        other.check_finalize_flag(true)?;
        if self.eval_domain_size()? != other.eval_domain_size()? {
            return Err(ParameterError(format!(
                "cannot merge circuits with different domain sizes: {}, {}",
                self.eval_domain_size()?,
                other.eval_domain_size()?
            )));
        }
        if self.plonk_params.plonk_type != PlonkType::TurboPlonk
            || other.plonk_params.plonk_type != PlonkType::TurboPlonk
        {
            return Err(ParameterError(
                "do not support merging non-TurboPlonk circuits.".to_string(),
            ));
        }
        if self.num_inputs() != other.num_inputs() {
            return Err(ParameterError(format!(
                "self.num_inputs = {} different from other.num_inputs = {}",
                self.num_inputs(),
                other.num_inputs()
            )));
        }
        if self.pub_input_gate_ids[0] != 0 {
            return Err(ParameterError(
                "the first circuit is not type A".to_string(),
            ));
        }
        if other.pub_input_gate_ids[0] != other.eval_domain_size()? - 1 {
            return Err(ParameterError(
                "the second circuit is not type B".to_string(),
            ));
        }
        let num_vars = self.num_vars + other.num_vars;
        let witness: Vec<F> = [self.witness.as_slice(), other.witness.as_slice()].concat();
        let pub_input_gate_ids: Vec<usize> = [
            self.pub_input_gate_ids.as_slice(),
            other.pub_input_gate_ids.as_slice(),
        ]
        .concat();

        // merge gates and wire variables
        // the first circuit occupies the first n gates, the second circuit
        // occupies the last n gates.
        let n = self.eval_domain_size()? / 2;
        let mut gates = vec![];
        let mut wire_variables = [vec![], vec![], vec![], vec![], vec![], vec![]];
        for (j, gate) in self.gates.iter().take(n).enumerate() {
            gates.push((*gate).clone());
            for (i, wire_vars) in wire_variables
                .iter_mut()
                .enumerate()
                .take(self.num_wire_types)
            {
                wire_vars.push(self.wire_variable(i, j));
            }
        }
        for (j, gate) in other.gates.iter().skip(n).enumerate() {
            gates.push((*gate).clone());
            for (i, wire_vars) in wire_variables
                .iter_mut()
                .enumerate()
                .take(self.num_wire_types)
            {
                wire_vars.push(other.wire_variable(i, n + j) + self.num_vars);
            }
        }

        // merge wire_permutation
        let mut wire_permutation = vec![(0usize, 0usize); self.num_wire_types * 2 * n];
        for i in 0..self.num_wire_types {
            for j in 0..n {
                wire_permutation[i * 2 * n + j] = self.wire_permutation[i * 2 * n + j];
                wire_permutation[i * 2 * n + n + j] = other.wire_permutation[i * 2 * n + n + j];
            }
        }

        Ok(Self {
            num_vars,
            witness,
            gates,
            wire_variables,
            pub_input_gate_ids,
            wire_permutation,
            extended_id_permutation: self.extended_id_permutation.clone(),
            num_wire_types: self.num_wire_types,
            eval_domain: self.eval_domain,
            plonk_params: self.plonk_params,
            num_table_elems: 0,
            table_gate_ids: vec![],
        })
    }
}

impl<F> Arithmetization<F> for PlonkCircuit<F>
where
    F: PrimeField,
{
    fn srs_size(&self) -> Result<usize, CircuitError> {
        // extra 2 degree for masking polynomial to make snark zero-knowledge
        Ok(self.eval_domain_size()? + 2)
    }

    fn eval_domain_size(&self) -> Result<usize, CircuitError> {
        self.check_finalize_flag(true)?;
        Ok(self.eval_domain.size())
    }

    fn compute_selector_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, CircuitError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        if domain.size() < self.num_gates() {
            return Err(ParameterError(
                "Domain size should be bigger than number of constraint".to_string(),
            ));
        }
        // order: (lc, mul, hash, o, c, ecc) as specified in spec
        let selector_polys = parallelizable_slice_iter(&self.all_selectors())
            .map(|selector| DensePolynomial::from_coefficients_vec(domain.ifft(selector)))
            .collect();
        Ok(selector_polys)
    }

    fn compute_extended_permutation_polynomials(
        &self,
    ) -> Result<Vec<DensePolynomial<F>>, CircuitError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        let n = domain.size();
        let extended_perm = self.compute_extended_permutation()?;

        let extended_perm_polys: Vec<DensePolynomial<F>> =
            parallelizable_slice_iter(&(0..self.num_wire_types).collect::<Vec<_>>()) // current par_utils only support slice iterator, not range iterator.
                .map(|i| {
                    DensePolynomial::from_coefficients_vec(
                        domain.ifft(&extended_perm[i * n..(i + 1) * n]),
                    )
                })
                .collect();

        Ok(extended_perm_polys)
    }

    fn compute_prod_permutation_polynomial(
        &self,
        beta: &F,
        gamma: &F,
    ) -> Result<DensePolynomial<F>, CircuitError> {
        self.check_finalize_flag(true)?;
        let mut product_vec = vec![F::one()];
        let domain = &self.eval_domain;
        let n = domain.size();
        for j in 0..(n - 1) {
            // Nominator
            let mut a = F::one();
            // Denominator
            let mut b = F::one();
            for i in 0..self.num_wire_types {
                let wire_value = self.witness[self.wire_variable(i, j)];
                let tmp = wire_value + gamma;
                a *= tmp + *beta * self.extended_id_permutation[i * n + j];
                let (perm_i, perm_j) = self.wire_permutation[i * n + j];
                b *= tmp + *beta * self.extended_id_permutation[perm_i * n + perm_j];
            }
            let prev_prod = *product_vec.last().ok_or(CircuitError::IndexError)?;
            product_vec.push(prev_prod * a / b);
        }
        domain.ifft_in_place(&mut product_vec);
        Ok(DensePolynomial::from_coefficients_vec(product_vec))
    }

    fn compute_wire_polynomials(&self) -> Result<Vec<DensePolynomial<F>>, CircuitError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        if domain.size() < self.num_gates() {
            return Err(ParameterError(format!(
                "Domain size {} should be bigger than number of constraint {}",
                domain.size(),
                self.num_gates()
            )));
        }
        let witness = &self.witness;
        let wire_polys: Vec<DensePolynomial<F>> = parallelizable_slice_iter(&self.wire_variables)
            .take(self.num_wire_types())
            .map(|wire_vars| {
                let mut wire_vec: Vec<F> = wire_vars.iter().map(|&var| witness[var]).collect();
                domain.ifft_in_place(&mut wire_vec);
                DensePolynomial::from_coefficients_vec(wire_vec)
            })
            .collect();

        assert_eq!(wire_polys.len(), self.num_wire_types());
        Ok(wire_polys)
    }

    fn compute_pub_input_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        let mut pub_input_vec = vec![F::zero(); domain.size()];
        self.pub_input_gate_ids.iter().for_each(|&io_gate_id| {
            let var = self.wire_variables[GATE_WIDTH][io_gate_id];
            pub_input_vec[io_gate_id] = self.witness[var];
        });
        domain.ifft_in_place(&mut pub_input_vec);
        Ok(DensePolynomial::from_coefficients_vec(pub_input_vec))
    }

    // Plookup-related methods
    //
    fn compute_range_table_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        let range_table = self.compute_range_table()?;
        let domain = &self.eval_domain;
        Ok(DensePolynomial::from_coefficients_vec(
            domain.ifft(&range_table),
        ))
    }

    fn compute_key_table_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        Ok(DensePolynomial::from_coefficients_vec(
            domain.ifft(&self.table_key_vec()),
        ))
    }

    fn compute_table_dom_sep_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        Ok(DensePolynomial::from_coefficients_vec(
            domain.ifft(&self.table_dom_sep_vec()),
        ))
    }

    fn compute_q_dom_sep_polynomial(&self) -> Result<DensePolynomial<F>, CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        Ok(DensePolynomial::from_coefficients_vec(
            domain.ifft(&self.q_dom_sep()),
        ))
    }

    fn compute_merged_lookup_table(&self, tau: F) -> Result<Vec<F>, CircuitError> {
        let range_table = self.compute_range_table()?;
        let table_key_vec = self.table_key_vec();
        let table_dom_sep_vec = self.table_dom_sep_vec();
        let q_lookup_vec = self.q_lookup();

        let mut merged_lookup_table = vec![];
        for i in 0..self.eval_domain_size()? {
            merged_lookup_table.push(self.merged_table_value(
                tau,
                &range_table,
                &table_key_vec,
                &table_dom_sep_vec,
                &q_lookup_vec,
                i,
            )?);
        }

        Ok(merged_lookup_table)
    }

    fn compute_lookup_prod_polynomial(
        &self,
        tau: &F,
        beta: &F,
        gamma: &F,
        merged_lookup_table: &[F],
        sorted_vec: &[F],
    ) -> Result<DensePolynomial<F>, CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        let n = domain.size();
        if n != self.wire_variables[RANGE_WIRE_ID].len() {
            return Err(ParameterError(
                "Domain size should match the size of the padded lookup variables vector"
                    .to_string(),
            ));
        }
        if n != merged_lookup_table.len() {
            return Err(ParameterError(
                "Domain size should match the size of the padded lookup table".to_string(),
            ));
        }
        if 2 * n - 1 != sorted_vec.len() {
            return Err(ParameterError(
                "The sorted vector has wrong length".to_string(),
            ));
        }

        let mut product_vec = vec![F::one()];
        let beta_plus_one = F::one() + *beta;
        let gamma_mul_beta_plus_one = *gamma * beta_plus_one;
        let q_lookup_vec = self.q_lookup();
        let q_dom_sep_vec = self.q_dom_sep();
        for j in 0..(n - 2) {
            // compute merged lookup witness value
            let lookup_wire_val =
                self.merged_lookup_wire_value(*tau, j, &q_lookup_vec, &q_dom_sep_vec)?;
            let table_val = merged_lookup_table[j];
            let table_next_val = merged_lookup_table[j + 1];
            let h1_val = sorted_vec[j];
            let h1_next_val = sorted_vec[j + 1];
            let h2_val = sorted_vec[n - 1 + j];
            let h2_next_val = sorted_vec[n + j];

            // Nominator
            let a = beta_plus_one
                * (*gamma + lookup_wire_val)
                * (gamma_mul_beta_plus_one + table_val + *beta * table_next_val);
            // Denominator
            let b = (gamma_mul_beta_plus_one + h1_val + *beta * h1_next_val)
                * (gamma_mul_beta_plus_one + h2_val + *beta * h2_next_val);

            let prev_prod = *product_vec.last().ok_or(CircuitError::IndexError)?;
            product_vec.push(prev_prod * a / b);
        }
        product_vec.push(F::one());
        domain.ifft_in_place(&mut product_vec);
        Ok(DensePolynomial::from_coefficients_vec(product_vec))
    }

    fn compute_lookup_sorted_vec_polynomials(
        &self,
        tau: F,
        merged_lookup_table: &[F],
    ) -> Result<SortedLookupVecAndPolys<F>, CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        let n = domain.size();
        if n != self.wire_variables[RANGE_WIRE_ID].len() {
            return Err(ParameterError(
                "Domain size should match the size of the padded lookup variables vector"
                    .to_string(),
            ));
        }
        if n != merged_lookup_table.len() {
            return Err(ParameterError(
                "Domain size should match the size of the padded lookup table".to_string(),
            ));
        }
        // only the first n-1 variables are for lookup
        let mut lookup_map = HashMap::<F, usize>::new();
        let q_lookup_vec = self.q_lookup();
        let q_dom_sep_vec = self.q_dom_sep();
        for i in 0..(n - 1) {
            let elem = self.merged_lookup_wire_value(tau, i, &q_lookup_vec, &q_dom_sep_vec)?;
            let n_lookups = lookup_map.entry(elem).or_insert(0);
            *n_lookups += 1;
        }
        // merge-sort the lookup vector with the (merged) lookup table
        // according to the order of the (merged) lookup table.
        let mut sorted_vec = vec![];
        for elem in merged_lookup_table.iter() {
            if let Some(n_lookup) = lookup_map.get(elem) {
                sorted_vec.extend(vec![*elem; 1 + n_lookup]);
                lookup_map.remove(elem);
            } else {
                sorted_vec.push(*elem);
            }
        }

        if sorted_vec.len() != 2 * n - 1 {
            return Err(ParameterError("The sorted vector has wrong length, some lookup variables might be outside the table".to_string()));
        }
        let h1_poly = DensePolynomial::from_coefficients_vec(domain.ifft(&sorted_vec[..n]));
        let h2_poly = DensePolynomial::from_coefficients_vec(domain.ifft(&sorted_vec[n - 1..]));
        Ok((sorted_vec, h1_poly, h2_poly))
    }
}

/// Private helper methods for arithmetizations.
impl<F: PrimeField> PlonkCircuit<F> {
    #[inline]
    fn compute_range_table(&self) -> Result<Vec<F>, CircuitError> {
        self.check_plonk_type(PlonkType::UltraPlonk)?;
        self.check_finalize_flag(true)?;
        let domain = &self.eval_domain;
        let range_size = self.range_size()?;
        if domain.size() < range_size {
            return Err(ParameterError(format!(
                "Domain size {} < range size {}",
                domain.size(),
                range_size
            )));
        }
        let mut range_table: Vec<F> = (0..range_size).map(|i| F::from(i as u32)).collect();
        range_table.resize(domain.size(), F::zero());
        Ok(range_table)
    }

    #[inline]
    fn merged_table_value(
        &self,
        tau: F,
        range_table: &[F],
        table_key_vec: &[F],
        table_dom_sep_vec: &[F],
        q_lookup_vec: &[F],
        i: usize,
    ) -> Result<F, CircuitError> {
        let range_val = range_table[i];
        let key_val = table_key_vec[i];
        let dom_sep_val = table_dom_sep_vec[i];
        let q_lookup_val = q_lookup_vec[i];
        let table_val_1 = self.witness(self.wire_variable(TABLE_VAL_1_WIRE_ID, i))?;
        let table_val_2 = self.witness(self.wire_variable(TABLE_VAL_2_WIRE_ID, i))?;
        Ok(range_val
            + q_lookup_val
                * tau
                * (dom_sep_val + tau * (key_val + tau * (table_val_1 + tau * table_val_2))))
    }

    #[inline]
    fn merged_lookup_wire_value(
        &self,
        tau: F,
        i: usize,
        q_lookup_vec: &[F],
        q_dom_sep_vec: &[F],
    ) -> Result<F, CircuitError> {
        let w_range_val = self.witness(self.wire_variable(RANGE_WIRE_ID, i))?;
        let lookup_key = self.witness(self.wire_variable(LOOKUP_KEY_WIRE_ID, i))?;
        let lookup_val_1 = self.witness(self.wire_variable(LOOKUP_VAL_1_WIRE_ID, i))?;
        let lookup_val_2 = self.witness(self.wire_variable(LOOKUP_VAL_2_WIRE_ID, i))?;
        let q_lookup_val = q_lookup_vec[i];
        let q_dom_sep_val = q_dom_sep_vec[i];
        Ok(w_range_val
            + q_lookup_val
                * tau
                * (q_dom_sep_val + tau * (lookup_key + tau * (lookup_val_1 + tau * lookup_val_2))))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::{Arithmetization, Circuit, PlonkCircuit};
    use crate::{constants::compute_coset_representatives, errors::CircuitError};
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_ff::PrimeField;
    use ark_poly::{domain::Radix2EvaluationDomain, univariate::DensePolynomial, EvaluationDomain};
    use ark_std::{vec, vec::Vec};
    use jf_utils::test_rng;

    #[test]
    fn test_circuit_trait() -> Result<(), CircuitError> {
        test_circuit_trait_helper::<FqEd254>()?;
        test_circuit_trait_helper::<FqEd377>()?;
        test_circuit_trait_helper::<FqEd381>()?;
        test_circuit_trait_helper::<Fq377>()
    }

    fn test_circuit_trait_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        // Create secret variables.
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(1u32))?;
        // Constant gate: a = 3.
        circuit.enforce_constant(a, F::from(3u32))?;
        // Bool gate: b is bool.
        circuit.enforce_bool(b)?;
        // Addition gate: c = a + b = 4.
        let c = circuit.add(a, b)?;
        // Subtraction gate: d = a - b = 2.
        let d = circuit.sub(a, b)?;
        // Multiplication gate: e = c * d = 8
        let e = circuit.mul(c, d)?;
        // Create public variables.
        let f = circuit.create_public_variable(F::from(8u32))?;
        // Equality gate: e = f = 8
        circuit.enforce_equal(e, f)?;

        // Check the number of gates:
        // 2 constant gates for default 0/1, 6 arithmetic gates, 1 io gate.
        assert_eq!(circuit.num_gates(), 9);
        // Check the number of variables:
        assert_eq!(circuit.num_vars(), 8);
        // Chech the number of public inputs:
        assert_eq!(circuit.num_inputs(), 1);

        // Check circuit satisfiability
        let pub_input = &[F::from(8u32)];
        let verify = circuit.check_circuit_satisfiability(pub_input);
        assert!(verify.is_ok(), "{:?}", verify.unwrap_err());
        let bad_pub_input = &[F::from(0u32)];
        assert!(circuit.check_circuit_satisfiability(bad_pub_input).is_err());
        // Wrong public input length
        let bad_pub_input = &[F::from(8u32), F::from(8u32)];
        assert!(circuit.check_circuit_satisfiability(bad_pub_input).is_err());

        Ok(())
    }

    #[test]
    fn test_add() -> Result<(), CircuitError> {
        test_add_helper::<FqEd254>()?;
        test_add_helper::<FqEd377>()?;
        test_add_helper::<FqEd381>()?;
        test_add_helper::<Fq377>()
    }

    fn test_add_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(1u32))?;
        let c = circuit.add(a, b)?;

        // Check circuits.
        assert_eq!(circuit.witness(c)?, F::from(4u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(c) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.add(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_sub() -> Result<(), CircuitError> {
        test_sub_helper::<FqEd254>()?;
        test_sub_helper::<FqEd377>()?;
        test_sub_helper::<FqEd381>()?;
        test_sub_helper::<Fq377>()
    }

    fn test_sub_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(1u32))?;
        let c = circuit.sub(a, b)?;

        // Check circuits.
        assert_eq!(circuit.witness(c)?, F::from(2u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(c) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.sub(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_mul() -> Result<(), CircuitError> {
        test_mul_helper::<FqEd254>()?;
        test_mul_helper::<FqEd377>()?;
        test_mul_helper::<FqEd381>()?;
        test_mul_helper::<Fq377>()
    }

    fn test_mul_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(2u32))?;
        let c = circuit.mul(a, b)?;

        // Check circuits.
        assert_eq!(circuit.witness(c)?, F::from(6u32));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(c) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.mul(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_equal_gate() -> Result<(), CircuitError> {
        test_equal_gate_helper::<FqEd254>()?;
        test_equal_gate_helper::<FqEd377>()?;
        test_equal_gate_helper::<FqEd381>()?;
        test_equal_gate_helper::<Fq377>()
    }
    fn test_equal_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_variable(F::from(3u32))?;
        circuit.enforce_equal(a, b)?;

        // Check circuits.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(b) = F::from(1u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.enforce_equal(circuit.num_vars(), a).is_err());

        Ok(())
    }

    #[test]
    fn test_bool() -> Result<(), CircuitError> {
        test_bool_helper::<FqEd254>()?;
        test_bool_helper::<FqEd377>()?;
        test_bool_helper::<FqEd381>()?;
        test_bool_helper::<Fq377>()
    }

    fn test_bool_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(0u32))?;
        circuit.enforce_bool(a)?;

        // Check circuits.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit.enforce_bool(circuit.num_vars()).is_err());

        Ok(())
    }

    #[test]
    fn test_constant() -> Result<(), CircuitError> {
        test_constant_helper::<FqEd254>()?;
        test_constant_helper::<FqEd377>()?;
        test_constant_helper::<FqEd381>()?;
        test_constant_helper::<Fq377>()
    }
    fn test_constant_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(10u32))?;
        circuit.enforce_constant(a, F::from(10u32))?;

        // Check circuits.
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // Check variable out of bound error.
        assert!(circuit
            .enforce_constant(circuit.num_vars(), F::from(0u32))
            .is_err());

        Ok(())
    }

    #[test]
    fn test_io_gate() -> Result<(), CircuitError> {
        test_io_gate_helper::<FqEd254>()?;
        test_io_gate_helper::<FqEd377>()?;
        test_io_gate_helper::<FqEd381>()?;
        test_io_gate_helper::<Fq377>()
    }

    fn test_io_gate_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let b = circuit.create_variable(F::from(0u32))?;
        let a = circuit.create_public_variable(F::from(1u32))?;
        circuit.enforce_bool(a)?;
        circuit.enforce_bool(b)?;
        circuit.set_variable_public(b)?;

        // Different valid public inputs should all pass the circuit check.
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(1u32), F::from(0u32)])
            .is_ok());
        *circuit.witness_mut(a) = F::from(0u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(0u32)])
            .is_ok());
        *circuit.witness_mut(b) = F::from(1u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(1u32)])
            .is_ok());

        // Invalid public inputs should fail the circuit check.
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(1u32)])
            .is_err());
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(1u32)])
            .is_err());
        *circuit.witness_mut(a) = F::from(0u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(2u32)])
            .is_err());
        *circuit.witness_mut(b) = F::from(2u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(0u32), F::from(2u32)])
            .is_err());

        Ok(())
    }

    #[test]
    fn test_io_gate_multi_inputs() -> Result<(), CircuitError> {
        test_io_gate_multi_inputs_helper::<FqEd254>()?;
        test_io_gate_multi_inputs_helper::<FqEd377>()?;
        test_io_gate_multi_inputs_helper::<FqEd381>()?;
        test_io_gate_multi_inputs_helper::<Fq377>()
    }
    fn test_io_gate_multi_inputs_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit = PlonkCircuit::<F>::new_turbo_plonk();
        let a = circuit.create_public_variable(F::from(1u32))?;
        let b = circuit.create_public_variable(F::from(2u32))?;
        let c = circuit.create_public_variable(F::from(3u32))?;
        circuit.add_gate(a, b, c)?;

        // Good path
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(1u32), F::from(2u32), F::from(3u32)])
            .is_ok());
        // The circuit check should fail given a public input with wrong order.
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(1u32), F::from(3u32)])
            .is_err());
        // A different valid public input should pass the circuit check.
        *circuit.witness_mut(a) = F::from(4u32);
        *circuit.witness_mut(b) = F::from(8u32);
        *circuit.witness_mut(c) = F::from(12u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(4u32), F::from(8u32), F::from(12u32)])
            .is_ok());
        // An invalid public input should fail the circuit check.
        *circuit.witness_mut(a) = F::from(2u32);
        assert!(circuit
            .check_circuit_satisfiability(&[F::from(2u32), F::from(8u32), F::from(12u32)])
            .is_err());

        Ok(())
    }

    fn create_turbo_plonk_instance<F: PrimeField>(
    ) -> Result<(PlonkCircuit<F>, Vec<F>), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_public_variable(F::from(1u32))?;
        circuit.enforce_constant(a, F::from(3u32))?;
        circuit.enforce_bool(b)?;
        let c = circuit.add(a, b)?;
        let d = circuit.sub(a, b)?;
        let e = circuit.mul(c, d)?;
        let f = circuit.create_public_variable(F::from(8u32))?;
        circuit.enforce_equal(e, f)?;

        Ok((circuit, vec![F::from(1u32), F::from(8u32)]))
    }

    fn create_ultra_plonk_instance<F: PrimeField>(
    ) -> Result<(PlonkCircuit<F>, Vec<F>), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(4);
        let a = circuit.create_variable(F::from(3u32))?;
        let b = circuit.create_public_variable(F::from(1u32))?;
        circuit.enforce_constant(a, F::from(3u32))?;
        circuit.enforce_bool(b)?;
        let c = circuit.add(a, b)?;
        let d = circuit.sub(a, b)?;
        let e = circuit.mul(c, d)?;
        let f = circuit.create_public_variable(F::from(8u32))?;
        circuit.enforce_equal(e, f)?;

        // Add range gates
        circuit.add_range_check_variable(b)?;
        circuit.add_range_check_variable(c)?;
        circuit.add_range_check_variable(e)?;
        circuit.add_range_check_variable(f)?;
        circuit.add_range_check_variable(circuit.zero())?;

        // Add variable table lookup gates
        // table = [(3,1), (4,2), (8,8)]
        let table_vars = [(a, b), (c, d), (e, f)];
        // lookup_witness = [(0, 3, 1), (2, 8, 8)]
        let x = circuit.create_variable(F::from(3u8))?;
        let y = circuit.create_variable(F::from(8u8))?;
        let key1 = circuit.create_variable(F::from(2u8))?;
        let lookup_vars = [(circuit.zero(), x, circuit.one()), (key1, y, y)];
        circuit.create_table_and_lookup_variables(&lookup_vars, &table_vars)?;

        Ok((circuit, vec![F::from(1u32), F::from(8u32)]))
    }

    /// Tests related to permutations
    #[test]
    fn test_compute_extended_permutation() -> Result<(), CircuitError> {
        test_compute_extended_permutation_helper::<FqEd254>()?;
        test_compute_extended_permutation_helper::<FqEd377>()?;
        test_compute_extended_permutation_helper::<FqEd381>()?;
        test_compute_extended_permutation_helper::<Fq377>()
    }

    fn test_compute_extended_permutation_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        let a = circuit.create_variable(F::from(2u32))?;
        let b = circuit.create_public_variable(F::from(3u32))?;
        let c = circuit.add(a, b)?;
        let d = circuit.add(circuit.one(), a)?;
        let _ = circuit.mul(c, d)?;

        // Create a UltraPlonk instance
        let (mut circuit, _) = create_ultra_plonk_instance::<F>()?;
        check_wire_permutation_and_extended_id_permutation(&mut circuit)?;

        Ok(())
    }

    fn check_wire_permutation_and_extended_id_permutation<F: PrimeField>(
        circuit: &mut PlonkCircuit<F>,
    ) -> Result<(), CircuitError> {
        let domain = Radix2EvaluationDomain::<F>::new(circuit.num_gates())
            .ok_or(CircuitError::DomainCreationError)?;
        let n = domain.size();
        circuit.eval_domain = domain;

        // Check wire permutation's correctness
        circuit.pad()?;
        circuit.compute_wire_permutation();
        let mut visit_wire = vec![false; circuit.num_wire_types * n];
        let mut visit_variable = vec![false; circuit.num_vars()];

        for i in 0..circuit.num_wire_types {
            for j in 0..n {
                if visit_wire[i * n + j] {
                    continue;
                }
                // Compute the cycle's variable.
                let cycle_var = circuit.wire_variable(i, j);
                // The variable shouldn't have been marked yet.
                assert!(!visit_variable[cycle_var]);
                visit_variable[cycle_var] = true;

                // Visit the cycle.
                let mut wire_id = i;
                let mut gate_id = j;
                visit_wire[i * n + j] = true;
                loop {
                    let (next_wire_id, next_gate_id) =
                        circuit.wire_permutation[wire_id * n + gate_id];
                    // Break the loop if back to the starting wire.
                    if next_wire_id == i && next_gate_id == j {
                        break;
                    }
                    let next_var = circuit.wire_variable(next_wire_id, next_gate_id);
                    // The adjacent wire's variable should be the same.
                    assert_eq!(cycle_var, next_var);
                    // The adjacent wire shouldn't have been marked yet.
                    assert!(!visit_wire[next_wire_id * n + next_gate_id]);
                    visit_wire[next_wire_id * n + next_gate_id] = true;
                    wire_id = next_wire_id;
                    gate_id = next_gate_id;
                }
            }
        }

        // Check the correctness of the extended id permutation
        circuit.compute_extended_id_permutation();
        // Compute quadratic non-residues and group elements.
        let k: Vec<F> = compute_coset_representatives(circuit.num_wire_types, Some(n));
        let group_elems: Vec<F> = domain.elements().collect();
        (0..circuit.num_wire_types).for_each(|i| {
            (0..n).for_each(|j| {
                assert_eq!(
                    k[i] * group_elems[j],
                    circuit.extended_id_permutation[i * n + j]
                )
            });
        });

        Ok(())
    }

    // Test flags
    //

    #[test]
    fn test_ultra_plonk_flag() -> Result<(), CircuitError> {
        test_ultra_plonk_flag_helper::<FqEd254>()?;
        test_ultra_plonk_flag_helper::<FqEd377>()?;
        test_ultra_plonk_flag_helper::<FqEd381>()?;
        test_ultra_plonk_flag_helper::<Fq377>()
    }

    fn test_ultra_plonk_flag_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        // Check that below methods return errors when not in UltraPlonk mode.
        assert!(circuit.add_range_check_variable(0).is_err());
        circuit.finalize_for_arithmetization()?;
        assert!(circuit.compute_range_table_polynomial().is_err());
        assert!(circuit.compute_key_table_polynomial().is_err());
        assert!(circuit.compute_merged_lookup_table(F::one()).is_err());
        assert!(circuit
            .compute_lookup_sorted_vec_polynomials(F::one(), &[])
            .is_err());
        assert!(circuit
            .compute_lookup_prod_polynomial(&F::one(), &F::one(), &F::one(), &[], &[])
            .is_err());

        Ok(())
    }

    #[test]
    fn test_finalized_flag() -> Result<(), CircuitError> {
        test_finalized_flag_helper::<FqEd254>()?;
        test_finalized_flag_helper::<FqEd377>()?;
        test_finalized_flag_helper::<FqEd381>()?;
        test_finalized_flag_helper::<Fq377>()
    }

    fn test_finalized_flag_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_turbo_plonk();
        // Should not call arithmetization methods before finalizing the circuit.
        assert!(circuit.compute_selector_polynomials().is_err());
        assert!(circuit.compute_extended_permutation_polynomials().is_err());
        assert!(circuit.compute_pub_input_polynomial().is_err());
        assert!(circuit.compute_wire_polynomials().is_err());
        assert!(circuit
            .compute_prod_permutation_polynomial(&F::one(), &F::one())
            .is_err());

        // Should not insert gates or add variables after finalizing the circuit.
        circuit.finalize_for_arithmetization()?;
        assert!(circuit.create_variable(F::one()).is_err());
        assert!(circuit.create_public_variable(F::one()).is_err());
        assert!(circuit.add_gate(0, 0, 0).is_err());
        assert!(circuit.sub_gate(0, 0, 0).is_err());
        assert!(circuit.mul_gate(0, 0, 0).is_err());
        assert!(circuit.enforce_constant(0, F::one()).is_err());
        assert!(circuit.enforce_bool(0).is_err());
        assert!(circuit.enforce_equal(0, 0).is_err());

        Ok(())
    }

    #[test]

    fn test_ultra_plonk_finalized_flag() -> Result<(), CircuitError> {
        test_ultra_plonk_finalized_flag_helper::<FqEd254>()?;
        test_ultra_plonk_finalized_flag_helper::<FqEd377>()?;
        test_ultra_plonk_finalized_flag_helper::<FqEd381>()?;
        test_ultra_plonk_finalized_flag_helper::<Fq377>()
    }

    fn test_ultra_plonk_finalized_flag_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(1);
        // Should not call arithmetization methods before finalizing the circuit.
        assert!(circuit.compute_selector_polynomials().is_err());
        assert!(circuit.compute_extended_permutation_polynomials().is_err());
        assert!(circuit.compute_pub_input_polynomial().is_err());
        assert!(circuit.compute_wire_polynomials().is_err());
        assert!(circuit
            .compute_prod_permutation_polynomial(&F::one(), &F::one())
            .is_err());
        assert!(circuit.compute_range_table_polynomial().is_err());
        assert!(circuit.compute_key_table_polynomial().is_err());
        assert!(circuit.compute_merged_lookup_table(F::one()).is_err());
        assert!(circuit
            .compute_lookup_sorted_vec_polynomials(F::one(), &[])
            .is_err());
        assert!(circuit
            .compute_lookup_prod_polynomial(&F::one(), &F::one(), &F::one(), &[], &[])
            .is_err());

        // Should not insert gates or add variables after finalizing the circuit.
        circuit.finalize_for_arithmetization()?;
        assert!(circuit.create_variable(F::one()).is_err());
        assert!(circuit.create_public_variable(F::one()).is_err());
        assert!(circuit.add_gate(0, 0, 0).is_err());
        assert!(circuit.sub_gate(0, 0, 0).is_err());
        assert!(circuit.mul_gate(0, 0, 0).is_err());
        assert!(circuit.enforce_constant(0, F::one()).is_err());
        assert!(circuit.enforce_bool(0).is_err());
        assert!(circuit.enforce_equal(0, 0).is_err());
        // Plookup-related methods
        assert!(circuit.add_range_check_variable(0).is_err());

        Ok(())
    }

    // Test arithmetizations
    //
    #[test]
    fn test_arithmetization() -> Result<(), CircuitError> {
        test_arithmetization_helper::<FqEd254>()?;
        test_arithmetization_helper::<FqEd377>()?;
        test_arithmetization_helper::<FqEd381>()?;
        test_arithmetization_helper::<Fq377>()
    }

    fn test_arithmetization_helper<F: PrimeField>() -> Result<(), CircuitError> {
        // Create the TurboPlonk circuit
        let (mut circuit, pub_inputs) = create_turbo_plonk_instance::<F>()?;
        circuit.finalize_for_arithmetization()?;
        test_arithmetization_for_circuit(circuit, pub_inputs)?;

        // Create the UltraPlonk circuit
        let (mut circuit, pub_inputs) = create_ultra_plonk_instance::<F>()?;
        circuit.finalize_for_arithmetization()?;
        test_arithmetization_for_lookup_circuit(&circuit)?;
        test_arithmetization_for_circuit(circuit, pub_inputs)?;

        Ok(())
    }

    // Check that the polynomial `poly` is consistent with the evaluations `evals`
    // over the domain.
    fn check_polynomial<F: PrimeField>(poly: &DensePolynomial<F>, evals: &[F]) {
        let domain = Radix2EvaluationDomain::new(evals.len()).unwrap();
        let poly_eval = poly.evaluate_over_domain_by_ref(domain);
        for (&a, &b) in poly_eval.evals.iter().zip(evals.iter()) {
            assert_eq!(a, b);
        }
    }

    pub(crate) fn test_arithmetization_for_lookup_circuit<F: PrimeField>(
        circuit: &PlonkCircuit<F>,
    ) -> Result<(), CircuitError> {
        let n = circuit.eval_domain.size();

        // Check range table polynomial
        let range_table_poly = circuit.compute_range_table_polynomial()?;
        let range_table = circuit.compute_range_table()?;
        check_polynomial(&range_table_poly, &range_table);

        // Check key table polynomial
        let key_table_poly = circuit.compute_key_table_polynomial()?;
        let key_table = circuit.table_key_vec();
        check_polynomial(&key_table_poly, &key_table);

        // Check sorted vector polynomials
        let rng = &mut test_rng();
        let tau = F::rand(rng);
        let merged_lookup_table = circuit.compute_merged_lookup_table(tau)?;
        let (sorted_vec, h1_poly, h2_poly) =
            circuit.compute_lookup_sorted_vec_polynomials(tau, &merged_lookup_table)?;
        assert_eq!(sorted_vec.len(), 2 * n - 1);
        // check that sorted_vec is sorted according to the order of
        // `merged_lookup_table`.
        assert_eq!(sorted_vec[0], merged_lookup_table[0]);
        let mut ptr = 1;
        for slice in sorted_vec.windows(2) {
            // find the next different value in `sorted_vec`
            if slice[0] == slice[1] {
                continue;
            }
            // find the next different value in `merged_lookup_table`
            while ptr < n && merged_lookup_table[ptr] == merged_lookup_table[ptr - 1] {
                ptr += 1;
            }
            assert!(ptr < n);
            assert_eq!(merged_lookup_table[ptr], slice[1]);
            ptr += 1;
        }
        // assert that the elements in `merged_lookup_table` have been exhausted
        assert_eq!(ptr, n);

        check_polynomial(&h1_poly, &sorted_vec[..n]);
        check_polynomial(&h2_poly, &sorted_vec[n - 1..]);

        // Check product accumulation polynomial
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let prod_poly = circuit.compute_lookup_prod_polynomial(
            &tau,
            &beta,
            &gamma,
            &merged_lookup_table,
            &sorted_vec,
        )?;
        let mut prod_evals = vec![F::one()];
        let one_plus_beta = F::one() + beta;
        let gamma_mul_one_plus_beta = gamma * one_plus_beta;
        let q_lookup_vec = circuit.q_lookup();
        let q_dom_sep = circuit.q_dom_sep();
        for j in 0..(n - 2) {
            let lookup_wire_val =
                circuit.merged_lookup_wire_value(tau, j, &q_lookup_vec, &q_dom_sep)?;
            let table_val = merged_lookup_table[j];
            let table_next_val = merged_lookup_table[j + 1];
            let h1_val = sorted_vec[j];
            let h1_next_val = sorted_vec[j + 1];
            let h2_val = sorted_vec[n - 1 + j];
            let h2_next_val = sorted_vec[n + j];

            // Nominator
            let a = one_plus_beta
                * (gamma + lookup_wire_val)
                * (gamma_mul_one_plus_beta + table_val + beta * table_next_val);
            // Denominator
            let b = (gamma_mul_one_plus_beta + h1_val + beta * h1_next_val)
                * (gamma_mul_one_plus_beta + h2_val + beta * h2_next_val);
            let prod = prod_evals[j] * a / b;
            prod_evals.push(prod);
        }
        prod_evals.push(F::one());
        check_polynomial(&prod_poly, &prod_evals);

        Ok(())
    }

    pub(crate) fn test_arithmetization_for_circuit<F: PrimeField>(
        circuit: PlonkCircuit<F>,
        pub_inputs: Vec<F>,
    ) -> Result<(), CircuitError> {
        // Check arithmetizations
        let n = circuit.eval_domain.size();

        // Check selector polynomials
        let selector_polys = circuit.compute_selector_polynomials()?;
        selector_polys
            .iter()
            .zip(circuit.all_selectors().iter())
            .for_each(|(poly, evals)| check_polynomial(poly, evals));

        // Check wire witness polynomials
        let wire_polys = circuit.compute_wire_polynomials()?;
        for (poly, wire_vars) in wire_polys
            .iter()
            .zip(circuit.wire_variables.iter().take(circuit.num_wire_types()))
        {
            let wire_evals: Vec<F> = wire_vars.iter().map(|&var| circuit.witness[var]).collect();
            check_polynomial(poly, &wire_evals);
        }

        // Check public input polynomial
        let pi_poly = circuit.compute_pub_input_polynomial()?;
        let mut pi_evals = pub_inputs;
        pi_evals.extend(vec![F::zero(); n - 2]);
        check_polynomial(&pi_poly, &pi_evals);

        // Check extended permutation polynomials
        let sigma_polys = circuit.compute_extended_permutation_polynomials()?;
        let extended_perm: Vec<F> = circuit
            .wire_permutation
            .iter()
            .map(|&(i, j)| circuit.extended_id_permutation[i * n + j])
            .collect();
        for (i, poly) in sigma_polys.iter().enumerate() {
            check_polynomial(poly, &extended_perm[i * n..(i + 1) * n]);
        }

        // Check grand product polynomial for permutation
        let rng = &mut test_rng();
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let prod_poly = circuit.compute_prod_permutation_polynomial(&beta, &gamma)?;
        let mut prod_evals = vec![F::one()];
        for j in 0..(n - 1) {
            // Nominator
            let mut a = F::one();
            // Denominator
            let mut b = F::one();
            for i in 0..circuit.num_wire_types {
                let wire_value = circuit.witness[circuit.wire_variable(i, j)];
                a *= wire_value + beta * circuit.extended_id_permutation[i * n + j] + gamma;
                b *= wire_value + beta * extended_perm[i * n + j] + gamma;
            }
            let prod = prod_evals[j] * a / b;
            prod_evals.push(prod);
        }
        check_polynomial(&prod_poly, &prod_evals);

        Ok(())
    }
}
