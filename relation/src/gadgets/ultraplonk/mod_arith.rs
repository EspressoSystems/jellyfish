// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Modular arithmetic gates
use crate::{
    constants::GATE_WIDTH,
    errors::CircuitError::{self, ParameterError},
    gadgets::utils::next_multiple,
    Circuit, PlonkCircuit, Variable,
};
use ark_ff::PrimeField;
use ark_std::{format, string::ToString, vec, vec::Vec};
use num_bigint::BigUint;

macro_rules! to_big_int {
    ($x:expr) => {
        ($x).into_bigint().into()
    };
}

#[derive(Debug, Clone, Eq, PartialEq, Default, Copy)]
/// A field element represented by:
/// p = p.0 + 2^m * p.1.
/// The struct is useful in modular multiplication
/// as the multiplication of two components (e.g. p.0 * q.0)
/// won't overflow the prime field.
/// Warning: for performance reasons, when this struct is used,
/// we will assume 2^m - two_power_m without checking.
pub struct FpElem<F: PrimeField> {
    p: (F, F),
    m: usize,
    two_power_m: F,
}

impl<F> FpElem<F>
where
    F: PrimeField,
{
    /// Create a FpElem struct from field element `p` and split parameter `m`,
    /// where `m` <= F::MODULUS_BIT_SIZE / 2
    pub fn new(p: &F, m: usize, two_power_m: Option<F>) -> Result<Self, CircuitError> {
        if m > F::MODULUS_BIT_SIZE as usize / 2 {
            return Err(ParameterError(format!(
                "field split parameter ({}) larger than half of the field size ({}) in bits",
                m,
                F::MODULUS_BIT_SIZE / 2
            )));
        }
        let two_power_m = match two_power_m {
            Some(p) => p,
            None => F::from(2u8).pow([m as u64]),
        };
        let (p1, p0) = div_rem(p, &two_power_m);
        Ok(Self {
            p: (p0, p1),
            m,
            two_power_m,
        })
    }

    /// Convert into a single field element.
    pub fn field_elem(&self) -> F {
        self.p.0 + self.two_power_m * self.p.1
    }

    /// Expose the field element components
    pub fn components(&self) -> (F, F) {
        self.p
    }

    /// Expose the m parameter
    pub fn param_m(&self) -> usize {
        self.m
    }

    /// Expose 2^m parameter
    pub fn two_power_m(&self) -> F {
        self.two_power_m
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default, Copy)]
/// Represent variable of an Fp element:
///   elem = witness[vars.0] + 2^m * witness[vars.1]
/// Warning: for performance reasons, when this struct is used,
/// we will assume 2^m - two_power_m without checking.
pub struct FpElemVar<F: PrimeField> {
    vars: (Variable, Variable),
    m: usize,
    two_power_m: F,
}

impl<F: PrimeField> FpElemVar<F> {
    /// Create an FpElemVar from Fp element variable `var` and split parameter
    /// `m`. Does not perform range checks on the resulting variables.
    /// To create an `FpElemVar` from a field element, consider to
    /// use `new_from_field_element` instead (which comes with
    /// a range proof for the field element).
    pub fn new_unchecked(
        cs: &mut PlonkCircuit<F>,
        var: Variable,
        m: usize,
        two_power_m: Option<F>,
    ) -> Result<Self, CircuitError> {
        let fp_elem = FpElem::new(&cs.witness(var)?, m, two_power_m)?;
        let var0 = cs.create_variable(fp_elem.p.0)?;
        let var1 = cs.create_variable(fp_elem.p.1)?;
        cs.lc_gate(
            &[var0, var1, cs.zero(), cs.zero(), var],
            &[F::one(), fp_elem.two_power_m, F::zero(), F::zero()],
        )?;

        Ok(Self {
            vars: (var0, var1),
            m,
            two_power_m: fp_elem.two_power_m,
        })
    }

    /// Convert into a single variable with value `witness[vars.0] + 2^m *
    /// witness[vars.1]`
    pub fn convert_to_var(&self, cs: &mut PlonkCircuit<F>) -> Result<Variable, CircuitError> {
        cs.lc(
            &[self.vars.0, self.vars.1, cs.zero(), cs.zero()],
            &[F::one(), self.two_power_m, F::zero(), F::zero()],
        )
    }

    /// Create an FpElemVar from field element and split parameter `m`.
    /// This function is built with range-check proofs.
    /// requires lookup table.
    pub fn new_from_field_element(
        cs: &mut PlonkCircuit<F>,
        f: &F,
        m: usize,
        two_power_m: Option<F>,
    ) -> Result<Self, CircuitError> {
        let fp_elem = FpElem::new(f, m, two_power_m)?;
        Self::new_from_fp_elem(cs, &fp_elem, m, two_power_m)
    }

    /// Create an FpElemVar from FpElem form field element .
    /// This function is built with range-check proofs.
    /// requires lookup table.
    pub fn new_from_fp_elem(
        cs: &mut PlonkCircuit<F>,
        fp_elem: &FpElem<F>,
        m: usize,
        two_power_m: Option<F>,
    ) -> Result<Self, CircuitError> {
        let var0 = cs.create_variable(fp_elem.p.0)?;
        let var1 = cs.create_variable(fp_elem.p.1)?;

        cs.range_gate_with_lookup(var0, m)?;
        cs.range_gate_with_lookup(var1, m)?;

        Ok(Self {
            vars: (var0, var1),
            m,
            two_power_m: match two_power_m {
                Some(p) => p,
                None => F::from(2u8).pow([m as u64]),
            },
        })
    }

    /// Get the witness in FpElem form from the variables
    pub fn witness_fp_elem(&self, cs: &PlonkCircuit<F>) -> Result<FpElem<F>, CircuitError> {
        Ok(FpElem {
            p: (cs.witness(self.vars.0)?, cs.witness(self.vars.1)?),
            m: self.m,
            two_power_m: self.two_power_m,
        })
    }

    /// Get the witness from the variables
    pub fn witness(&self, cs: &PlonkCircuit<F>) -> Result<F, CircuitError> {
        Ok(cs.witness(self.vars.0)? + cs.witness(self.vars.1)? * self.two_power_m)
    }

    /// Expose the field element variables components
    pub fn components(&self) -> (Variable, Variable) {
        self.vars
    }

    /// Expose the m parameter
    pub fn param_m(&self) -> usize {
        self.m
    }

    /// Expose 2^m parameter
    pub fn two_power_m(&self) -> F {
        self.two_power_m
    }

    /// An FpElemVar that represents a 0
    pub fn zero(cs: &PlonkCircuit<F>, m: usize, two_power_m: Option<F>) -> Self {
        FpElemVar {
            vars: (cs.zero(), cs.zero()),
            m,
            two_power_m: match two_power_m {
                Some(p) => p,
                None => F::from(2u8).pow([m as u64]),
            },
        }
    }

    /// An FpElemVar that represents a 1
    pub fn one(cs: &PlonkCircuit<F>, m: usize, two_power_m: Option<F>) -> Self {
        FpElemVar {
            vars: (cs.one(), cs.zero()),
            m,
            two_power_m: match two_power_m {
                Some(p) => p,
                None => F::from(2u8).pow([m as u64]),
            },
        }
    }

    /// Enforce self == other.
    pub fn enforce_equal(
        &self,
        circuit: &mut PlonkCircuit<F>,
        other: &Self,
    ) -> Result<(), CircuitError> {
        if self.m != other.m || self.two_power_m != other.two_power_m {
            return Err(CircuitError::ParameterError(
                "m or two_power_m do not match".to_string(),
            ));
        }
        circuit.enforce_equal(self.components().0, other.components().0)?;
        circuit.enforce_equal(self.components().1, other.components().1)
    }
}

impl<F: PrimeField> PlonkCircuit<F> {
    /// Modular arithmetic gates
    ///
    /// Modular addition gate: compute y = var_1 + ... var_k mod p,
    /// where k < range_size / 2, p << field_size / range_size.
    /// Let l_p be the minimal integer such that range_size^l_p >= p,
    /// witness[var_1], ..., witness[var_k] are guaranteed to be in [0,
    /// range_size^l_p). Return error if any variables are invalid.
    fn mod_add_internal(
        &mut self,
        vars: &[Variable],
        p: F,
        l_p: usize,
    ) -> Result<Variable, CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        let range_size = self.range_size()?;
        let mut sum_x = F::zero();
        for &var in vars.iter() {
            sum_x += self.witness(var)?;
        }
        // perform integer division
        let (z, y) = div_rem(&sum_x, &p);
        let z_range = F::from(range_size as u32);
        if z >= z_range {
            return Err(ParameterError(format!(
                "z = {z} is out of range, the sum of variable values = {sum_x} might be too large for modulus = {p}",
            )));
        }

        // add range check gates
        let z_var = self.create_variable(z)?;
        // range check z \in [0, range_size)
        self.range_gate_with_lookup(z_var, range_bit_len)?;
        let y_var = self.create_variable(y)?;
        // range check y \in [0, range_size^l_p)
        self.range_gate_with_lookup(y_var, range_bit_len * l_p)?;

        // add constraint: y = x_1 + ... + x_k - p * z
        let mut padded = vec![z_var];
        padded.extend(vars);
        let rate = GATE_WIDTH - 1; // rate at which lc add each round
        let padded_len = next_multiple(padded.len() - 1, rate)? + 1;
        padded.resize(padded_len, self.zero());

        let coeffs = [F::one(), F::one(), F::one(), F::one()];
        let mut accum = padded[padded_len - 1];
        for i in 1..padded_len / rate {
            accum = self.lc(
                &[
                    accum,
                    padded[padded_len - 1 - rate * i + 2],
                    padded[padded_len - 1 - rate * i + 1],
                    padded[padded_len - 1 - rate * i],
                ],
                &coeffs,
            )?;
        }
        // final round
        let coeffs = [F::one(), F::one(), F::one(), p.neg()];
        let wires = [accum, padded[2], padded[1], padded[0], y_var];
        self.lc_gate(&wires, &coeffs)?;

        Ok(y_var)
    }

    /// Modular addition gate:
    /// Given Fp elements x, y and modulus p, compute z = x + y mod p
    pub fn mod_add(
        &mut self,
        x: &FpElemVar<F>,
        y: &FpElemVar<F>,
        p: &FpElem<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        self.check_var_bound(x.vars.0)?;
        self.check_var_bound(x.vars.1)?;
        self.check_var_bound(y.vars.0)?;
        self.check_var_bound(y.vars.1)?;

        if x.m != p.m || y.m != p.m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.m = {}, y.m = {}, p.m = {}",
                x.m, y.m, p.m
            )));
        }
        if x.two_power_m != p.two_power_m || y.two_power_m != p.two_power_m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.2^m = {}, y.2^m = {}, p.2^m = {}",
                x.two_power_m, y.two_power_m, p.two_power_m
            ))
            );
        }
        if p.m % range_bit_len != 0 {
            return Err(ParameterError(format!(
                "splitting parameter m = {} is not a multiple of range_bit_len",
                p.m
            )));
        }

        let x_var = x.convert_to_var(self)?;
        let y_var = y.convert_to_var(self)?;

        let num_range_blocks = self.num_range_blocks()?;
        let res = self.mod_add_internal(&[x_var, y_var], p.field_elem(), num_range_blocks)?;

        FpElemVar::new_unchecked(self, res, x.m, Some(p.two_power_m))
    }

    /// Modular addition gate:
    /// Given input
    ///  x: Fp element variable,
    ///  y: Fp element, and
    ///  modulus p: Fp element,
    /// use y as a constant and
    /// compute z = x + y mod p
    pub fn mod_add_constant(
        &mut self,
        x: &FpElemVar<F>,
        y: &FpElem<F>,
        p: &FpElem<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        let range_size = self.range_size()?;
        self.check_var_bound(x.vars.0)?;
        self.check_var_bound(x.vars.1)?;

        if x.m != p.m || y.m != p.m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.m = {}, y.m = {}, p.m = {}",
                x.m, y.m, p.m
            )));
        }
        if x.two_power_m != p.two_power_m || y.two_power_m != p.two_power_m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.2^m = {}, y.2^m = {}, p.2^m = {}",
                x.two_power_m, y.two_power_m, p.two_power_m
            ))
            );
        }
        if p.m % range_bit_len != 0 {
            return Err(ParameterError(format!(
                "splitting parameter m = {} is not a multiple of range_bit_len",
                p.m
            )));
        }
        // ==============================================
        // prepare the variables and constants
        // ==============================================
        let x_var = x.convert_to_var(self)?;
        let y_f = y.field_elem();
        let p_f = p.field_elem();

        // perform integer division
        let sum = self.witness(x_var)? + y_f;
        let (divisor, remainder) = div_rem(&sum, &p_f);

        let divisor_range = F::from(range_size as u32);
        if divisor >= divisor_range {
            return Err(ParameterError(format!(
              "divisor = {divisor} is out of range, the sum of variable values = {sum} might be too large for modulus = {p_f}",
          ))
          );
        }

        // ==============================================
        // now we need to prove a quadratic equation
        //   x + y - p * divisor = remainder
        // with the following map
        //  var1: x
        //  var2: remainder
        //  var3: p
        //  var4: divisor
        //  var_output: 0
        //  constant: y
        // ==============================================

        // add range check gates
        let divisor_var = self.create_variable(divisor)?;
        // range check divisor \in [0, range_size)
        self.range_gate_with_lookup(divisor_var, range_bit_len)?;

        // range check remainder \in [0, range_size^l_p)
        let remainder_var = self.create_variable(remainder)?;
        let num_range_blocks = self.num_range_blocks()?;
        self.range_gate_with_lookup(remainder_var, range_bit_len * num_range_blocks)?;

        // add constraint: x - remainder - p * divisor  + y = 0
        let wires = [x_var, remainder_var, divisor_var, self.zero(), self.zero()];
        let q_lc = [F::one(), -F::one(), -p_f, F::zero()];
        let q_mul = [F::zero(), F::zero()];
        let q_o = F::zero();
        let q_c = y_f;

        self.quad_poly_gate(&wires, &q_lc, &q_mul, q_o, q_c)?;

        FpElemVar::new_unchecked(self, remainder_var, x.m, Some(p.two_power_m))
    }

    /// Modular addition gate:
    /// Given Fp elements &\[x\] and modulus p, compute z = \sum x mod p
    pub fn mod_add_vec(
        &mut self,
        x: &[FpElemVar<F>],
        p: &FpElem<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        for e in x {
            if e.m != p.m {
                return Err(ParameterError(format!(
                    "field elements splitting parameters do not match: x.m = {}, p.m = {}",
                    e.m, p.m
                )));
            }

            if e.two_power_m != p.two_power_m {
                return Err(ParameterError(format!(
                    "field elements splitting parameters do not match: x.2^m = {}, p.2^m = {}",
                    e.two_power_m, p.two_power_m
                )));
            }
        }

        if p.m % range_bit_len != 0 {
            return Err(ParameterError(format!(
                "splitting parameter m = {} is not a multiple of range_bit_len",
                p.m
            )));
        }

        let x_vars: Vec<Variable> = x
            .iter()
            .map(|y| y.convert_to_var(self))
            .collect::<Result<Vec<Variable>, _>>()?;

        let num_range_blocks = self.num_range_blocks()?;
        let res = self.mod_add_internal(x_vars.as_ref(), p.field_elem(), num_range_blocks)?;

        FpElemVar::new_unchecked(self, res, p.m, Some(p.two_power_m))
    }

    /// Modular multiplication gate:
    /// Given Fp elements x, y and modulus p, compute z = x * y mod p.
    #[allow(clippy::many_single_char_names)]
    pub fn mod_mul(
        &mut self,
        x: &FpElemVar<F>,
        y: &FpElemVar<F>,
        p: &FpElem<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        if x.m != p.m || y.m != p.m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.m = {}, y.m = {}, p.m = {}",
                x.m, y.m, p.m
            )));
        }
        if x.two_power_m != p.two_power_m || y.two_power_m != p.two_power_m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.2^m = {}, y.2^m = {}, p.2^m = {}",
                x.two_power_m, y.two_power_m, p.two_power_m
            )));
        }
        if p.m % range_bit_len != 0 {
            return Err(ParameterError(format!(
                "splitting parameter m = {} is not a multiple of range_bit_len",
                p.m
            )));
        }

        // Witness computation
        //
        // compute integer values of x, y, and p
        let two_power_m_int: BigUint = to_big_int!(p.two_power_m);
        let x0_int: BigUint = to_big_int!(self.witness(x.vars.0)?);
        let x1_int: BigUint = to_big_int!(self.witness(x.vars.1)?);
        let y0_int: BigUint = to_big_int!(self.witness(y.vars.0)?);
        let y1_int: BigUint = to_big_int!(self.witness(y.vars.1)?);
        let p0_int: BigUint = to_big_int!(p.p.0);
        let p1_int: BigUint = to_big_int!(p.p.1);
        let x_int = &x0_int + &two_power_m_int * &x1_int;
        let y_int = &y0_int + &two_power_m_int * &y1_int;
        let p_int = &p0_int + &two_power_m_int * &p1_int;

        // compute z = x * y mod p, and w s.t. z + w * p = x * y
        let xy_int = &x_int * &y_int;
        let w_int = &xy_int / &p_int;
        let z_int = &xy_int - (&w_int * &p_int);
        let w = FpElem::new(&F::from(w_int), p.m, Some(p.two_power_m))?;
        let w0_int: BigUint = to_big_int!(w.p.0);
        let w1_int: BigUint = to_big_int!(w.p.1);
        let z = FpElem::new(&F::from(z_int), p.m, Some(p.two_power_m))?;
        let z0_int = to_big_int!(z.p.0);
        let z1_int = to_big_int!(z.p.1);

        // now we have the following:
        //      z + w * p = x * y
        // which is
        //             z0 + w0p0 - x0y0                     (0)
        //   + 2^m  *( z1 + w0p1 + w1p0 - x0y1 - x1y0 )     (1)
        //   + 2^2m *( w1p1 - x1y1 )                        (2)
        //   = 0
        //
        // Eq.(0) will generate a carrier c0' that gets added to 2^m term
        // Eq.(1) will generate a carrier c1' that gets added to 2^2m term

        // compute carry values
        //
        // c0' := c0 - 2^m is the carrier for |  z0 + w0p0 - x0y0  |,
        // we define variable c0 rather than c0' because c0 is guaranteed to be positive
        let x0y0_int = &x0_int * &y0_int;
        let z0_plus_p0w0_int = &z0_int + &p0_int * &w0_int;
        let c0_int = if z0_plus_p0w0_int >= x0y0_int {
            let carry0_int = (&z0_plus_p0w0_int - &x0y0_int) / &two_power_m_int;
            &two_power_m_int + carry0_int
        } else {
            let carry0_int = (&x0y0_int - z0_plus_p0w0_int) / &two_power_m_int;
            &two_power_m_int - carry0_int
        };

        // c1' := c1 - 2^{m+1} is the carrier for | z1 + w0p1 + w1p0 - x0y1 - x1y0 + c0|
        // we define variable c1 rather than c1' because c1 is guaranteed to be positive
        let a_int = &x0_int * &y1_int + &x1_int * &y0_int + &two_power_m_int;
        let b_int = &z1_int + &p0_int * &w1_int + &p1_int * &w0_int + &c0_int;
        let c1_int = if b_int >= a_int {
            let carry1_int = (b_int - a_int) / &two_power_m_int;
            &two_power_m_int + &two_power_m_int + carry1_int
        } else {
            let carry1_int = (a_int - b_int) / &two_power_m_int;
            &two_power_m_int + &two_power_m_int - carry1_int
        };

        // with the carriers, we translate
        //      z + w * p = x * y
        // into
        //             z0 + w0p0 - x0y0 - 2^m c0'                        (3)
        //   + 2^m  *( z1 + w0p1 + w1p0 - x0y1 - x1y0 + c0' - 2^m c1' )  (4)
        //   + 2^2m *( w1p1 - x1y1 + c1' )                               (5)
        //   = 0
        // and we are able to choose c0' \in [-2^m, 2^{m+1}], c1' \in [-2^{m+1},
        // 2^{m+2}] so that formulas (3), (4), (5) equal zero respectively.

        // create variables and add range_checks
        let w0_var = self.create_variable(F::from(w0_int))?;
        let w1_var = self.create_variable(F::from(w1_int))?;
        let z0_var = self.create_variable(F::from(z0_int))?;
        let z1_var = self.create_variable(F::from(z1_int))?;
        let c0_var = self.create_variable(F::from(c0_int))?;
        let c1_var = self.create_variable(F::from(c1_int))?;
        self.range_gate_with_lookup(w0_var, p.m)?;
        self.range_gate_with_lookup(w1_var, p.m)?;
        self.range_gate_with_lookup(z0_var, p.m)?;
        self.range_gate_with_lookup(z1_var, p.m)?;
        self.range_gate_with_lookup(c0_var, p.m + range_bit_len)?;
        self.range_gate_with_lookup(c1_var, p.m + range_bit_len)?;

        // add remaining gates
        //
        // ==============================================
        // Eq.(3): z0 + w0p0 - x0y0 - 2^m c0' = 0 where c0' := c0 - 2^m
        // ==============================================
        // x0y0 - p0w0 + 2^m * c0 - 2^{2m} = z0
        let wires = [x.vars.0, y.vars.0, w0_var, c0_var, z0_var];
        let q_lin = [F::zero(), F::zero(), -p.p.0, p.two_power_m];
        let q_mul = [F::one(), F::zero()];
        let q_o = F::one();
        let q_c = -p.two_power_m.square();
        self.quad_poly_gate(&wires, &q_lin, &q_mul, q_o, q_c)?;

        // ==============================================
        // Eq.(4): z1 + w0p1 + w1p0 - x0y1 - x1y0 + c0' - 2^m c1' = 0
        // which is
        //  t1 + 2^m * c1' = z1 + t2 + c0' (4.1)
        // where
        //  t1 = x0y1 + x1y0  (4.2)
        //  t2 = p0w1 + p1w0  (4.3)
        // ==============================================

        // Eq.(4.2): x0y1 + x1y0 = t1
        let wires_in = [x.vars.0, y.vars.1, x.vars.1, y.vars.0];
        let q_mul = [F::one(), F::one()];
        let t1_var = self.mul_add(&wires_in, &q_mul)?;

        // Eq.(4.3): p0w1 + p1w0 = t2
        let wires_in = [w1_var, w0_var, self.zero(), self.zero()];
        let q_lc = [p.p.0, p.p.1, F::zero(), F::zero()];
        let t2_var = self.lc(&wires_in, &q_lc)?;

        // ===============================================
        // Eq.(4.1): t1 + 2^m * c1' = z1 + t2 + c0',
        // where c0' := c0 - 2^m and c1' := c1 - 2^{m+1}
        // ===============================================
        // t1 - t2 - c0 + 2^m * c1 - 2^{2m+1} + 2^m = z1
        let wires = [t1_var, t2_var, c0_var, c1_var, z1_var];
        let q_lin = [F::one(), -F::one(), -F::one(), p.two_power_m];
        let q_mul = [F::zero(), F::zero()];
        let q_o = F::one();
        let q_c = p.two_power_m - p.two_power_m.square().double();
        self.quad_poly_gate(&wires, &q_lin, &q_mul, q_o, q_c)?;

        // ==============================================
        // Eq.(5): w1p1 - x1y1 + c1' = 0 where c1' := c1 - 2^{m+1}
        // ==============================================
        // x1y1 - p1w1 + 2^{m+1} = c1
        let wires = [x.vars.1, y.vars.1, w1_var, self.zero(), c1_var];
        let q_lin = [F::zero(), F::zero(), -p.p.1, F::zero()];
        let q_mul = [F::one(), F::zero()];
        let q_o = F::one();
        let q_c = p.two_power_m.double();
        self.quad_poly_gate(&wires, &q_lin, &q_mul, q_o, q_c)?;

        Ok(FpElemVar {
            vars: (z0_var, z1_var),
            m: p.m,
            two_power_m: p.two_power_m,
        })
    }

    /// Modular multiplication gate:
    /// Given input
    ///  x: Fp element variable,
    ///  y: Fp element, and
    ///  modulus p: Fp element,
    /// use y as a constant
    /// compute z = x * y mod p
    #[allow(clippy::many_single_char_names)]
    pub fn mod_mul_constant(
        &mut self,
        x: &FpElemVar<F>,
        y: &FpElem<F>,
        p: &FpElem<F>,
    ) -> Result<FpElemVar<F>, CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        if x.m != p.m || y.m != p.m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.m = {}, y.m = {}, p.m = {}",
                x.m, y.m, p.m
            )));
        }
        if x.two_power_m != p.two_power_m || y.two_power_m != p.two_power_m {
            return Err(ParameterError(format!(
                "field elements splitting parameters do not match: x.2^m = {}, y.2^m = {}, p.2^m = {}",
                x.two_power_m, y.two_power_m, p.two_power_m
            )));
        }
        if p.m % range_bit_len != 0 {
            return Err(ParameterError(format!(
                "splitting parameter m = {} is not a multiple of range_bit_len",
                p.m
            )));
        }

        // Witness computation
        //
        // compute integer values of x, y, and p
        let two_power_m_int: BigUint = to_big_int!(p.two_power_m);
        let x0_int: BigUint = to_big_int!(self.witness(x.vars.0)?);
        let x1_int: BigUint = to_big_int!(self.witness(x.vars.1)?);
        let y0_int: BigUint = to_big_int!(y.p.0);
        let y1_int: BigUint = to_big_int!(y.p.1);
        let p0_int: BigUint = to_big_int!(p.p.0);
        let p1_int: BigUint = to_big_int!(p.p.1);
        let x_int = &x0_int + &two_power_m_int * &x1_int;
        let y_int = &y0_int + &two_power_m_int * &y1_int;
        let p_int = &p0_int + &two_power_m_int * &p1_int;

        // compute z = x * y mod p, and w s.t. z + w * p = x * y
        let xy_int = &x_int * &y_int;
        let w_int = &xy_int / &p_int;
        let z_int = &xy_int - (&w_int * &p_int);
        let w = FpElem::new(&F::from(w_int), p.m, Some(p.two_power_m))?;
        let w0_int: BigUint = to_big_int!(w.p.0);
        let w1_int: BigUint = to_big_int!(w.p.1);
        let z = FpElem::new(&F::from(z_int), p.m, Some(p.two_power_m))?;
        let z0_int = to_big_int!(z.p.0);
        let z1_int = to_big_int!(z.p.1);

        // now we have the following:
        //      z + w * p = x * y
        // which is
        //             z0 + w0p0 - x0y0                     (0)
        //   + 2^m  *( z1 + w0p1 + w1p0 - x0y1 - x1y0 )     (1)
        //   + 2^2m *( w1p1 - x1y1 )                        (2)
        //   = 0
        //
        // Eq.(0) will generate a carrier c0' that gets added to 2^m term
        // Eq.(1) will generate a carrier c1' that gets added to 2^2m term

        // compute carry values
        //
        // c0' := c0 - 2^m is the carrier for |  z0 + w0p0 - x0y0  |,
        // we define variable c0 rather than c0' because c0 is guaranteed to be positive
        let x0y0_int = &x0_int * &y0_int;
        let z0_plus_p0w0_int = &z0_int + &p0_int * &w0_int;
        let c0_int = if z0_plus_p0w0_int >= x0y0_int {
            let carry0_int = (&z0_plus_p0w0_int - &x0y0_int) / &two_power_m_int;
            &two_power_m_int + carry0_int
        } else {
            let carry0_int = (&x0y0_int - z0_plus_p0w0_int) / &two_power_m_int;
            &two_power_m_int - carry0_int
        };

        // c1' := c1 - 2^{m+1} is the carrier for | z1 + w0p1 + w1p0 - x0y1 - x1y0 + c0|
        // we define variable c1 rather than c1' because c1 is guaranteed to be positive
        let a_int = &x0_int * &y1_int + &x1_int * &y0_int + &two_power_m_int;
        let b_int = &z1_int + &p0_int * &w1_int + &p1_int * &w0_int + &c0_int;
        let c1_int = if b_int >= a_int {
            let carry1_int = (b_int - a_int) / &two_power_m_int;
            &two_power_m_int + &two_power_m_int + carry1_int
        } else {
            let carry1_int = (a_int - b_int) / &two_power_m_int;
            &two_power_m_int + &two_power_m_int - carry1_int
        };

        // with the carriers, we translate
        //      z + w * p = x * y
        // into
        //             z0 + w0p0 - x0y0 - 2^m c0'                        (3)
        //   + 2^m  *( z1 + w0p1 + w1p0 - x0y1 - x1y0 + c0' - 2^m c1' )  (4)
        //   + 2^2m *( w1p1 - x1y1 + c1' )                               (5)
        //   = 0
        // and we are able to choose c0' \in [-2^m, 2^{m+1}], c1' \in [-2^{m+1},
        // 2^{m+2}] so that formulas (3), (4), (5) equal zero respectively.

        // create variables and add range_checks
        let w0_var = self.create_variable(F::from(w0_int))?;
        let w1_var = self.create_variable(F::from(w1_int))?;
        let z0_var = self.create_variable(F::from(z0_int))?;
        let z1_var = self.create_variable(F::from(z1_int))?;
        let c0_var = self.create_variable(F::from(c0_int))?;
        let c1_var = self.create_variable(F::from(c1_int))?;
        self.range_gate_with_lookup(w0_var, p.m)?;
        self.range_gate_with_lookup(w1_var, p.m)?;
        self.range_gate_with_lookup(z0_var, p.m)?;
        self.range_gate_with_lookup(z1_var, p.m)?;
        self.range_gate_with_lookup(c0_var, p.m + range_bit_len)?;
        self.range_gate_with_lookup(c1_var, p.m + range_bit_len)?;

        // add remaining gates
        //
        // ==============================================
        // Eq.(3): z0 + w0p0 - x0y0 - 2^m c0' = 0 where c0' := c0 - 2^m
        // Note: this use same number of constraints as mul_mod
        // ==============================================
        // y0x0 - p0w0 + 2^m * c0 - z0 - 2^{2m} = 0
        let wires = [x.vars.0, w0_var, c0_var, z0_var, self.zero()];
        let q_lin = [y.p.0, -p.p.0, p.two_power_m, -F::one()];
        let q_mul = [F::zero(), F::zero()];
        let q_o = F::zero();
        let q_c = -p.two_power_m.square();
        self.quad_poly_gate(&wires, &q_lin, &q_mul, q_o, q_c)?;

        // ==============================================
        // Eq.(4): z1 + w0p1 + w1p0 - x0y1 - x1y0 + c0' - 2^m c1' = 0
        // which is
        //  t + 2^m * c1' = z1 + c0' (4.1)
        // where
        //  t = x0y1 + x1y0 -  p0w1 - p1w0 (4.2)
        // Note: this use one less constraint than mul_mod
        // ==============================================

        // Eq.(4.2): t = x0y1 + x1y0 - p0w1 - p1w0
        let wires_in = [x.vars.0, x.vars.1, w1_var, w0_var];
        let coeffs = [y.p.1, y.p.0, -p.p.0, -p.p.1];
        let t1_var = self.lc(&wires_in, &coeffs)?;

        // ===============================================
        // Eq.(4.1): t + 2^m * c1' = z1 + c0',
        // where c0' := c0 - 2^m and c1' := c1 - 2^{m+1}
        // ===============================================
        // t - z1 - c0 + 2^m * c1 - 2^{2m+1} + 2^m = 0
        let wires = [t1_var, z1_var, c0_var, c1_var, self.zero()];
        let q_lin = [F::one(), -F::one(), -F::one(), p.two_power_m];
        let q_mul = [F::zero(), F::zero()];
        let q_o = F::zero();
        let q_c = p.two_power_m - p.two_power_m.square().double();
        self.quad_poly_gate(&wires, &q_lin, &q_mul, q_o, q_c)?;

        // ==============================================
        // Eq.(5): w1p1 - x1y1 + c1' = 0 where c1' := c1 - 2^{m+1}
        // ==============================================
        // x1y1 - p1w1 - c1 + 2^{m+1} = 0
        let wires = [x.vars.1, w1_var, c1_var, self.zero(), self.zero()];
        let q_lin = [y.p.1, -p.p.1, -F::one(), F::zero()];
        let q_mul = [F::zero(), F::zero()];
        let q_o = F::zero();
        let q_c = p.two_power_m.double();
        self.quad_poly_gate(&wires, &q_lin, &q_mul, q_o, q_c)?;

        Ok(FpElemVar {
            vars: (z0_var, z1_var),
            m: p.m,
            two_power_m: p.two_power_m,
        })
    }

    /// Negate an FpElemVar mod p where p is a public variable which is
    /// also the modulus for the FpElem element.
    pub fn mod_negate(&mut self, x: &FpElemVar<F>, p: &F) -> Result<FpElemVar<F>, CircuitError> {
        let range_bit_len = self.range_bit_len()?;
        if x.m % range_bit_len != 0 {
            return Err(ParameterError(format!(
                "splitting parameter m = {} is not a multiple of range_bit_len",
                x.m
            )));
        }
        // Witness computation
        let two_power_m_int: BigUint = to_big_int!(x.two_power_m);
        let x0_int: BigUint = to_big_int!(self.witness(x.vars.0)?);
        let x1_int: BigUint = to_big_int!(self.witness(x.vars.1)?);
        let p_int: BigUint = to_big_int!(p);
        let x_int = &x0_int + &two_power_m_int * &x1_int;
        if x_int >= p_int {
            return Err(CircuitError::FieldAlgebraError(
                "non native field overflow".to_string(),
            ));
        }
        let x_negate = F::from(p_int - x_int);

        // variables
        let x_var = x.convert_to_var(self)?;
        let x_neg_var = self.create_variable(x_negate)?;

        let wires = [x_var, x_neg_var, self.one(), self.zero(), self.zero()];
        let coeffs = [F::one(), F::one(), -*p, F::zero()];

        self.lc_gate(&wires, &coeffs)?;

        FpElemVar::new_unchecked(self, x_neg_var, x.m, Some(x.two_power_m))
    }
}

#[inline]
// Integer division: c = a / b
fn int_div<F: PrimeField>(a: &F, b: &F) -> F {
    let c_big_int: BigUint = a.into_bigint().into() / b.into_bigint().into();
    F::from(c_big_int)
}

#[inline]
// Return (a / b, a % b)
fn div_rem<F: PrimeField>(a: &F, b: &F) -> (F, F) {
    let div = int_div(a, b);
    let rem = *a - *b * div;
    (div, rem)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::gadgets::test_utils::test_variable_independence_for_circuit;
    use ark_bls12_377::{Fq as Fq377, Fr as Fr377};
    use ark_ed_on_bls12_377::{Fq as FqEd377, Fr as FrEd377};
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::{Fq as FqEd254, Fr as FrEd254};
    use ark_ff::BigInteger;
    use ark_std::{rand::Rng, vec::Vec};
    use jf_utils::{field_switching, test_rng};

    const RANGE_BIT_LEN_FOR_TEST: usize = 16;
    const RANGE_SIZE_FOR_TEST: usize = 65536;

    #[test]
    fn test_fp_elem() -> Result<(), CircuitError> {
        test_fp_elem_helper::<FqEd254>()?;
        test_fp_elem_helper::<FqEd377>()?;
        test_fp_elem_helper::<FqEd381>()?;
        test_fp_elem_helper::<Fq377>()
    }
    // Test FpElem creation and conversion
    fn test_fp_elem_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut rng = test_rng();
        let p = int_div(&F::rand(&mut rng), &F::from(4u8));

        // case 1: m = len(|F|) / 2
        let m = F::MODULUS_BIT_SIZE as usize / 2;
        let two_power_m = F::from(2u8).pow([m as u64]);
        let fp_elem = FpElem::new(&p, m, Some(two_power_m))?;
        assert!(fp_elem.p.0 < two_power_m, "p0 larger than 2^m");
        assert!(fp_elem.p.1 < two_power_m, "p1 larger than 2^m");
        let q = fp_elem.field_elem();
        assert_eq!(p, q, "FpElem conversion failure");

        // case 2: m = 0
        let fp_elem = FpElem::new(&p, 0, Some(two_power_m))?;
        let q = fp_elem.field_elem();
        assert_eq!(p, q, "FpElem conversion failure when m = 0");

        // case 3: m > len(|F|) / 2
        let m = F::MODULUS_BIT_SIZE as usize / 2 + 1;
        assert!(FpElem::new(&p, m, Some(two_power_m)).is_err());

        Ok(())
    }

    #[test]
    fn test_fp_elem_var() -> Result<(), CircuitError> {
        test_fp_elem_var_helper::<FqEd254>()?;
        test_fp_elem_var_helper::<FqEd377>()?;
        test_fp_elem_var_helper::<FqEd381>()?;
        test_fp_elem_var_helper::<Fq377>()
    }
    // Test FpElemVar variables creation and conversion
    fn test_fp_elem_var_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        let m = F::MODULUS_BIT_SIZE as usize / 2;
        let mut rng = test_rng();

        // Good path
        let p = F::rand(&mut rng);
        let p_var = circuit.create_variable(p)?;
        let fp_elem_var = FpElemVar::new_unchecked(&mut circuit, p_var, m, None)?;
        let q_var = fp_elem_var.convert_to_var(&mut circuit)?;
        circuit.enforce_equal(p_var, q_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Error path
        *circuit.witness_mut(p_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // check that circuit config is independent of witness values
        let p1 = F::rand(&mut rng);
        let p2 = F::rand(&mut rng);
        let circuit_1 = build_fp_elem_var_circuit(p1, m, fp_elem_var.two_power_m)?;
        let circuit_2 = build_fp_elem_var_circuit(p2, m, fp_elem_var.two_power_m)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }
    fn build_fp_elem_var_circuit<F: PrimeField>(
        p: F,
        m: usize,
        two_power_m: F,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(2);
        let p_var = circuit.create_variable(p)?;
        let fp_elem_var = FpElemVar::new_unchecked(&mut circuit, p_var, m, Some(two_power_m))?;
        let _ = fp_elem_var.convert_to_var(&mut circuit)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    // ========================================
    //  mod add internal
    // ========================================

    #[test]
    fn test_mod_add_internal() -> Result<(), CircuitError> {
        test_mod_add_internal_helper::<FqEd254>()?;
        test_mod_add_internal_helper::<FqEd377>()?;
        test_mod_add_internal_helper::<FqEd381>()?;
        test_mod_add_internal_helper::<Fq377>()
    }
    fn test_mod_add_internal_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        // Good paths
        //
        // 1 + ... + 10 mod 17 = 4
        let p = F::from(17u8);
        let vars: Vec<Variable> = (1..=10)
            .map(|i| circuit.create_variable(F::from(i as u8)))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let y_var = circuit.mod_add_internal(&vars, p, 1)?;
        assert_eq!(circuit.witness(y_var)?, F::from(4u8));
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // larger modulus: l_p = 10, p = 2^{160}
        let p = F::from(RANGE_SIZE_FOR_TEST as u32).pow([10u64]);
        let mut rng = test_rng();
        let vars: Vec<Variable> = (0..12)
            .map(|_| {
                circuit.create_variable(
                    int_div(&p, &F::from(2u8)) + F::from(rng.gen_range(0..u64::MAX)),
                )
            })
            .collect::<Result<Vec<_>, CircuitError>>()?;
        let y_var = circuit.mod_add_internal(&vars, p, 10)?;
        // y = x1 + ... + x12 - 6 * p
        let mut expected_y = F::zero();
        for &var in vars.iter() {
            expected_y += circuit.witness(var)?;
        }
        expected_y -= F::from(6u8) * p;
        assert_eq!(circuit.witness(y_var)?, expected_y);
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // Error paths
        //
        // bad output witness
        *circuit.witness_mut(y_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(y_var) = p + F::one();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        *circuit.witness_mut(y_var) = expected_y;
        // input witnesses are larger than the modulus
        let range_size = F::from(RANGE_SIZE_FOR_TEST as u32);
        let bad_x_var = circuit.create_variable(range_size * p)?;
        assert!(circuit
            .mod_add_internal(&[bad_x_var, bad_x_var], p, 10)
            .is_err());

        // check that circuit config is independent of witness values
        let elems1: Vec<F> = (0..3)
            .map(|_| int_div(&p, &F::from(3u8)) + F::from(rng.gen_range(0..u64::MAX)))
            .collect();
        let elems2: Vec<F> = (0..3)
            .map(|_| int_div(&p, &F::from(3u8)) + F::from(rng.gen_range(0..u64::MAX)))
            .collect();
        let circuit_1 = build_mod_add_internal_circuit(&elems1, p, 10)?;
        let circuit_2 = build_mod_add_internal_circuit(&elems2, p, 10)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }
    fn build_mod_add_internal_circuit<F: PrimeField>(
        elems: &[F],
        p: F,
        l_p: usize,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(3);
        let vars: Vec<Variable> = elems
            .iter()
            .map(|&elem| circuit.create_variable(elem))
            .collect::<Result<Vec<_>, CircuitError>>()?;
        circuit.mod_add_internal(&vars, p, l_p)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    // ========================================
    //  mod mul
    // ========================================
    #[test]
    fn test_mod_mul() -> Result<(), CircuitError> {
        test_mod_mul_helper::<FqEd254>()?;
        test_mod_mul_helper::<FqEd377>()?;
        test_mod_mul_helper::<FqEd381>()?;
        test_mod_mul_helper::<Fq377>()
    }
    fn test_mod_mul_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let p = F::from(RANGE_SIZE_FOR_TEST as u32).pow([10u64]);
        let m = 80;
        let p_split = FpElem::new(&p, m, None)?;
        let mut rng = test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        for _ in 0..10 {
            let x_var = circuit.create_variable(p - F::from(rng.gen_range(1..u128::MAX)))?;
            let x_split_vars =
                FpElemVar::new_unchecked(&mut circuit, x_var, m, Some(p_split.two_power_m))?;
            let y_var = circuit.create_variable(p - F::from(rng.gen_range(1..u128::MAX)))?;
            let y_split_vars =
                FpElemVar::new_unchecked(&mut circuit, y_var, m, Some(p_split.two_power_m))?;
            let z_split_vars = circuit.mod_mul(&x_split_vars, &y_split_vars, &p_split)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            // bad witnesses
            *circuit.witness_mut(z_split_vars.vars.1) += F::one();
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= F::one();
            *circuit.witness_mut(z_split_vars.vars.1) += p_split.two_power_m;
            // range check should fail
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= p_split.two_power_m;

            let z_var = z_split_vars.convert_to_var(&mut circuit)?;
            check_mod_mul(
                circuit.witness(z_var)?,
                circuit.witness(x_var)?,
                circuit.witness(y_var)?,
                &p,
            );
        }

        // Other error paths
        //
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        // mismatched splitting parameters
        let zero_var = circuit.zero();
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_mul(&x_split_vars, &y_split_vars, &p_split)
            .is_err());
        // p.m is not a multiple of RANGE_BIT_LEN_FOR_TEST
        let p_split_bad = FpElem::new(&p, m + 1, Some(p_split.two_power_m))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_mul(&x_split_vars, &y_split_vars, &p_split_bad)
            .is_err());

        // p.two_power_m is not  2^m
        let p_split_bad = FpElem::new(&p, m, Some(p_split.two_power_m + F::one()))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        let y_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_mul(&x_split_vars, &y_split_vars, &p_split_bad)
            .is_err());

        // check that circuit config is independent of witness values
        let x1 = p - F::from(rng.gen_range(1..u128::MAX));
        let y1 = p - F::from(rng.gen_range(1..u128::MAX));
        let x2 = p - F::from(rng.gen_range(1..u128::MAX));
        let y2 = p - F::from(rng.gen_range(1..u128::MAX));
        let circuit_1 = build_mod_mul_circuit(&x1, &y1, &p_split)?;
        let circuit_2 = build_mod_mul_circuit(&x2, &y2, &p_split)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }
    fn check_mod_mul<F: PrimeField>(z: F, x: F, y: F, p: &F) {
        let x_int: BigUint = to_big_int!(x);
        let y_int: BigUint = to_big_int!(y);
        let p_int: BigUint = to_big_int!(p);
        let xy_int = &x_int * &y_int;
        let w_int = &xy_int / &p_int;
        let z_int = &xy_int - (&w_int * &p_int);
        let expected_z = F::from(z_int);
        assert_eq!(z, expected_z);
    }
    fn build_mod_mul_circuit<F: PrimeField>(
        x: &F,
        y: &F,
        p: &FpElem<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(5);
        let x_var = circuit.create_variable(*x)?;
        let x_split_vars = FpElemVar::new_unchecked(&mut circuit, x_var, p.m, Some(p.two_power_m))?;
        let y_var = circuit.create_variable(*y)?;
        let y_split_vars = FpElemVar::new_unchecked(&mut circuit, y_var, p.m, Some(p.two_power_m))?;
        circuit.mod_mul(&x_split_vars, &y_split_vars, p)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    // ========================================
    //  mod mul constant
    // ========================================
    #[test]
    fn test_mod_mul_constant() -> Result<(), CircuitError> {
        test_mod_mul_constant_helper::<FqEd254>()?;
        test_mod_mul_constant_helper::<FqEd377>()?;
        test_mod_mul_constant_helper::<FqEd381>()?;
        test_mod_mul_constant_helper::<Fq377>()
    }
    fn test_mod_mul_constant_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let p = F::from(RANGE_SIZE_FOR_TEST as u32).pow([10u64]);
        let m = 80;
        let p_split = FpElem::new(&p, m, None)?;
        let mut rng = test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        for _ in 0..10 {
            let x_var = circuit.create_variable(p - F::from(rng.gen_range(1..u128::MAX)))?;
            let x_split_vars =
                FpElemVar::new_unchecked(&mut circuit, x_var, m, Some(p_split.two_power_m))?;
            let y = p - F::from(rng.gen_range(1..u128::MAX));
            let y_split = FpElem::new(&y, m, Some(p_split.two_power_m))?;
            let z_split_vars = circuit.mod_mul_constant(&x_split_vars, &y_split, &p_split)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            // bad witnesses
            *circuit.witness_mut(z_split_vars.vars.1) += F::one();
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= F::one();
            *circuit.witness_mut(z_split_vars.vars.1) += p_split.two_power_m;
            // range check should fail
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= p_split.two_power_m;

            let z_var = z_split_vars.convert_to_var(&mut circuit)?;
            check_mod_mul(circuit.witness(z_var)?, circuit.witness(x_var)?, y, &p);
        }

        // Other error paths
        //
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        // mismatched splitting parameters
        let zero_var = circuit.zero();
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y = p - F::from(rng.gen_range(1..u128::MAX));
        let y_split = FpElem::new(&y, m, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_mul_constant(&x_split_vars, &y_split, &p_split)
            .is_err());
        // p.m is not a multiple of RANGE_BIT_LEN_FOR_TEST
        let p_split_bad = FpElem::new(&p, m + 1, Some(p_split.two_power_m))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y = p - F::from(rng.gen_range(1..u128::MAX));
        let y_split = FpElem::new(&y, m + 1, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_mul_constant(&x_split_vars, &y_split, &p_split_bad)
            .is_err());

        // p.two_power_m is not  2^m
        let p_split_bad = FpElem::new(&p, m, Some(p_split.two_power_m + F::one()))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        let y = p - F::from(rng.gen_range(1..u128::MAX));
        let y_split = FpElem::new(&y, m, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_mul_constant(&x_split_vars, &y_split, &p_split_bad)
            .is_err());

        // check that circuit config is independent of witness values
        let x1 = p - F::from(rng.gen_range(1..u128::MAX));
        let y1 = p - F::from(rng.gen_range(1..u128::MAX));
        let x2 = p - F::from(rng.gen_range(1..u128::MAX));
        let y2 = p - F::from(rng.gen_range(1..u128::MAX));
        let circuit_1 = build_mod_mul_constant_circuit(&x1, &y1, &p_split)?;
        let circuit_2 = build_mod_mul_constant_circuit(&x2, &y2, &p_split)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }
    fn build_mod_mul_constant_circuit<F: PrimeField>(
        x: &F,
        y: &F,
        p: &FpElem<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(5);
        let x_var = circuit.create_variable(*x)?;
        let x_split_vars = FpElemVar::new_unchecked(&mut circuit, x_var, p.m, Some(p.two_power_m))?;
        let y_split = FpElem::new(y, p.m, Some(p.two_power_m))?;
        circuit.mod_mul_constant(&x_split_vars, &y_split, p)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    // ========================================
    //  mod add
    // ========================================
    #[test]
    fn test_mod_add() -> Result<(), CircuitError> {
        test_mod_add_helper::<FqEd254>()?;
        test_mod_add_helper::<FqEd377>()?;
        test_mod_add_helper::<FqEd381>()?;
        test_mod_add_helper::<Fq377>()
    }
    fn test_mod_add_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let p = F::from(RANGE_SIZE_FOR_TEST as u32).pow([10u64]);
        let m = 80;
        let p_split = FpElem::new(&p, m, None)?;
        let mut rng = test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        for _ in 0..10 {
            let x_var = circuit.create_variable(p - F::from(rng.gen_range(1..u128::MAX)))?;
            let x_split_vars =
                FpElemVar::new_unchecked(&mut circuit, x_var, m, Some(p_split.two_power_m))?;
            let y_var = circuit.create_variable(p - F::from(rng.gen_range(1..u128::MAX)))?;
            let y_split_vars =
                FpElemVar::new_unchecked(&mut circuit, y_var, m, Some(p_split.two_power_m))?;
            let z_split_vars = circuit.mod_add(&x_split_vars, &y_split_vars, &p_split)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            // bad witnesses
            *circuit.witness_mut(z_split_vars.vars.1) += F::one();
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= F::one();
            *circuit.witness_mut(z_split_vars.vars.1) += p_split.two_power_m;
            // range check should fail
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= p_split.two_power_m;

            let z_var = z_split_vars.convert_to_var(&mut circuit)?;
            check_mod_add(
                circuit.witness(z_var)?,
                circuit.witness(x_var)?,
                circuit.witness(y_var)?,
                &p,
            );
        }

        // Other error paths
        //
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        // mismatched splitting parameters
        let zero_var = circuit.zero();
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_add(&x_split_vars, &y_split_vars, &p_split)
            .is_err());
        // p.m is not a multiple of RANGE_BIT_LEN_FOR_TEST
        let p_split_bad = FpElem::new(&p, m + 1, Some(p_split.two_power_m))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_add(&x_split_vars, &y_split_vars, &p_split_bad)
            .is_err());
        // p.two_power_m is not 2^m
        let p_split_bad = FpElem::new(&p, m, Some(p_split.two_power_m + F::one()))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        let y_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        assert!(circuit
            .mod_add(&x_split_vars, &y_split_vars, &p_split_bad)
            .is_err());

        // check that circuit config is independent of witness values
        let x1 = p - F::from(rng.gen_range(1..u128::MAX));
        let y1 = p - F::from(rng.gen_range(1..u128::MAX));
        let x2 = p - F::from(rng.gen_range(1..u128::MAX));
        let y2 = p - F::from(rng.gen_range(1..u128::MAX));
        let circuit_1 = build_mod_add_circuit(&x1, &y1, &p_split)?;
        let circuit_2 = build_mod_add_circuit(&x2, &y2, &p_split)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }
    fn check_mod_add<F: PrimeField>(z: F, x: F, y: F, p: &F) {
        let x_int: BigUint = to_big_int!(x);
        let y_int: BigUint = to_big_int!(y);
        let p_int: BigUint = to_big_int!(p);
        let xy_int = &x_int + &y_int;
        let w_int = &xy_int / &p_int;
        let z_int = &xy_int - (&w_int * &p_int);
        let expected_z = F::from(z_int);
        assert_eq!(z, expected_z);
    }
    fn build_mod_add_circuit<F: PrimeField>(
        x: &F,
        y: &F,
        p: &FpElem<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(5);
        let x_var = circuit.create_variable(*x)?;
        let x_split_vars = FpElemVar::new_unchecked(&mut circuit, x_var, p.m, Some(p.two_power_m))?;
        let y_var = circuit.create_variable(*y)?;
        let y_split_vars = FpElemVar::new_unchecked(&mut circuit, y_var, p.m, Some(p.two_power_m))?;
        circuit.mod_add(&x_split_vars, &y_split_vars, p)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    // ========================================
    //  mod add constant
    // ========================================
    #[test]
    fn test_mod_add_constant() -> Result<(), CircuitError> {
        test_mod_add_constant_helper::<FqEd254>()?;
        test_mod_add_constant_helper::<FqEd377>()?;
        test_mod_add_constant_helper::<FqEd381>()?;
        test_mod_add_constant_helper::<Fq377>()
    }
    fn test_mod_add_constant_helper<F: PrimeField>() -> Result<(), CircuitError> {
        let p = F::from(RANGE_SIZE_FOR_TEST as u32).pow([10u64]);
        let m = 80;
        let p_split = FpElem::new(&p, m, None)?;
        let mut rng = test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);

        // set up a test where a mod p will happen
        {
            let x = p - F::one();
            let y = F::from(2u8);

            let x_var = circuit.create_variable(x)?;
            let x_split_vars =
                FpElemVar::new_unchecked(&mut circuit, x_var, m, Some(p_split.two_power_m))?;
            let y_split = FpElem::new(&y, m, Some(p_split.two_power_m))?;

            let z_split_vars = circuit.mod_add_constant(&x_split_vars, &y_split, &p_split)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            // bad witnesses
            *circuit.witness_mut(z_split_vars.vars.1) += F::one();
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= F::one();
            *circuit.witness_mut(z_split_vars.vars.1) += p_split.two_power_m;
            // range check should fail
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= p_split.two_power_m;

            let z_var = z_split_vars.convert_to_var(&mut circuit)?;

            check_mod_add_constant(circuit.witness(z_var)?, circuit.witness(x_var)?, y, &p);
        }

        // random tests
        for _ in 0..10 {
            let x_var = circuit.create_variable(p - F::from(rng.gen_range(1..u128::MAX)))?;
            let x_split_vars =
                FpElemVar::new_unchecked(&mut circuit, x_var, m, Some(p_split.two_power_m))?;
            let y = p - F::from(rng.gen_range(1..u128::MAX));
            let y_split = FpElem::new(&y, m, Some(p_split.two_power_m))?;

            let z_split_vars = circuit.mod_add_constant(&x_split_vars, &y_split, &p_split)?;
            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            // bad witnesses
            *circuit.witness_mut(z_split_vars.vars.1) += F::one();
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= F::one();
            *circuit.witness_mut(z_split_vars.vars.1) += p_split.two_power_m;
            // range check should fail
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(z_split_vars.vars.1) -= p_split.two_power_m;

            let z_var = z_split_vars.convert_to_var(&mut circuit)?;
            check_mod_add_constant(circuit.witness(z_var)?, circuit.witness(x_var)?, y, &p);
        }

        // Other error paths
        //
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST);
        // mismatched splitting parameters
        let zero_var = circuit.zero();
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y_split = FpElem::new(
            &(p - F::from(rng.gen_range(1..u128::MAX))),
            m,
            Some(p_split.two_power_m),
        )?;

        assert!(circuit
            .mod_add_constant(&x_split_vars, &y_split, &p_split)
            .is_err());
        // p.m is not a multiple of RANGE_BIT_LEN_FOR_TEST
        let p_split_bad = FpElem::new(&p, m + 1, Some(p_split.two_power_m))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m + 1, Some(p_split.two_power_m))?;
        let y_split = FpElem::new(
            &(p - F::from(rng.gen_range(1..u128::MAX))),
            m + 1,
            Some(p_split.two_power_m),
        )?;
        assert!(circuit
            .mod_add_constant(&x_split_vars, &y_split, &p_split_bad)
            .is_err());
        // p.two_power_m is not 2^m
        let p_split_bad = FpElem::new(&p, m, Some(p_split.two_power_m + F::one()))?;
        let x_split_vars =
            FpElemVar::new_unchecked(&mut circuit, zero_var, m, Some(p_split.two_power_m))?;
        let y_split = FpElem::new(
            &(p - F::from(rng.gen_range(1..u128::MAX))),
            m,
            Some(p_split.two_power_m),
        )?;
        assert!(circuit
            .mod_add_constant(&x_split_vars, &y_split, &p_split_bad)
            .is_err());

        // check that circuit config is independent of witness values
        let x1 = p - F::from(rng.gen_range(1..u128::MAX));
        let y1 = p - F::from(rng.gen_range(1..u128::MAX));
        let x2 = p - F::from(rng.gen_range(1..u128::MAX));
        let y2 = p - F::from(rng.gen_range(1..u128::MAX));
        let circuit_1 = build_mod_add_constant_circuit(&x1, &y1, &p_split)?;
        let circuit_2 = build_mod_add_constant_circuit(&x2, &y2, &p_split)?;
        test_variable_independence_for_circuit::<F>(circuit_1, circuit_2)?;

        Ok(())
    }
    fn check_mod_add_constant<F: PrimeField>(z: F, x: F, y: F, p: &F) {
        let x_int: BigUint = to_big_int!(x);
        let y_int: BigUint = to_big_int!(y);
        let p_int: BigUint = to_big_int!(p);
        let xy_int = &x_int + &y_int;
        let w_int = &xy_int / &p_int;
        let z_int = &xy_int - (&w_int * &p_int);
        let expected_z = F::from(z_int);
        assert_eq!(z, expected_z);
    }
    fn build_mod_add_constant_circuit<F: PrimeField>(
        x: &F,
        y: &F,
        p: &FpElem<F>,
    ) -> Result<PlonkCircuit<F>, CircuitError> {
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(5);
        let x_var = circuit.create_variable(*x)?;
        let x_split_vars = FpElemVar::new_unchecked(&mut circuit, x_var, p.m, Some(p.two_power_m))?;
        let y_split = FpElem::new(y, p.m, Some(p.two_power_m))?;
        circuit.mod_add_constant(&x_split_vars, &y_split, p)?;
        circuit.finalize_for_arithmetization()?;
        Ok(circuit)
    }

    // ========================================
    //  mod negation
    // ========================================
    #[test]
    fn test_mod_negation() -> Result<(), CircuitError> {
        test_mod_negation_helper::<FqEd254, FrEd254>(126, 9)?;
        test_mod_negation_helper::<FqEd377, FrEd377>(126, 9)?;
        test_mod_negation_helper::<Fq377, Fr377>(128, 16)

        // cannot test for the following set up since 127 is a prime
        // test_mod_negation_helper::<FqEd381, FrEd381>(127, xx)?;
    }
    fn test_mod_negation_helper<F: PrimeField, T: PrimeField>(
        m: usize,
        range_bit_len: usize,
    ) -> Result<(), CircuitError> {
        let p = F::from_le_bytes_mod_order(T::MODULUS.to_bytes_le().as_ref());
        let p_split = FpElem::new(&p, m, None)?;
        let mut rng = test_rng();
        let mut circuit: PlonkCircuit<F> = PlonkCircuit::new_ultra_plonk(range_bit_len);

        for _ in 0..10 {
            let x = T::rand(&mut rng);
            let x_var = circuit.create_variable(field_switching(&x))?;
            let x_split_vars =
                FpElemVar::new_unchecked(&mut circuit, x_var, m, Some(p_split.two_power_m))?;

            let y_split_vars = circuit.mod_negate(&x_split_vars, &p)?;

            assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

            // bad witnesses
            *circuit.witness_mut(y_split_vars.vars.1) += F::one();
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(y_split_vars.vars.1) -= F::one();
            *circuit.witness_mut(y_split_vars.vars.1) += p_split.two_power_m;

            // range check should fail
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            *circuit.witness_mut(y_split_vars.vars.1) -= p_split.two_power_m;

            let y_var = y_split_vars.convert_to_var(&mut circuit)?;
            let y = circuit.witness(y_var)?;
            assert_eq!(T::zero(), x + field_switching::<_, T>(&y))
        }

        Ok(())
    }
}
