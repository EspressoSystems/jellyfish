// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements multi-scalar-multiplication circuits.

use super::{Point, PointVariable};
use crate::{errors::CircuitError, Circuit, PlonkCircuit, Variable};
use ark_ec::{
    twisted_edwards::{Projective, TECurveConfig as Config},
    CurveConfig,
};
use ark_ff::{BigInteger, PrimeField};
use ark_std::{format, vec, vec::Vec};
use jf_utils::fq_to_fr;

/// Compute the multi-scalar-multiplications in circuit.
pub trait MultiScalarMultiplicationCircuit<F, P>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    /// Compute the multi-scalar-multiplications.
    /// Use pippenger when the circuit supports lookup;
    /// Use naive method otherwise.
    /// Return error if the number bases does not match the number of scalars.
    fn msm(
        &mut self,
        bases: &[PointVariable],
        scalars: &[Variable],
    ) -> Result<PointVariable, CircuitError>;

    /// Compute the multi-scalar-multiplications where each scalar has at most
    /// `scalar_bit_length` bits.
    fn msm_with_var_scalar_length(
        &mut self,
        bases: &[PointVariable],
        scalars: &[Variable],
        scalar_bit_length: usize,
    ) -> Result<PointVariable, CircuitError>;
}

impl<F, P> MultiScalarMultiplicationCircuit<F, P> for PlonkCircuit<F>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    fn msm(
        &mut self,
        bases: &[PointVariable],
        scalars: &[Variable],
    ) -> Result<PointVariable, CircuitError> {
        let scalar_bit_length = <P as CurveConfig>::ScalarField::MODULUS_BIT_SIZE as usize;
        MultiScalarMultiplicationCircuit::<F, P>::msm_with_var_scalar_length(
            self,
            bases,
            scalars,
            scalar_bit_length,
        )
    }

    fn msm_with_var_scalar_length(
        &mut self,
        bases: &[PointVariable],
        scalars: &[Variable],
        scalar_bit_length: usize,
    ) -> Result<PointVariable, CircuitError> {
        if bases.len() != scalars.len() {
            return Err(CircuitError::ParameterError(format!(
                "bases length ({}) does not match scalar length ({})",
                bases.len(),
                scalars.len()
            )));
        }

        if self.support_lookup() {
            msm_pippenger::<F, P>(self, bases, scalars, scalar_bit_length)
        } else {
            msm_naive::<F, P>(self, bases, scalars, scalar_bit_length)
        }
    }
}

// A naive way to implement msm by computing them individually.
// Used for double checking the correctness; also as a fall-back solution
// to Pippenger.
//
// Some typical result on BW6-761 curve is shown below (i.e. the circuit
// simulates BLS12-377 curve operations). More results are available in the test
// function.
//
// number of basis: 1
// #variables: 1867
// #constraints: 1865
//
// number of basis: 2
// #variables: 3734
// #constraints: 3730
//
// number of basis: 4
// #variables: 7468
// #constraints: 7460
//
// number of basis: 8
// #variables: 14936
// #constraints: 14920
//
// number of basis: 16
// #variables: 29872
// #constraints: 29840
//
// number of basis: 32
// #variables: 59744
// #constraints: 59680
//
// number of basis: 64
// #variables: 119488
// #constraints: 119360
//
// number of basis: 128
// #variables: 238976
// #constraints: 238720
fn msm_naive<F, P>(
    circuit: &mut PlonkCircuit<F>,
    bases: &[PointVariable],
    scalars: &[Variable],
    scalar_bit_length: usize,
) -> Result<PointVariable, CircuitError>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    circuit.check_vars_bound(scalars)?;
    for base in bases.iter() {
        circuit.check_point_var_bound(base)?;
    }

    let scalar_0_bits_le = circuit.unpack(scalars[0], scalar_bit_length)?;
    let mut res = circuit.variable_base_binary_scalar_mul::<P>(&scalar_0_bits_le, &bases[0])?;

    for (base, scalar) in bases.iter().zip(scalars.iter()).skip(1) {
        let scalar_bits_le = circuit.unpack(*scalar, scalar_bit_length)?;
        let tmp = circuit.variable_base_binary_scalar_mul::<P>(&scalar_bits_le, base)?;
        res = circuit.ecc_add::<P>(&res, &tmp)?;
    }

    Ok(res)
}

// A variant of Pippenger MSM.
//
// Some typical result on BW6-761 curve is shown below (i.e. the circuit
// simulates BLS12-377 curve operations). More results are available in the test
// function.
//
// number of basis: 1
// #variables: 887
// #constraints: 783
//
// number of basis: 2
// #variables: 1272
// #constraints: 1064
//
// number of basis: 4
// #variables: 2042
// #constraints: 1626
//
// number of basis: 8
// #variables: 3582
// #constraints: 2750
//
// number of basis: 16
// #variables: 6662
// #constraints: 4998
//
// number of basis: 32
// #variables: 12822
// #constraints: 9494
//
// number of basis: 64
// #variables: 25142
// #constraints: 18486
//
// number of basis: 128
// #variables: 49782
// #constraints: 36470
fn msm_pippenger<F, P>(
    circuit: &mut PlonkCircuit<F>,
    bases: &[PointVariable],
    scalars: &[Variable],
    scalar_bit_length: usize,
) -> Result<PointVariable, CircuitError>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    // ================================================
    // check inputs
    // ================================================
    for (&scalar, base) in scalars.iter().zip(bases.iter()) {
        circuit.check_var_bound(scalar)?;
        circuit.check_point_var_bound(base)?;
    }

    // ================================================
    // set up parameters
    // ================================================
    let c = if scalar_bit_length < 32 {
        3
    } else {
        ln_without_floats(scalar_bit_length)
    };

    // ================================================
    // compute lookup tables and window sums
    // ================================================
    let point_zero_var = circuit.neutral_point_variable();
    // Each window is of size `c`.
    // We divide up the bits 0..scalar_bit_length into windows of size `c`, and
    // in parallel process each such window.
    let mut window_sums = Vec::new();
    for (base_var, &scalar_var) in bases.iter().zip(scalars.iter()) {
        // decompose scalar into c-bit scalars
        let decomposed_scalar_vars =
            decompose_scalar_var(circuit, scalar_var, c, scalar_bit_length)?;

        // create point table [0 * base, 1 * base, ..., (2^c-1) * base]
        let mut table_point_vars = vec![point_zero_var, *base_var];
        for _ in 0..((1 << c) - 2) {
            let point_var = circuit.ecc_add::<P>(base_var, table_point_vars.last().unwrap())?;
            table_point_vars.push(point_var);
        }

        // create lookup point variables
        let mut lookup_point_vars = Vec::new();
        for &scalar_var in decomposed_scalar_vars.iter() {
            let lookup_point = compute_scalar_mul_value::<F, P>(circuit, scalar_var, base_var)?;
            let lookup_point_var = circuit.create_point_variable(lookup_point)?;
            lookup_point_vars.push(lookup_point_var);
        }

        create_point_lookup_gates(
            circuit,
            &table_point_vars,
            &decomposed_scalar_vars,
            &lookup_point_vars,
        )?;

        // update window sums
        if window_sums.is_empty() {
            window_sums = lookup_point_vars;
        } else {
            for (window_sum_mut, lookup_point_var) in
                window_sums.iter_mut().zip(lookup_point_vars.iter())
            {
                *window_sum_mut = circuit.ecc_add::<P>(window_sum_mut, lookup_point_var)?;
            }
        }
    }

    // ================================================
    // performing additions
    // ================================================
    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();

    // We're traversing windows from high to low.
    let b = &window_sums[1..]
        .iter()
        .rev()
        .fold(point_zero_var, |mut total, sum_i| {
            // total += sum_i
            total = circuit.ecc_add::<P>(&total, sum_i).unwrap();
            for _ in 0..c {
                // double
                total = circuit.ecc_add::<P>(&total, &total).unwrap();
            }
            total
        });
    circuit.ecc_add::<P>(&lowest, b)
}

#[inline]
fn create_point_lookup_gates<F>(
    circuit: &mut PlonkCircuit<F>,
    table_point_vars: &[PointVariable],
    lookup_scalar_vars: &[Variable],
    lookup_point_vars: &[PointVariable],
) -> Result<(), CircuitError>
where
    F: PrimeField,
{
    let table_vars: Vec<(Variable, Variable)> = table_point_vars
        .iter()
        .map(|p| (p.get_x(), p.get_y()))
        .collect();
    let lookup_vars: Vec<(Variable, Variable, Variable)> = lookup_scalar_vars
        .iter()
        .zip(lookup_point_vars.iter())
        .map(|(&s, pt)| (s, pt.get_x(), pt.get_y()))
        .collect();
    circuit.create_table_and_lookup_variables(&lookup_vars, &table_vars)
}

#[inline]
/// Decompose a `scalar_bit_length`-bit scalar `s` into many c-bit scalar
/// variables `{s0, ..., s_m}` such that `s = \sum_{j=0..m} 2^{cj} * s_j`
fn decompose_scalar_var<F>(
    circuit: &mut PlonkCircuit<F>,
    scalar_var: Variable,
    c: usize,
    scalar_bit_length: usize,
) -> Result<Vec<Variable>, CircuitError>
where
    F: PrimeField,
{
    // create witness
    let m = (scalar_bit_length - 1) / c + 1;
    let mut scalar_val = circuit.witness(scalar_var)?.into_bigint();
    let decomposed_scalar_vars = (0..m)
        .map(|_| {
            // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
            let scalar_u64 = scalar_val.as_ref()[0] % (1 << c);
            // We right-shift by c bits, thus getting rid of the
            // lower bits.
            scalar_val.divn(c as u32);
            circuit.create_variable(F::from(scalar_u64))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // create circuit
    let range_size = F::from((1 << c) as u32);
    circuit.decomposition_gate(decomposed_scalar_vars.clone(), scalar_var, range_size)?;

    Ok(decomposed_scalar_vars)
}

#[inline]
/// Compute the value of scalar multiplication `witness(scalar_var) *
/// witness(base_var)`. This function does not add any constraints.
fn compute_scalar_mul_value<F, P>(
    circuit: &PlonkCircuit<F>,
    scalar_var: Variable,
    base_var: &PointVariable,
) -> Result<Point<F>, CircuitError>
where
    F: PrimeField,
    P: Config<BaseField = F>,
{
    let curve_point: Projective<P> = circuit.point_witness(base_var)?.into();
    let scalar = fq_to_fr::<F, P>(&circuit.witness(scalar_var)?);
    let res = curve_point * scalar;
    Ok(res.into())
}

/// The result of this function is only approximately `ln(a)`
/// [`Explanation of usage`]
///
/// [`Explanation of usage`]: https://github.com/scipr-lab/zexe/issues/79#issue-556220473
fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)
    (ark_std::log2(a) * 69 / 100) as usize
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{gadgets::ecc::Point, Circuit, PlonkType};
    use ark_bls12_377::{g1::Config as Param377, Fq as Fq377};
    use ark_ec::{
        scalar_mul::variable_base::VariableBaseMSM,
        twisted_edwards::{Affine, TECurveConfig as Config},
    };
    use ark_ed_on_bls12_377::{EdwardsConfig as ParamEd377, Fq as FqEd377};
    use ark_ed_on_bls12_381::{EdwardsConfig as ParamEd381, Fq as FqEd381};
    use ark_ed_on_bn254::{EdwardsConfig as ParamEd254, Fq as FqEd254};
    use ark_ff::UniformRand;
    use ark_std::vec::Vec;
    use jf_utils::fr_to_fq;

    const RANGE_BIT_LEN_FOR_TEST: usize = 8;

    #[test]
    fn test_variable_base_multi_scalar_mul() -> Result<(), CircuitError> {
        test_variable_base_multi_scalar_mul_helper::<FqEd254, ParamEd254>(PlonkType::TurboPlonk)?;
        test_variable_base_multi_scalar_mul_helper::<FqEd254, ParamEd254>(PlonkType::UltraPlonk)?;
        test_variable_base_multi_scalar_mul_helper::<FqEd377, ParamEd377>(PlonkType::TurboPlonk)?;
        test_variable_base_multi_scalar_mul_helper::<FqEd377, ParamEd377>(PlonkType::UltraPlonk)?;
        test_variable_base_multi_scalar_mul_helper::<FqEd381, ParamEd381>(PlonkType::TurboPlonk)?;
        test_variable_base_multi_scalar_mul_helper::<FqEd381, ParamEd381>(PlonkType::UltraPlonk)?;
        test_variable_base_multi_scalar_mul_helper::<Fq377, Param377>(PlonkType::TurboPlonk)?;
        test_variable_base_multi_scalar_mul_helper::<Fq377, Param377>(PlonkType::UltraPlonk)?;

        // // uncomment the following code to dump the circuit comparison to screen
        // assert!(false);

        Ok(())
    }

    fn test_variable_base_multi_scalar_mul_helper<F, P>(
        plonk_type: PlonkType,
    ) -> Result<(), CircuitError>
    where
        F: PrimeField,
        P: Config<BaseField = F>,
    {
        let mut rng = jf_utils::test_rng();

        for dim in [1, 2, 4, 8, 16, 32, 64, 128] {
            let mut circuit: PlonkCircuit<F> = match plonk_type {
                PlonkType::TurboPlonk => PlonkCircuit::new_turbo_plonk(),
                PlonkType::UltraPlonk => PlonkCircuit::new_ultra_plonk(RANGE_BIT_LEN_FOR_TEST),
            };

            // bases and scalars
            let bases: Vec<Affine<P>> = (0..dim).map(|_| Affine::<P>::rand(&mut rng)).collect();
            let scalars: Vec<P::ScalarField> =
                (0..dim).map(|_| P::ScalarField::rand(&mut rng)).collect();
            let scalar_reprs: Vec<<P::ScalarField as PrimeField>::BigInt> =
                scalars.iter().map(|x| x.into_bigint()).collect();
            let res = Projective::<P>::msm_bigint(&bases, &scalar_reprs);
            let res_point: Point<F> = res.into();

            // corresponding wires
            let bases_point: Vec<Point<F>> = bases.iter().map(|x| (*x).into()).collect();
            let bases_vars: Vec<PointVariable> = bases_point
                .iter()
                .map(|x| circuit.create_point_variable(*x))
                .collect::<Result<Vec<_>, _>>()?;
            let scalar_vars: Vec<Variable> = scalars
                .iter()
                .map(|x| circuit.create_variable(fr_to_fq::<F, P>(x)))
                .collect::<Result<Vec<_>, _>>()?;

            // compute circuit
            let res_var = MultiScalarMultiplicationCircuit::<F, P>::msm(
                &mut circuit,
                &bases_vars,
                &scalar_vars,
            )?;

            assert_eq!(circuit.point_witness(&res_var)?, res_point);

            // // uncomment the following code to dump the circuit comparison to screen
            // ark_std::println!("number of basis: {}", dim);
            // ark_std::println!("#variables: {}", circuit.num_vars(),);
            // ark_std::println!("#constraints: {}\n", circuit.num_gates(),);

            // wrong witness should fail
            *circuit.witness_mut(2) = F::rand(&mut rng);
            assert!(circuit.check_circuit_satisfiability(&[]).is_err());
            // un-matching basis & scalars
            assert!(MultiScalarMultiplicationCircuit::<F, P>::msm(
                &mut circuit,
                &bases_vars[0..dim - 1],
                &scalar_vars
            )
            .is_err());

            // Check variable out of bound error.
            let var_number = circuit.num_vars();
            assert!(MultiScalarMultiplicationCircuit::<F, P>::msm(
                &mut circuit,
                &[PointVariable(var_number, var_number)],
                &scalar_vars
            )
            .is_err());
            assert!(MultiScalarMultiplicationCircuit::<F, P>::msm(
                &mut circuit,
                &bases_vars,
                &[var_number]
            )
            .is_err());
        }
        Ok(())
    }
}
