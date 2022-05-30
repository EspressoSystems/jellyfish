// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements multi-scalar-multiplication circuits.

use super::PointVariable;
use crate::{
    circuit::{PlonkCircuit, Variable},
    errors::PlonkError,
};
use ark_ec::{ModelParameters, TEModelParameters as Parameters};
use ark_ff::PrimeField;
use ark_std::format;

/// Compute the multi-scalar-multiplications in circuit.
pub trait MultiScalarMultiplicationCircuit<F, P>
where
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
{
    /// Compute the multi-scalar-multiplications.
    /// Use pippenger when the circuit supports lookup;
    /// Use naive method otherwise.
    /// Return error if the number bases does not match the number of scalars.
    fn msm(
        &mut self,
        bases: &[PointVariable],
        scalars: &[Variable],
    ) -> Result<PointVariable, PlonkError>;

    /// Compute the multi-scalar-multiplications where each scalar has at most
    /// `scalar_bit_length` bits.
    fn msm_with_var_scalar_length(
        &mut self,
        bases: &[PointVariable],
        scalars: &[Variable],
        scalar_bit_length: usize,
    ) -> Result<PointVariable, PlonkError>;
}

impl<F, P> MultiScalarMultiplicationCircuit<F, P> for PlonkCircuit<F>
where
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
{
    fn msm(
        &mut self,
        bases: &[PointVariable],
        scalars: &[Variable],
    ) -> Result<PointVariable, PlonkError> {
        let scalar_bit_length = <P as ModelParameters>::ScalarField::size_in_bits();
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
    ) -> Result<PointVariable, PlonkError> {
        if bases.len() != scalars.len() {
            return Err(PlonkError::InvalidParameters(format!(
                "bases length ({}) does not match scalar length ({})",
                bases.len(),
                scalars.len()
            )));
        }

        msm_naive::<F, P>(self, bases, scalars, scalar_bit_length)
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
) -> Result<PointVariable, PlonkError>
where
    F: PrimeField,
    P: Parameters<BaseField = F> + Clone,
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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::circuit::{customized::ecc::Point, Circuit};
    use ark_bls12_377::{g1::Parameters as Param377, Fq as Fq377};
    use ark_ec::{
        msm::VariableBaseMSM, twisted_edwards_extended::GroupAffine,
        TEModelParameters as Parameters,
    };
    use ark_ed_on_bls12_377::{EdwardsParameters as ParamEd377, Fq as FqEd377};
    use ark_ed_on_bls12_381::{EdwardsParameters as ParamEd381, Fq as FqEd381};
    use ark_ed_on_bn254::{EdwardsParameters as ParamEd254, Fq as FqEd254};
    use ark_ff::UniformRand;
    use ark_std::vec::Vec;
    use jf_utils::fr_to_fq;

    #[test]
    fn test_variable_base_multi_scalar_mul() -> Result<(), PlonkError> {
        test_variable_base_multi_scalar_mul_helper::<FqEd254, ParamEd254>()?;
        test_variable_base_multi_scalar_mul_helper::<FqEd377, ParamEd377>()?;
        test_variable_base_multi_scalar_mul_helper::<FqEd381, ParamEd381>()?;
        test_variable_base_multi_scalar_mul_helper::<Fq377, Param377>()?;

        // // uncomment the following code to dump the circuit comparison to screen
        // assert!(false);

        Ok(())
    }

    fn test_variable_base_multi_scalar_mul_helper<F, P>() -> Result<(), PlonkError>
    where
        F: PrimeField,
        P: Parameters<BaseField = F> + Clone,
    {
        let mut rng = ark_std::test_rng();

        for dim in [1, 2, 4, 8, 16, 32, 64, 128] {
            let mut circuit: PlonkCircuit<F> = PlonkCircuit::new();

            // bases and scalars
            let bases: Vec<GroupAffine<P>> =
                (0..dim).map(|_| GroupAffine::<P>::rand(&mut rng)).collect();
            let scalars: Vec<P::ScalarField> =
                (0..dim).map(|_| P::ScalarField::rand(&mut rng)).collect();
            let scalar_reprs: Vec<<P::ScalarField as PrimeField>::BigInt> =
                scalars.iter().map(|x| x.into_repr()).collect();
            let res = VariableBaseMSM::multi_scalar_mul(&bases, &scalar_reprs);
            let res_point: Point<F> = res.into();

            // corresponding wires
            let bases_point: Vec<Point<F>> = bases.iter().map(|x| (*x).into()).collect();
            let bases_vars: Vec<PointVariable> = bases_point
                .iter()
                .map(|x| circuit.create_point_variable(*x))
                .collect::<Result<Vec<_>, _>>()?;
            let scalar_vars: Vec<Variable> = scalars
                .iter()
                .map(|x| circuit.create_variable(F::from(fr_to_fq::<F, P>(x))))
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
