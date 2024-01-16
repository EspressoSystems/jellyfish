// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Represent polynomials in its "evaluation form".

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::fmt;

// TODO: (alex) consider a generalized version where original coefficient can be
// group elements, thus evaluations are group points where we can use `trait
// GroupCoeff`.
/// A polynomial represented in its evaluation form.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EvalReprPolynomial<F: FftField, I: IntoIterator<Item = F>> {
    /// Evaluation domain over which `evals` are computed
    domain: Radix2EvaluationDomain<F>,
    /// Number of evaluations = degree + 1
    /// For memory efficiency, especially for large-degree polynomial, we use
    /// iterator instead of owned vector
    evals: I,
    /// degree of the polynomial
    degree: usize,
}

impl<F, I> EvalReprPolynomial<F, I>
where
    F: FftField,
    I: IntoIterator<Item = F>,
{
    /// create a new polynomial without sanity check
    pub fn new_unchecked(degree: usize, evals: I) -> Self {
        let domain = Radix2EvaluationDomain::new(degree + 1).unwrap();
        Self {
            domain,
            evals,
            degree,
        }
    }
}

impl<F, I> fmt::Debug for EvalReprPolynomial<F, I>
where
    F: FftField,
    I: IntoIterator<Item = F>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // TODO: add logic here
        // for (i, coeff) in self.evals.iter().enumerate() {
        //     if i == 0 {
        //         write!(f, "\n{:?}", coeff)?;
        //     } else if i == 1 {
        //         write!(f, " + \n{:?} * x", coeff)?;
        //     } else {
        //         write!(f, " + \n{:?} * x^{}", coeff, i)?;
        //     }
        // }

        Ok(())
    }
}
