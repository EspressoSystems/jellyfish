// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Generalized DensePolynomial, allowing coefficients to be group elements, not
//! just field elemnts.
//! Inspired by and natural extension of arkwork's `ark-poly` code.

// FIXME: remove this
#![allow(dead_code)]
use ark_ff::{Field, Zero};
use ark_std::{
    fmt,
    marker::PhantomData,
    ops::{Add, MulAssign},
    rand::Rng,
    vec::Vec,
    UniformRand,
};
use itertools::{
    EitherOrBoth::{Both, Left, Right},
    Itertools,
};

// TODO: (alex) change to trait alias once stablized in Rust:
// `https://doc.rust-lang.org/unstable-book/language-features/trait-alias.html`
/// A trait bound alias for generalized coefficient type used in
/// `GeneralDensePolynomial`. Concrete instantiations can be both field or
/// group elements.
pub trait GeneralCoeff<F: Field>:
    Clone + fmt::Debug + Copy + Add<Self, Output = Self> + MulAssign<F> + Zero + UniformRand + Sized
{
}

impl<T, F: Field> GeneralCoeff<F> for T where
    T: Clone
        + fmt::Debug
        + Copy
        + Add<Self, Output = Self>
        + MulAssign<F>
        + Zero
        + UniformRand
        + Sized
{
}

/// Stores a polynomial in the coefficient form.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct GeneralDensePolynomial<T: GeneralCoeff<F>, F: Field> {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub coeffs: Vec<T>,
    _phantom: PhantomData<F>,
}

// TODO: (alex) we didn't implement `trait Polynomial<F>` in arkwork for our
// struct because that trait assume the coeffs are field elements. Therefore, we
// need to generalize that trait first which is left for future work or even
// upstream PR.
impl<T, F> GeneralDensePolynomial<T, F>
where
    T: GeneralCoeff<F>,
    F: Field,
{
    /// Constructs a new polynomial from a list of coefficients
    pub fn from_coeff_slice(coeffs: &[T]) -> Self {
        Self::from_coeff_vec(coeffs.to_vec())
    }

    /// Constructs a new polynomial from a list of coefficients
    pub fn from_coeff_vec(coeffs: Vec<T>) -> Self {
        let mut result = Self {
            coeffs,
            _phantom: PhantomData,
        };
        result.truncate_leading_zeros();
        assert!(result.coeffs.last().map_or(true, |coeff| !coeff.is_zero()));
        result
    }

    /// Outputs a univariate polynomial of degree `d` where
    /// each coefficient is sampled uniformly at random.
    fn rand<R: Rng>(d: usize, rng: &mut R) -> Self {
        let mut random_coeffs = Vec::new();
        for _ in 0..=d {
            random_coeffs.push(T::rand(rng));
        }
        Self::from_coeff_vec(random_coeffs)
    }

    /// Returns the total degree of the polynomial
    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            assert!(self.coeffs.last().map_or(false, |coeff| !coeff.is_zero()));
            self.coeffs.len() - 1
        }
    }

    /// Evaluate `self` at a given `point`
    pub fn evaluate(&self, point: &F) -> T {
        if self.is_zero() {
            return T::zero();
        } else if point.is_zero() {
            return self.coeffs[0];
        }
        self.horner_evaluate(point)
    }
}

impl<T, F> GeneralDensePolynomial<T, F>
where
    T: GeneralCoeff<F>,
    F: Field,
{
    fn truncate_leading_zeros(&mut self) {
        while self.coeffs.last().map_or(false, |c| c.is_zero()) {
            self.coeffs.pop();
        }
    }

    // Horner's method for polynomial evaluation with cost O(n).
    fn horner_evaluate(&self, point: &F) -> T {
        self.coeffs
            .iter()
            .rfold(T::zero(), move |mut result, coeff| {
                result *= *point;
                result + *coeff
            })
    }
}

impl<T, F> Zero for GeneralDensePolynomial<T, F>
where
    T: GeneralCoeff<F>,
    F: Field,
{
    /// returns the zero polynomial
    fn zero() -> Self {
        Self {
            coeffs: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// checks if the given polynomial is zero
    fn is_zero(&self) -> bool {
        self.coeffs.is_empty() || self.coeffs.iter().all(|coeff| coeff.is_zero())
    }
}

impl<T, F> Add<Self> for GeneralDensePolynomial<T, F>
where
    T: GeneralCoeff<F>,
    F: Field,
{
    type Output = Self;

    // TODO: (alex) add `Add<'a Self, Output=Self>` and internally use that instead.
    fn add(self, rhs: Self) -> Self::Output {
        let mut res = if self.is_zero() {
            rhs
        } else if rhs.is_zero() {
            self
        } else {
            let coeffs = self
                .coeffs
                .into_iter()
                .zip_longest(rhs.coeffs.into_iter())
                .map(|pair| match pair {
                    Both(x, y) => x + y,
                    Left(x) | Right(x) => x,
                })
                .collect();
            Self::from_coeff_vec(coeffs)
        };

        res.truncate_leading_zeros();
        res
    }
}

impl<T, F> fmt::Debug for GeneralDensePolynomial<T, F>
where
    T: GeneralCoeff<F>,
    F: Field,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for (i, coeff) in self.coeffs.iter().enumerate().filter(|(_, c)| !c.is_zero()) {
            if i == 0 {
                write!(f, "\n{:?}", coeff)?;
            } else if i == 1 {
                write!(f, " + \n{:?} * x", coeff)?;
            } else {
                write!(f, " + \n{:?} * x^{}", coeff, i)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::{short_weierstrass::SWCurveConfig, CurveGroup};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use ark_std::iter::successors;
    use jf_utils::test_rng;

    #[test]
    fn test_poly_eval_single_point() {
        let mut rng = test_rng();
        for _ in 0..5 {
            let degree = rng.gen_range(5..40);
            let f = GeneralDensePolynomial::<Fr, Fr>::rand(degree, &mut rng);
            let g = GeneralDensePolynomial::<G1Projective, Fr>::rand(degree, &mut rng);
            let point = Fr::rand(&mut rng);

            let f_x = f.evaluate(&point);
            let expected_f_x: Fr =
                DensePolynomial::from_coefficients_slice(&f.coeffs).evaluate(&point);
            assert_eq!(f_x, expected_f_x);

            let g_x = g.evaluate(&point);
            // g(X) = G0 + G1 * X + G2 * X^2 + G3 * X^3 + ...
            // turn into an MSM between [G0, G1, G2, ...] and [1, x, x^2, x^3, ...]
            let scalars: Vec<Fr> = successors(Some(Fr::from(1u32)), |&prev| Some(prev * point))
                .take((g.degree() + 1) as usize)
                .collect();
            let expected_g_x =
                SWCurveConfig::msm(&CurveGroup::normalize_batch(&g.coeffs), &scalars).unwrap();
            assert_eq!(g_x, expected_g_x);
        }
    }

    #[test]
    fn test_poly_add() {
        let mut rng = test_rng();
        for _ in 0..5 {
            let degree = rng.gen_range(5..40);
            let f_1 = GeneralDensePolynomial::<Fr, Fr>::rand(degree, &mut rng);
            let f_2 = GeneralDensePolynomial::<Fr, Fr>::rand(degree, &mut rng);
            let expected_f_3 = DensePolynomial::from_coefficients_slice(&f_1.coeffs)
                + DensePolynomial::from_coefficients_slice(&f_2.coeffs);
            let f_3 = f_1 + f_2;
            assert_eq!(f_3.coeffs, expected_f_3.coeffs);

            let g_1 = GeneralDensePolynomial::<G1Projective, Fr>::rand(degree, &mut rng);
            let g_2 = GeneralDensePolynomial::<G1Projective, Fr>::rand(degree, &mut rng);
            let expected_g_3: Vec<G1Projective> = g_1
                .coeffs
                .iter()
                .zip(g_2.coeffs.iter())
                .map(|(a, b)| a + b)
                .collect();
            let g_3 = g_1 + g_2;
            assert_eq!(g_3.coeffs, expected_g_3);
        }
    }
}
