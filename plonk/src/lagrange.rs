//! Utilities for Lagrange interpolations, evaluations, and coefficients for a polynomial.

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{ops::Range, vec, vec::Vec};

/// A helper trait for computing Lagrange coefficients of an evaluation domain.
pub(crate) trait LagrangeCoeffs<F: FftField> {
    /// Returns the first coefficient: `L_{0, Domain}(tau)`
    fn first_lagrange_coeff(&self, tau: F) -> F;

    /// Returns the last coefficient: `L_{n-1, Domain}(tau)`
    fn last_lagrange_coeff(&self, tau: F) -> F;

    /// Returns (first, last) lagrange coefficients.
    fn first_and_last_lagrange_coeffs(&self, tau: F) -> (F, F) {
        (self.first_lagrange_coeff(tau), self.last_lagrange_coeff(tau))
    }

    /// Returns a list of coefficients for `L_{range, Domain}(tau)`
    fn lagrange_coeffs_for_range(&self, range: Range<usize>, tau: F) -> Vec<F>;
}

impl<F: FftField> LagrangeCoeffs<F> for Radix2EvaluationDomain<F> {
    /// Computes the first Lagrange coefficient `L_0(tau)`.
    fn first_lagrange_coeff(&self, tau: F) -> F {
        compute_lagrange_coeff(self, tau, self.coset_offset())
    }

    /// Computes the last Lagrange coefficient `L_{n-1}(tau)`.
    fn last_lagrange_coeff(&self, tau: F) -> F {
        let offset = self.coset_offset();
        let group_gen_inv = self.group_gen_inv();
        compute_lagrange_coeff(self, tau, offset * group_gen_inv)
    }

    /// Optimized computation for first and last coefficients simultaneously.
    fn first_and_last_lagrange_coeffs(&self, tau: F) -> (F, F) {
        let offset = self.coset_offset();
        let group_gen_inv = self.group_gen_inv();

        if tau == offset {
            return (F::one(), F::zero());
        }
        if tau == offset * group_gen_inv {
            return (F::zero(), F::one());
        }

        let z_h_at_tau = self.evaluate_vanishing_polynomial(tau);
        if z_h_at_tau.is_zero() {
            return (F::zero(), F::zero());
        }

        let offset_pow_size_minus_one = self.coset_offset_pow_size() / offset;
        let size_as_fe = self.size_as_field_element();

        let first_denominator = size_as_fe * offset_pow_size_minus_one * (tau - offset);
        let last_denominator =
            size_as_fe * offset_pow_size_minus_one * (tau - offset * group_gen_inv);

        (
            z_h_at_tau / first_denominator,
            z_h_at_tau * group_gen_inv / last_denominator,
        )
    }

    /// Computes Lagrange coefficients for a specific range.
    fn lagrange_coeffs_for_range(&self, range: Range<usize>, tau: F) -> Vec<F> {
        compute_lagrange_coeffs_for_range(self, range, tau)
    }
}

/// Computes a single Lagrange coefficient `L_{i,Domain}(tau)`.
fn compute_lagrange_coeff<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    tau: F,
    offset: F,
) -> F {
    if tau == offset {
        return F::one();
    }

    let z_h_at_tau = domain.evaluate_vanishing_polynomial(tau);
    if z_h_at_tau.is_zero() {
        F::zero()
    } else {
        let offset_pow_size_minus_one = domain.coset_offset_pow_size() / offset;
        let denominator = domain.size_as_field_element()
            * offset_pow_size_minus_one
            * (tau - offset);
        z_h_at_tau * denominator.inverse().unwrap()
    }
}

/// Computes Lagrange coefficients for a range `[start, end)`.
fn compute_lagrange_coeffs_for_range<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    range: Range<usize>,
    tau: F,
) -> Vec<F> {
    if range.end > domain.size() {
        panic!("Out of range: domain size is smaller than range.end");
    }

    let z_h_at_tau = domain.evaluate_vanishing_polynomial(tau);
    let offset = domain.coset_offset();
    let group_gen = domain.group_gen();
    let group_start = group_gen.pow([range.start as u64]);

    if z_h_at_tau.is_zero() {
        compute_trivial_lagrange_coeffs(domain, range, tau, offset, group_start, group_gen)
    } else {
        compute_nontrivial_lagrange_coeffs(
            domain,
            range,
            tau,
            z_h_at_tau,
            offset,
            group_start,
            group_gen,
        )
    }
}

/// Computes trivial Lagrange coefficients when `tau` is in the domain.
fn compute_trivial_lagrange_coeffs<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    range: Range<usize>,
    tau: F,
    offset: F,
    group_start: F,
    group_gen: F,
) -> Vec<F> {
    let mut coeffs = vec![F::zero(); range.len()];
    let mut omega_i = offset * group_start;

    for coeff in &mut coeffs {
        if omega_i == tau {
            *coeff = F::one();
            break;
        }
        omega_i *= group_gen;
    }
    coeffs
}

/// Computes non-trivial Lagrange coefficients when `tau` is not in the domain.
fn compute_nontrivial_lagrange_coeffs<F: FftField>(
    domain: &Radix2EvaluationDomain<F>,
    range: Range<usize>,
    tau: F,
    z_h_at_tau: F,
    offset: F,
    group_start: F,
    group_gen: F,
) -> Vec<F> {
    let group_gen_inv = domain.group_gen_inv();
    let v_0_inv = domain.size_as_field_element() * domain.coset_offset_pow_size() / offset;

    let mut l_i = z_h_at_tau.inverse().unwrap() * v_0_inv * group_gen_inv.pow([range.start as u64]);
    let mut negative_cur_elem = -offset * group_start;

    let mut coeffs = vec![F::zero(); range.len()];
    for coeff in &mut coeffs {
        let r_i = tau + negative_cur_elem;
        *coeff = l_i * r_i;

        // Update `l_i` and `negative_cur_elem`
        l_i *= group_gen_inv;
        negative_cur_elem *= group_gen;
    }
    ark_ff::fields::batch_inversion(&mut coeffs);
    coeffs
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{rand::Rng, UniformRand};

    #[test]
    fn test_in_domain_lagrange_coeff() {
        let mut rng = jf_utils::test_rng();

        for domain_log_size in 4..9 {
            let domain_size = 1 << domain_log_size;
            let domain = Radix2EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let coset_domain = domain.get_coset(Fr::GENERATOR).unwrap();

            for (i, (x, coset_x)) in domain.elements().zip(coset_domain.elements()).enumerate() {
                if i == 0 {
                    assert_eq!(domain.first_lagrange_coeff(x), Fr::one());
                    assert_eq!(domain.last_lagrange_coeff(x), Fr::zero());
                }
                if i == domain.size() - 1 {
                    assert_eq!(domain.last_lagrange_coeff(x), Fr::one());
                    assert_eq!(domain.first_lagrange_coeff(x), Fr::zero());
                }
                test_range_lagrange_coeff(&mut rng, &domain, x, i, domain_size);
                test_range_lagrange_coeff(&mut rng, &coset_domain, coset_x, i, domain_size);
            }
        }
    }

    fn test_range_lagrange_coeff<R: Rng, F: FftField>(
        rng: &mut R,
        domain: &Radix2EvaluationDomain<F>,
        x: F,
        i: usize,
        domain_size: usize,
    ) {
        let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(x);

        for _ in 0..10 {
            let start = rng.gen_range(0..=i);
            let end = rng.gen_range(start..=domain_size);
            assert_eq!(
                domain.lagrange_coeffs_for_range(start..end, x),
                lagrange_coeffs[start..end]
            );
        }
    }
}
