//! Utilities for Lagrange interpolations, evaluations, coefficients for a
//! polynomial

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{ops::Range, vec, vec::Vec};

// TODO: (alex) include these APIs upstream in arkworks directly

/// A helper trait for computing Lagrange coefficients of an evaluation domain
///
/// from arkworks:
/// Evaluate all Lagrange polynomials at tau to get the lagrange coefficients.
/// Define the following as
/// - H: The coset we are in, with generator g and offset h
/// - n: The size of the coset H
/// - Z_H: The vanishing polynomial for H. Z_H(x) = prod_{i in n} (x - hg^i) =
///   x^n - h^n
/// - v_i: A sequence of values, where v_0 = 1/(n * h^(n-1)), and v_{i + 1} = g
///   * v_i
///
/// We then compute L_{i,H}(tau) as `L_{i,H}(tau) = Z_H(tau) * v_i / (tau - h *
/// g^i)`
#[allow(dead_code)]
pub(crate) trait LagrangeCoeffs<F: FftField> {
    /// Returns the first coefficient: `L_{0, Domain}(tau)`
    fn first_lagrange_coeff(&self, tau: F) -> F;
    /// Returns the last coefficient: `L_{n-1, Domain}(tau)`
    fn last_lagrange_coeff(&self, tau: F) -> F;
    /// Returns (first, last) lagrange coeffs
    fn first_and_last_lagrange_coeffs(&self, tau: F) -> (F, F) {
        (
            self.first_lagrange_coeff(tau),
            self.last_lagrange_coeff(tau),
        )
    }
    /// Return a list of coefficients for `L_{range, Domain}(tau)`
    fn lagrange_coeffs_for_range(&self, range: Range<usize>, tau: F) -> Vec<F>;
}

impl<F: FftField> LagrangeCoeffs<F> for Radix2EvaluationDomain<F> {
    // L_0(tau) = Z_H(tau) * g^0 / (n * h^(n-1) * (tau - h * g^0))
    // with g^0 = 1
    // special care when tau in H, as both numerator and denominator is zero
    fn first_lagrange_coeff(&self, tau: F) -> F {
        let offset = self.coset_offset();
        if tau == offset {
            // when tau = g^0 * offset
            return F::one();
        }

        let z_h_at_tau = self.evaluate_vanishing_polynomial(tau);
        if z_h_at_tau.is_zero() {
            // the case where tau is the first element in the coset
            // already early-return
            F::zero()
        } else {
            let offset_pow_size_minus_one = self.coset_offset_pow_size() / offset;
            let denominator =
                self.size_as_field_element() * offset_pow_size_minus_one * (tau - offset);
            z_h_at_tau * denominator.inverse().unwrap()
        }
    }

    // L_n-1(tau) = Z_H(tau) * g^-1 / (n * h^(n-1) * (tau - h * g^-1))
    // with g^n-1 = g^-1
    fn last_lagrange_coeff(&self, tau: F) -> F {
        let offset = self.coset_offset();
        if tau == self.group_gen_inv() * offset {
            return F::one();
        }

        let z_h_at_tau = self.evaluate_vanishing_polynomial(tau);
        if z_h_at_tau.is_zero() {
            // the case where tau is the last element in the coset
            // already early-return
            F::zero()
        } else {
            let offset_pow_size_minus_one = self.coset_offset_pow_size() / offset;
            let denominator = self.size_as_field_element()
                * offset_pow_size_minus_one
                * (tau - offset * self.group_gen_inv());
            z_h_at_tau * self.group_gen_inv() * denominator.inverse().unwrap()
        }
    }

    // a slightly cheaper implementation of the generic default
    // saving repeated work when computing two coeffs separately
    fn first_and_last_lagrange_coeffs(&self, tau: F) -> (F, F) {
        let offset = self.coset_offset();
        let group_gen_inv = self.group_gen_inv();
        if tau == offset {
            return (F::one(), F::zero());
        }
        if tau == group_gen_inv * offset {
            return (F::zero(), F::one());
        }

        let z_h_at_tau = self.evaluate_vanishing_polynomial(tau);
        if z_h_at_tau.is_zero() {
            (F::zero(), F::zero())
        } else {
            let offset_pow_size_minus_one = self.coset_offset_pow_size() / offset;
            let first_denominator =
                self.size_as_field_element() * offset_pow_size_minus_one * (tau - offset);
            let last_denominator = self.size_as_field_element()
                * offset_pow_size_minus_one
                * (tau - offset * group_gen_inv);

            (
                z_h_at_tau / first_denominator,
                z_h_at_tau * group_gen_inv / last_denominator,
            )
        }
    }

    // similar to `EvaluationDomain::evaluate_all_lagrange_coefficients()`
    //
    // # Panic
    // if `range` exceeds the `self.size()`
    fn lagrange_coeffs_for_range(&self, range: Range<usize>, tau: F) -> Vec<F> {
        if range.end > self.size() {
            panic!("Out of range: domain size smaller than range.end");
        }
        let size = range.end - range.start;
        let z_h_at_tau = self.evaluate_vanishing_polynomial(tau);
        let offset = self.coset_offset();
        let group_gen = self.group_gen();
        let group_start = group_gen.pow([range.start as u64]);

        if z_h_at_tau.is_zero() {
            // In this case, we know that tau = hg^i, for some value i.
            // Then i-th lagrange coefficient in this case is then simply 1,
            // and all other lagrange coefficients are 0.
            // Thus we find i by brute force.
            let mut u = vec![F::zero(); size];
            let mut omega_i = offset * group_start;
            for u_i in u.iter_mut().take(size) {
                if omega_i == tau {
                    *u_i = F::one();
                    break;
                }
                omega_i *= &group_gen;
            }
            u
        } else {
            // In this case we have to compute `Z_H(tau) * v_i / (tau - h g^i)`
            // for i in start..end
            // We actually compute this by computing (Z_H(tau) * v_i)^{-1} * (tau - h g^i)
            // and then batch inverting to get the correct lagrange coefficients.
            // We let `l_i = (Z_H(tau) * v_i)^-1` and `r_i = tau - h g^i`
            // Notice that since Z_H(tau) is i-independent,
            // and v_i = g * v_{i-1}, it follows that
            // l_i = g^-1 * l_{i-1}

            let group_gen_inv = self.group_gen_inv();
            let start = range.start as u64;

            // v_0_inv = n * h^(n-1)
            let v_0_inv = self.size_as_field_element() * self.coset_offset_pow_size() / offset;
            let mut l_i = z_h_at_tau.inverse().unwrap() * v_0_inv * group_gen_inv.pow([start]);

            let mut negative_cur_elem = -offset * group_start;
            let mut lagrange_coefficients_inverse = vec![F::zero(); size];
            for coeff in lagrange_coefficients_inverse.iter_mut() {
                let r_i = tau + negative_cur_elem;
                *coeff = l_i * r_i;
                // Increment l_i and negative_cur_elem
                l_i *= &group_gen_inv;
                negative_cur_elem *= &group_gen;
            }
            ark_ff::fields::batch_inversion(lagrange_coefficients_inverse.as_mut_slice());
            lagrange_coefficients_inverse
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{rand::Rng, One, UniformRand, Zero};

    /// Test that for points in the domain, coefficients are computed correctly
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
                    assert_eq!(coset_domain.first_lagrange_coeff(coset_x), Fr::one());
                    assert_eq!(coset_domain.last_lagrange_coeff(coset_x), Fr::zero());
                }
                if i == domain.size() - 1 {
                    assert_eq!(domain.last_lagrange_coeff(x), Fr::one());
                    assert_eq!(domain.first_lagrange_coeff(x), Fr::zero());
                    assert_eq!(coset_domain.last_lagrange_coeff(coset_x), Fr::one());
                    assert_eq!(coset_domain.first_lagrange_coeff(coset_x), Fr::zero());
                }

                let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(x);
                let coset_lagrange_coeffs =
                    coset_domain.evaluate_all_lagrange_coefficients(coset_x);
                for _ in 0..10 {
                    let start = rng.gen_range(0..i + 1);
                    let end = rng.gen_range(start..domain_size + 1);
                    assert_eq!(
                        domain.lagrange_coeffs_for_range(start..end, x),
                        lagrange_coeffs[start..end]
                    );
                    assert_eq!(
                        coset_domain.lagrange_coeffs_for_range(start..end, coset_x),
                        coset_lagrange_coeffs[start..end]
                    );
                }
            }
        }
    }

    #[test]
    fn test_random_lagrange_coeff() {
        let mut rng = jf_utils::test_rng();
        for domain_log_size in 4..9 {
            let domain_size = 1 << domain_log_size;
            let domain = Radix2EvaluationDomain::<Fr>::new(domain_size).unwrap();
            let coset_domain = domain.get_coset(Fr::GENERATOR).unwrap();

            for _ in 0..10 {
                let x = Fr::rand(&mut rng);
                let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(x);
                let coset_lagrange_coeffs = coset_domain.evaluate_all_lagrange_coefficients(x);

                assert_eq!(domain.first_lagrange_coeff(x), lagrange_coeffs[0]);
                assert_eq!(
                    domain.last_lagrange_coeff(x),
                    lagrange_coeffs[domain_size - 1]
                );
                assert_eq!(
                    coset_domain.first_lagrange_coeff(x),
                    coset_lagrange_coeffs[0]
                );
                assert_eq!(
                    coset_domain.last_lagrange_coeff(x),
                    coset_lagrange_coeffs[domain_size - 1]
                );

                for _ in 0..10 {
                    let start = rng.gen_range(0..domain_size);
                    let end = rng.gen_range(start..domain_size + 1);
                    assert_eq!(
                        domain.lagrange_coeffs_for_range(start..end, x),
                        lagrange_coeffs[start..end]
                    );
                    assert_eq!(
                        coset_domain.lagrange_coeffs_for_range(start..end, x),
                        coset_lagrange_coeffs[start..end]
                    );
                }
            }
        }
    }
}
