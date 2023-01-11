use std::cmp::max;

use ark_bls12_381::Fr;
use ark_ff::{Field, Zero};
use ark_std::end_timer;
use fn_timer::fn_timer;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

use super::{PlonkImplInner, Selectors};
use crate::{gpu::FFTDomain, polynomial::VecPolynomial, timer};

impl PlonkImplInner {
    #[fn_timer]
    pub fn compute_t_part1_type1(&self) -> Vec<Fr> {
        let n = self.n;
        match &self.q {
            Selectors::Type1 { a, h } | Selectors::Type2 { a, h, .. } => {
                let h = timer!("FFT on h", {
                    let mut h = h.load().unwrap();
                    self.domain8.fft_io(&mut h);
                    self.vec_to_mmap("quot_evals_1", h)
                });
                // h is dropped from memory here, so we can reuse the memory for a.
                let a = timer!("FFT on a", {
                    let mut a = a.load().unwrap();
                    self.domain8.fft_io(&mut a);
                    self.vec_to_mmap("quot_evals_2", a)
                });
                // a is dropped from memory here, so we can reuse the memory for u.
                let mut u = timer!("FFT on w", {
                    let mut u = self.w.load().unwrap();
                    self.domain8.fft_io(&mut u);
                    u
                });
                // Only u is present in memory now.
                // u is of size 8n, and we assume that it fits in memory.
                // For larger n, one may store u in disk and create a mmap for it,
                // just like we do for h and a.

                let w = timer!("Copy w evals", self.slice_to_mmap("quot_evals_3", &u));

                timer!("Compute evals of (w^4 * h + a) * w", {
                    u.par_iter_mut()
                        .zip_eq(h.par_iter())
                        .zip_eq(a.par_iter())
                        .zip_eq(w.par_iter())
                        .for_each(|(((u, h), a), w)| {
                            u.square_in_place();
                            u.square_in_place();
                            *u *= h;
                            *u += a;
                            *u *= w;
                        });
                });
                timer!("IFFT on u", {
                    self.domain8.ifft_oi(&mut u);
                });

                u.div_by_vanishing_poly(n);

                assert!(u.len() <= 6 * n + 5, "{} {}", u.len(), 6 * n + 5);

                u
            }
            Selectors::Type3 { o, c, .. } => {
                let mut u = timer!("FFT on w", {
                    let mut u = self.w.load().unwrap();
                    self.domain4.fft_io(&mut u);
                    u
                });
                let o = timer!("FFT on o", {
                    let mut o = o.load().unwrap();
                    self.domain4.fft_io(&mut o);
                    o
                });
                // Both u and o are of size 4n, and we assume that they fit in memory.

                timer!("Compute evals of -o * w", {
                    u.par_iter_mut().zip_eq(o.into_par_iter()).for_each(|(u, o)| {
                        *u *= -o;
                    });
                });

                timer!("IFFT on u", {
                    self.domain4.ifft_oi(&mut u);
                });

                timer!("Compute x + c - o * w", {
                    u.par_iter_mut()
                        .zip(c.mmap().unwrap().par_iter())
                        .zip_eq(self.x.mmap().unwrap().par_iter())
                        .for_each(|((u, c), x)| {
                            *u += c;
                            *u += x;
                        });
                });

                u.div_by_vanishing_poly(n);

                assert!(u.len() <= 2 * n + 1, "{} {}", u.len(), 2 * n + 1);

                u
            }
        }
    }

    #[fn_timer]
    pub fn compute_t_part1_type2(&self, mut ww: Vec<Fr>) -> Vec<Fr> {
        let n = self.n;
        match &self.q {
            Selectors::Type2 { m, .. } => {
                let m = timer!("FFT on m", {
                    let mut m = m.load().unwrap();
                    self.domain4.fft_io(&mut m);
                    self.vec_to_mmap("quot_evals_1", m)
                });
                let mut u = timer!(format!("FFT on w{} * w{}", self.me - 1, self.me), {
                    self.domain4.fft_io(&mut ww);
                    ww
                });
                timer!(format!("Compute evals of m * w{} * w{}", self.me - 1, self.me), {
                    u.par_iter_mut().zip_eq(m.par_iter()).for_each(|(u, m)| {
                        *u *= m;
                    });
                });
                timer!("IFFT on u", {
                    self.domain4.ifft_oi(&mut u);
                });

                u.div_by_vanishing_poly(n);

                assert!(u.len() <= 3 * n + 2, "{} {}", u.len(), 3 * n + 2);

                u
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer]
    pub fn compute_t_part1_type3_and_part2(
        &self,
        mut w0w1: Vec<Fr>,
        mut w2w3: Vec<Fr>,
        mut delta01: Vec<Fr>,
        mut delta23: Vec<Fr>,
        z: &[Fr],
    ) -> Vec<Fr> {
        let n = self.n;
        let d = self.beta * self.k[self.me];
        let m = 64 - self.domain8.size().trailing_zeros();
        match &self.q {
            Selectors::Type3 { e, .. } => {
                let w0w1 = timer!("FFT on w0 * w1", {
                    self.domain8.fft_io(&mut w0w1);
                    self.vec_to_mmap("quot_evals_1", w0w1)
                });
                // w0w1 is dropped from memory here, so we can reuse the memory for w2w3.
                let w2w3 = timer!("FFT on w2 * w3", {
                    self.domain8.fft_io(&mut w2w3);
                    self.vec_to_mmap("quot_evals_2", w2w3)
                });
                // w2w3 is dropped from memory here, so we can reuse the memory for delta01.
                let delta01 =
                    timer!("FFT on (w0 + β * k0 * X + γ) * (w1 + β * k1 * X + γ) - w0 * w1", {
                        self.domain8.fft_io(&mut delta01);
                        self.vec_to_mmap("quot_evals_4", delta01)
                    });
                // delta01 is dropped from memory here, so we can reuse the memory for delta23.
                let delta23 =
                    timer!("FFT on (w2 + β * k2 * X + γ) * (w3 + β * k3 * X + γ) - w2 * w3", {
                        self.domain8.fft_io(&mut delta23);
                        self.vec_to_mmap("quot_evals_5", delta23)
                    });
                // delta23 is dropped from memory here, so we can reuse the memory for w4.
                let w4 = timer!("FFT on w4", {
                    let mut w4 = self.w.load().unwrap();
                    self.domain8.fft_io(&mut w4);
                    self.vec_to_mmap("quot_evals_3", w4)
                });
                // w4 is dropped from memory here, so we can reuse the memory for e.
                let e = timer!("FFT on e", {
                    let mut e = e.load().unwrap();
                    self.domain8.fft_io(&mut e);
                    self.vec_to_mmap("quot_evals_6", e)
                });
                // w4 is dropped from memory here, so we can reuse the memory for u.
                let mut u = timer!("FFT on z", {
                    let mut u = z.to_vec();
                    self.domain8.fft_io(&mut u);
                    u
                });
                // Only u is present in memory now.
                // u is of size 8n, and we assume that it fits in memory.
                timer!("Compute evals of e * Π(wi) + α * z * Π(wi + β * ki * X + γ)", {
                    u.par_iter_mut()
                        .zip_eq(w0w1.par_iter())
                        .zip_eq(w2w3.par_iter())
                        .zip_eq(w4.par_iter())
                        .zip_eq(e.par_iter())
                        .zip_eq(delta01.par_iter())
                        .zip_eq(delta23.par_iter())
                        .enumerate()
                        .for_each(|(i, ((((((u, w0w1), w2w3), w4), e), delta01), delta23))| {
                            *u *= self.alpha;
                            *u *= *w0w1 + delta01;
                            *u *= *w2w3 + delta23;
                            *u *= self.domain8.element(i.reverse_bits() >> m) * d + self.gamma + w4;
                            *u += *e * w0w1 * w2w3 * w4;
                        });
                });
                timer!("IFFT on u", {
                    self.domain8.ifft_oi(&mut u);
                });

                u.div_by_vanishing_poly(n);

                assert!(u.len() <= 6 * n + 8, "{} {}", u.len(), 6 * n + 8);

                u
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer]
    pub fn compute_t_part4(&self, alpha: Fr, z: &[Fr]) -> Vec<Fr> {
        let alpha_square_over_n = alpha.square() / Fr::from(self.n as u64);
        let mut t = z.to_vec();
        t.scale_mut(alpha_square_over_n);
        t[0] -= alpha_square_over_n;
        let mut r = t.pop().unwrap();
        for i in (0..t.len()).rev() {
            (t[i], r) = (r, t[i] + r);
        }
        t
    }

    #[fn_timer]
    pub fn update_t(&self, t_self: &mut Vec<Fr>, t_other: &[Fr], offset: usize) {
        t_self.resize(max(t_self.len(), offset + t_other.len()), Fr::zero());
        t_self[offset..].par_iter_mut().zip(t_other).for_each(|(t, u)| {
            *t += u;
        });
    }

    #[fn_timer]
    pub fn compute_ww_type1_and_type2_delta(&self, mut w_other: Vec<Fr>) {
        let beta = self.beta;
        let gamma = self.gamma;

        let n = self.n;
        let mut w_self = self.w.load().unwrap();

        let this = unsafe { &mut *(self as *const _ as *mut Self) };

        this.w2_tmp = {
            let mut u = vec![
                gamma.square(),
                gamma * beta * (self.k[self.me - 1] + self.k[self.me]),
                beta.square() * self.k[self.me - 1] * self.k[self.me],
            ];
            u.add_scaled_mut(&w_self, gamma);
            u.add_scaled_mut(&w_other, gamma);
            u.add_scaled_mut_offset(&w_self, beta * self.k[self.me - 1], 1);
            u.add_scaled_mut_offset(&w_other, beta * self.k[self.me], 1);
            u
        };
        this.w1_tmp = {
            let w = timer!(format!("FFT on w{}", self.me - 1), {
                self.domain4.fft_io(&mut w_other);
                self.vec_to_mmap("quot_evals_1", w_other)
            });
            let mut u = timer!(format!("FFT on w{}", self.me), {
                self.domain4.fft_io(&mut w_self);
                w_self
            });
            timer!(format!("Compute evals of w{} * w{}", self.me - 1, self.me), {
                u.par_iter_mut().zip_eq(w.par_iter()).for_each(|(u, w)| {
                    *u *= w;
                });
            });
            timer!("IFFT on u", {
                self.domain4.ifft_oi(&mut u);
            });

            u.remove_leading_zeros(0);

            assert!(u.len() <= 2 * n + 3, "{} {}", u.len(), 2 * n + 3);

            u
        };

        this.w1_tmp.resize(2 * n + 3, Default::default());
        this.w2_tmp.resize(n + 3, Default::default());
    }

    #[fn_timer]
    pub fn compute_w_type3(&self) {
        let mut u = self.w.load().unwrap();
        u.add_scaled_mut(&self.sigma.mmap().unwrap(), self.beta);
        u[0] += self.gamma;

        u.resize(self.n + 2, Default::default());

        unsafe {
            let this = &mut *(self as *const _ as *mut Self);
            this.w3_tmp = u;
        }
    }
}
