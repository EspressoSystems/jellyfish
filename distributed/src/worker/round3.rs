use std::{
    cmp::{max, min},
    mem,
    ops::Range,
};

use ark_bls12_381::Fr;
use ark_ff::{Field, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::end_timer;
use fn_timer::fn_timer;
use futures::future::join_all;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};

use super::{PlonkImplInner, Selectors};
use crate::{
    constants::CAPNP_CHUNK_SIZE, gpu::FFTDomain, polynomial::VecPolynomial, send_chunks_until_ok,
    set_chunk, timer,
};

fn add_within(v: &mut Vec<Fr>, to: Range<usize>, from: Range<usize>) {
    v[to].par_iter().zip(&v[from]).for_each(|(a, b)| unsafe {
        *(a as *const _ as *mut Fr) += b;
    });
}

/// Divide a polynomial by the vanishing polynomial.
/// The algorithm is in place, and the actual result is u[n..].
/// The first n elements are not removed, so we can avoid a memory copy.
#[fn_timer]
fn div_by_vanishing_poly(u: &mut Vec<Fr>, n: usize) {
    for i in (n..u.len()).step_by(n).rev() {
        add_within(u, i - n..i, i..i + n);
    }
    // Trick: add the remainder to the quotient.
    // Although at this point u is not divisible by the vanishing polynomial,
    // the final quotient polynomial t will be.
    // One can check this by running the following code:
    // ```
    // let rng = &mut thread_rng();
    // let l = 1 << (rng.gen_range(1..20));
    // let domain = Radix2EvaluationDomain::<Fr>::new(l).unwrap();
    // let q = DensePolynomial::rand(l - 1, rng);
    // let a = DensePolynomial::rand(2 * l - 1, rng);
    // let b = &q.mul_by_vanishing_poly(domain) - &a;
    // let (q_1, r_1) = a.divide_by_vanishing_poly(domain).unwrap();
    // let (q_2, r_2) = b.divide_by_vanishing_poly(domain).unwrap();
    // assert_eq!(&q_1 + &q_2 + r_1 + r_2, q);
    // ```
    add_within(u, n..2 * n, 0..n);

    u.remove_leading_zeros(n);
}

impl PlonkImplInner {
    #[fn_timer]
    pub fn init_z(&self, z: Vec<Fr>) {
        let mut this = unsafe { &mut *(self as *const _ as *mut Self) };
        this.z = z;
    }

    #[fn_timer]
    pub fn compute_t_part1_type1(&self) -> Vec<Fr> {
        let n = self.n;
        match &self.q {
            Selectors::Type1 { a, h } | Selectors::Type2 { a, h, .. } => {
                let h = timer!("FFT on h", {
                    let mut h = h.load().unwrap().to_vec();
                    self.domain8.fft_io(&mut h);
                    self.vec_to_mmap("quot_evals_1", h)
                });
                // h is dropped from memory here, so we can reuse the memory for a.
                let a = timer!("FFT on a", {
                    let mut a = a.load().unwrap().to_vec();
                    self.domain8.fft_io(&mut a);
                    self.vec_to_mmap("quot_evals_2", a)
                });
                // a is dropped from memory here, so we can reuse the memory for u.
                let mut u = timer!("FFT on w", {
                    let mut u = self.w.load().unwrap().to_vec();
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

                div_by_vanishing_poly(&mut u, n);

                assert!(u.len() <= 6 * n + 5, "{} {}", u.len(), 6 * n + 5);

                u
            }
            Selectors::Type3 { o, c, .. } => {
                let mut u = timer!("FFT on w", {
                    let mut u = self.w.load().unwrap().to_vec();
                    self.domain4.fft_io(&mut u);
                    u
                });
                let o = timer!("FFT on o", {
                    let mut o = o.load().unwrap().to_vec();
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
                        .zip(c.load().unwrap().par_iter())
                        .zip_eq(self.x.load().unwrap().par_iter())
                        .for_each(|((u, c), x)| {
                            *u += c;
                            *u += x;
                        });
                });

                div_by_vanishing_poly(&mut u, n);

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
                    let mut m = m.load().unwrap().to_vec();
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

                div_by_vanishing_poly(&mut u, n);

                assert!(u.len() <= 3 * n + 2, "{} {}", u.len(), 3 * n + 2);

                u
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer]
    pub fn compute_t_part1_type3(&self, mut w0w1: Vec<Fr>, mut w2w3: Vec<Fr>) -> Vec<Fr> {
        let n = self.n;
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
                // w2w3 is dropped from memory here, so we can reuse the memory for w4.
                let w4 = timer!("FFT on w4", {
                    let mut w4 = self.w.load().unwrap().to_vec();
                    self.domain8.fft_io(&mut w4);
                    self.vec_to_mmap("quot_evals_3", w4)
                });
                // w4 is dropped from memory here, so we can reuse the memory for u.
                let mut u = timer!("FFT on e", {
                    let mut u = e.load().unwrap().to_vec();
                    self.domain8.fft_io(&mut u);
                    u
                });
                // Only u is present in memory now.
                // u is of size 8n, and we assume that it fits in memory.
                timer!("Compute evals of e * Π(wi)", {
                    u.par_iter_mut()
                        .zip_eq(w0w1.par_iter())
                        .zip_eq(w2w3.par_iter())
                        .zip_eq(w4.par_iter())
                        .for_each(|(((u, w0w1), w2w3), w4)| {
                            *u *= w0w1;
                            *u *= w2w3;
                            *u *= w4;
                        });
                });
                timer!("IFFT on u", {
                    self.domain8.ifft_oi(&mut u);
                });

                div_by_vanishing_poly(&mut u, n);

                assert!(u.len() <= 6 * n + 5, "{} {}", u.len(), 6 * n + 5);

                u
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer]
    pub fn compute_t_part2(
        &self,
        mut w0w1: Vec<Fr>,
        mut w2w3: Vec<Fr>,
        alpha: Fr,
        beta: Fr,
        gamma: Fr,
    ) -> Vec<Fr> {
        match &self.q {
            Selectors::Type3 { .. } => {
                let n = self.n;

                let w0w1 = timer!("FFT on (w0 + β * k0 * X + γ) * (w1 + β * k1 * X + γ)", {
                    self.domain8.fft_io(&mut w0w1);
                    self.vec_to_mmap("quot_evals_1", w0w1)
                });
                // w0w1 is dropped from memory here, so we can reuse the memory for w2w3.
                let w2w3 = timer!("FFT on (w2 + β * k2 * X + γ) * (w3 + β * k3 * X + γ)", {
                    self.domain8.fft_io(&mut w2w3);
                    self.vec_to_mmap("quot_evals_2", w2w3)
                });
                // w2w3 is dropped from memory here, so we can reuse the memory for w4.
                let w4 = timer!("FFT on (w4 + β * k4 * X + γ)", {
                    let mut w4 = self.w.load().unwrap().to_vec();
                    w4[0] += gamma;
                    w4[1] += beta * self.k[self.me];
                    self.domain8.fft_io(&mut w4);
                    self.vec_to_mmap("quot_evals_3", w4)
                });
                // w4 is dropped from memory here, so we can reuse the memory for u.
                let mut u = timer!("FFT on z", {
                    let mut u = self.z.clone();
                    self.domain8.fft_io(&mut u);
                    u
                });
                // Only u is present in memory now.
                // u is of size 8n, and we assume that it fits in memory.
                timer!("Compute evals of α * z * Π(wi + β * ki * X + γ) ", {
                    u.par_iter_mut()
                        .zip_eq(w0w1.par_iter())
                        .zip_eq(w2w3.par_iter())
                        .zip_eq(w4.par_iter())
                        .for_each(|(((u, w0w1), w2w3), w4)| {
                            *u *= alpha;
                            *u *= w0w1;
                            *u *= w2w3;
                            *u *= w4;
                        });
                });
                timer!("IFFT on u", {
                    self.domain8.ifft_oi(&mut u);
                });

                div_by_vanishing_poly(&mut u, n);

                assert!(u.len() <= 6 * n + 8, "{} {}", u.len(), 6 * n + 8);

                u
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer]
    pub fn compute_t_part3(
        &self,
        mut w0w1: Vec<Fr>,
        mut w2w3: Vec<Fr>,
        alpha: Fr,
        beta: Fr,
        gamma: Fr,
    ) -> Vec<Fr> {
        match &self.q {
            Selectors::Type3 { .. } => {
                let n = self.n;

                let w0w1 = timer!("FFT on (w0 + β * σ0 + γ) * (w1 + β * σ1 + γ)", {
                    self.domain8.fft_io(&mut w0w1);
                    self.vec_to_mmap("quot_evals_1", w0w1)
                });
                // w0w1 is dropped from memory here, so we can reuse the memory for w2w3.
                let w2w3 = timer!("FFT on (w2 + β * σ2 + γ) * (w3 + β * σ3 + γ)", {
                    self.domain8.fft_io(&mut w2w3);
                    self.vec_to_mmap("quot_evals_2", w2w3)
                });
                // w2w3 is dropped from memory here, so we can reuse the memory for w4.
                let w4 = timer!("FFT on (w4 + β * σ4 + γ)", {
                    let mut w4 = self.w.load().unwrap().to_vec();
                    let sigma = self.sigma.load().unwrap();
                    w4.resize(max(w4.len(), sigma.len()), Fr::zero());
                    w4.par_iter_mut().zip(sigma.par_iter()).for_each(|(w, s)| {
                        *w += beta * s;
                    });
                    w4[0] += gamma;
                    self.domain8.fft_io(&mut w4);
                    self.vec_to_mmap("quot_evals_3", w4)
                });
                // w4 is dropped from memory here, so we can reuse the memory for u.
                let mut u = timer!("FFT on -α * z'", {
                    let mut u = self.z.clone();
                    Radix2EvaluationDomain::distribute_powers_and_mul_by_const(
                        &mut u,
                        self.domain1.generator(),
                        -alpha,
                    );
                    self.domain8.fft_io(&mut u);
                    u
                });
                // Only u is present in memory now.
                // u is of size 8n, and we assume that it fits in memory.
                timer!("Compute evals of -α * z' * Π(wi + β * σi + γ) ", {
                    u.par_iter_mut()
                        .zip_eq(w0w1.par_iter())
                        .zip_eq(w2w3.par_iter())
                        .zip_eq(w4.par_iter())
                        .for_each(|(((u, w0w1), w2w3), w4)| {
                            *u *= w0w1;
                            *u *= w2w3;
                            *u *= w4;
                        });
                });
                timer!("IFFT on u", {
                    self.domain8.ifft_oi(&mut u);
                });

                div_by_vanishing_poly(&mut u, n);

                assert!(u.len() <= 6 * n + 8, "{} {}", u.len(), 6 * n + 8);

                u
            }
            _ => unreachable!(),
        }
    }

    #[fn_timer]
    pub fn compute_t_part4(&self, z: &[Fr], alpha: Fr) -> Vec<Fr> {
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
    pub async fn share_t(&self, t: &[Fr]) {
        let step = CAPNP_CHUNK_SIZE / mem::size_of::<Fr>();
        for i in (0..self.n + 2).step_by(step) {
            join_all(t.chunks(self.n + 2).zip(self.connections.iter().rev()).map(
                |(t, peer)| async move {
                    if i < t.len() {
                        send_chunks_until_ok!({
                            let mut req = peer.prove_round3_update_t_request();
                            req.get().set_offset(i as u64);
                            set_chunk!(req, init_t, &t[i..min(i + step, t.len())]);
                            req
                        });
                    }
                },
            ))
            .await;
        }
    }

    #[fn_timer]
    pub fn update_t(&self, t_self: &mut Vec<Fr>, t_other: &[Fr], offset: usize) {
        t_self.resize(max(t_self.len(), offset + t_other.len()), Fr::zero());
        t_self[offset..].par_iter_mut().zip(t_other).for_each(|(t, u)| {
            *t += u;
        });
    }

    #[fn_timer]
    pub fn compute_ww_type1(&self, w: &[Fr]) -> Vec<Fr> {
        let n = self.n;
        let w = timer!(format!("FFT on w{}", self.me - 1), {
            let mut w = w.to_vec();
            self.domain4.fft_io(&mut w);
            self.vec_to_mmap("quot_evals_1", w)
        });
        let mut u = timer!(format!("FFT on w{}", self.me), {
            let mut w = self.w.load().unwrap().to_vec();
            self.domain4.fft_io(&mut w);
            w
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
    }

    // #[fn_timer]
    pub fn compute_ww_type2(
        &self,
        ww1: &[Fr],
        w_other: &mut [Fr],
        beta: Fr,
        gamma: Fr,
    ) -> Vec<Fr> {
        let n = self.n;
        let w_self = self.w.load().unwrap();
        let mut u = w_other.to_vec();
        u.add_mut(&w_self);
        u.scale_mut(gamma);
        u.add_scaled_mut_offset(&w_self, beta * self.k[self.me - 1], 1);
        u.add_scaled_mut_offset(w_other, beta * self.k[self.me], 1);
        u.add_mut(&[
            gamma.square(),
            gamma * beta * (self.k[self.me - 1] + self.k[self.me]),
            beta.square() * self.k[self.me - 1] * self.k[self.me],
        ]);
        u.add_mut(&ww1);

        assert!(u.len() <= 2 * n + 3, "{} {}", u.len(), 2 * n + 3);

        u
    }

    pub fn compute_w_type3(&self, beta: Fr, gamma: Fr) -> Vec<Fr> {
        let mut u = self.w.load().unwrap().to_vec();
        u.add_scaled_mut(&self.sigma.load().unwrap(), beta);
        u[0] += gamma;
        u
    }

    #[fn_timer]
    pub fn compute_ww_type3(&self, mut w: Vec<Fr>, beta: Fr, gamma: Fr) -> Vec<Fr> {
        let n = self.n;
        let w = timer!(format!("FFT on (w{0} + β * σ{0} + γ)", self.me - 1), {
            self.domain4.fft_io(&mut w);
            self.vec_to_mmap("quot_evals_1", w)
        });
        let mut u = timer!(format!("FFT on (w{0} + β * σ{0} + γ)", self.me), {
            let mut w = self.w.load().unwrap().to_vec();
            let sigma = self.sigma.load().unwrap();
            w.resize(max(w.len(), sigma.len()), Fr::zero());
            w.par_iter_mut().zip(sigma.par_iter()).for_each(|(w, s)| {
                *w += beta * s;
            });
            w[0] += gamma;
            self.domain4.fft_io(&mut w);
            w
        });
        timer!(
            format!(
                "Compute evals of (w{0} + β * σ{0} + γ) * (w{1} + β * σ{1} + γ)",
                self.me - 1,
                self.me
            ),
            {
                u.par_iter_mut().zip_eq(w.par_iter()).for_each(|(u, w)| {
                    *u *= w;
                });
            }
        );
        timer!("IFFT on u", {
            self.domain4.ifft_oi(&mut u);
        });

        u.remove_leading_zeros(0);

        assert!(u.len() <= 2 * n + 3, "{} {}", u.len(), 2 * n + 3);

        u
    }
}
