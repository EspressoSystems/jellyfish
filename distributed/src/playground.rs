use ark_bls12_381::Fr;
use ark_ff::{FftField, Field};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len).map(|_| iters.iter_mut().map(|n| n.next().unwrap()).collect::<Vec<T>>()).collect()
}

fn fft(domain: &Radix2EvaluationDomain<Fr>, coeffs: &Vec<Fr>) -> Vec<Fr> {
    let r = 1 << (domain.log_size_of_group >> 1);
    let c = domain.size() / r;
    let r_domain = Radix2EvaluationDomain::<Fr>::new(r).unwrap();
    let c_domain = Radix2EvaluationDomain::<Fr>::new(c).unwrap();

    let mut coeffs = coeffs.clone();
    coeffs.resize(domain.size(), Default::default());
    let mut t = transpose(coeffs.chunks(r).map(|i| i.to_vec()).collect::<Vec<_>>());
    t.iter_mut().enumerate().for_each(|(i, group)| {
        c_domain.fft_in_place(group);
        group.iter_mut().enumerate().for_each(|(j, u)| *u *= domain.group_gen.pow([(i * j) as u64]))
    });
    let mut groups = transpose(t);
    groups.iter_mut().for_each(|group| r_domain.fft_in_place(group));
    transpose(groups).concat()
}

fn ifft(domain: &Radix2EvaluationDomain<Fr>, coeffs: &Vec<Fr>) -> Vec<Fr> {
    let r = 1 << (domain.log_size_of_group >> 1);
    let c = domain.size() / r;
    let r_domain = Radix2EvaluationDomain::<Fr>::new(r).unwrap();
    let c_domain = Radix2EvaluationDomain::<Fr>::new(c).unwrap();

    let mut coeffs = coeffs.clone();
    coeffs.resize(domain.size(), Fr::default());
    let mut t = transpose(coeffs.chunks(r).map(|i| i.to_vec()).collect::<Vec<_>>());
    t.iter_mut().enumerate().for_each(|(i, group)| {
        c_domain.ifft_in_place(group);
        group
            .iter_mut()
            .enumerate()
            .for_each(|(j, u)| *u *= domain.group_gen_inv.pow([(i * j) as u64]))
    });
    let mut groups = transpose(t);
    groups.iter_mut().for_each(|group| r_domain.ifft_in_place(group));
    transpose(groups).concat()
}

fn coset_fft(domain: &Radix2EvaluationDomain<Fr>, coeffs: &Vec<Fr>) -> Vec<Fr> {
    let mut coeffs = coeffs.clone();
    Radix2EvaluationDomain::distribute_powers(&mut coeffs, Fr::multiplicative_generator());
    fft(domain, &coeffs)
}

fn coset_ifft(domain: &Radix2EvaluationDomain<Fr>, coeffs: &Vec<Fr>) -> Vec<Fr> {
    let mut coeffs = ifft(domain, coeffs);
    Radix2EvaluationDomain::distribute_powers(
        &mut coeffs,
        Fr::multiplicative_generator().inverse().unwrap(),
    );
    coeffs
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{File, OpenOptions},
        io::BufWriter,
        time::Instant,
    };

    use ark_ff::UniformRand;
    use ark_poly::{univariate::DensePolynomial, UVPolynomial};
    use ark_serialize::Write;
    use rand::thread_rng;
    use rayon::prelude::{
        IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator,
        ParallelIterator,
    };

    use super::*;
    use crate::{
        gpu::{Domain, FFTDomain},
        mmap::{Mmap, MutMmap},
        playground3::{fft_helper_in_place, ifft_helper_in_place},
        transpose::{ip_transpose, oop_transpose},
        utils::CastSlice,
    };

    #[test]
    fn test() {
        let rng = &mut thread_rng();

        let l = 512;

        let domain = Radix2EvaluationDomain::<Fr>::new(l).unwrap();
        let quot_domain = Radix2EvaluationDomain::<Fr>::new(l * 2).unwrap();

        let exps = (0..l).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let mut t = exps.clone();
        t.resize(l * 2, Default::default());

        assert_eq!(fft(&domain, &exps), domain.fft(&exps));
        assert_eq!(ifft(&domain, &exps), domain.ifft(&exps));
        assert_eq!(coset_fft(&domain, &exps), domain.coset_fft(&exps));
        assert_eq!(coset_ifft(&domain, &exps), domain.coset_ifft(&exps));

        assert_eq!(quot_domain.coset_fft(&exps), quot_domain.coset_fft(&t));
        assert_eq!(quot_domain.fft(&exps), fft(&quot_domain, &exps));
        assert_eq!(domain.coset_ifft(&domain.coset_fft(&exps)), exps);
    }

    #[test]
    fn test2() {
        let rng = &mut thread_rng();

        let l = 4;

        let domain = Radix2EvaluationDomain::<Fr>::new(l).unwrap();
        let quot_domain = Radix2EvaluationDomain::<Fr>::new(l * 2).unwrap();

        let x = DensePolynomial::<Fr>::rand(domain.size() - 1, rng);
        let mut xx = x.clone();
        Radix2EvaluationDomain::distribute_powers(&mut xx, quot_domain.group_gen);
        let y = DensePolynomial::<Fr>::rand(domain.size() - 1, rng);
        let mut yy = y.clone();
        Radix2EvaluationDomain::distribute_powers(&mut yy, quot_domain.group_gen);

        let now = Instant::now();
        let x_evals = quot_domain.fft(&x);
        println!("{:?}", now.elapsed());

        let now = Instant::now();
        let x_evals_2 = domain
            .fft(&x)
            .into_iter()
            .zip(domain.fft(&xx))
            .map(|(i, j)| vec![i, j])
            .flatten()
            .collect::<Vec<_>>();
        println!("{:?}", now.elapsed());

        assert_eq!(x_evals, x_evals_2);
        let y_evals = quot_domain.fft(&y);

        println!(
            "{:?}",
            domain
                .ifft(
                    &domain
                        .fft(&x)
                        .into_iter()
                        .zip(domain.fft(&y))
                        .map(|(i, j)| i * j)
                        .collect::<Vec<_>>(),
                )
                .into_iter()
                .zip(
                    domain.ifft(
                        &domain
                            .fft(&xx)
                            .into_iter()
                            .zip(domain.fft(&yy))
                            .map(|(i, j)| i * j * quot_domain.group_gen_inv)
                            .collect::<Vec<_>>(),
                    ),
                )
                .map(|(i, j)| vec![i, j])
                .flatten()
                .map(|i| i * domain.size_as_field_element * quot_domain.size_inv)
                .collect::<Vec<_>>()
        );

        println!(
            "{:?}",
            quot_domain
                .ifft(&x_evals.into_iter().zip(y_evals).map(|(a, b)| a * b).collect::<Vec<_>>())
        );

        println!("{:?}", &x * &y);
    }

    #[test]
    fn test_gpu_msm() {
        use std::{cmp::min, time::Instant};

        use ark_bls12_381::G1Projective;
        use ark_ec::msm::VariableBaseMSM;
        use ark_ff::{PrimeField, UniformRand};
        use rand::thread_rng;

        use crate::gpu::KERNELS;

        let kernel = KERNELS[0].lock().unwrap();

        let rng = &mut thread_rng();

        let l = 1 << 25;

        let mut bases =
            (0..min(l, 1 << 11)).map(|_| G1Projective::rand(rng).into()).collect::<Vec<_>>();

        while bases.len() < l {
            bases.append(&mut bases.clone());
        }

        bases.push(G1Projective::rand(rng).into());
        bases.push(G1Projective::rand(rng).into());

        let exps = (0..l).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let exps_repr = exps.iter().map(|i| i.into_repr()).collect::<Vec<_>>();

        let now = Instant::now();
        let s = VariableBaseMSM::multi_scalar_mul(&bases, &exps_repr);
        println!("cpu: {:?}", now.elapsed());

        let now = Instant::now();
        let r = kernel.multiexp(&bases, &exps);
        println!("gpu: {:?}", now.elapsed());

        assert_eq!(s, r);

        let now = Instant::now();
        let r = kernel.multiexp(&bases[..l / 2], &exps[..l / 2])
            + kernel.multiexp(&bases[l / 2..], &exps[l / 2..]);
        println!("gpu2: {:?}", now.elapsed());

        assert_eq!(s, r);

        let now = Instant::now();
        let r = kernel.multiexp(&bases[..l / 4], &exps[..l / 4])
            + kernel.multiexp(&bases[l / 4..l / 2], &exps[l / 4..l / 2])
            + kernel.multiexp(&bases[l / 2..3 * l / 4], &exps[l / 2..3 * l / 4])
            + kernel.multiexp(&bases[3 * l / 4..], &exps[3 * l / 4..]);
        println!("gpu3: {:?}", now.elapsed());

        assert_eq!(s, r);
    }

    #[test]
    fn test_gpu_fft() {
        use std::time::Instant;

        use ark_ff::UniformRand;
        use rand::thread_rng;
        use rayon::prelude::{
            IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
        };

        use crate::{gpu::KERNELS, transpose::ip_transpose};

        let kernel = KERNELS[0].lock().unwrap();

        let rng = &mut thread_rng();

        let l = 1 << 20;

        let domain = Radix2EvaluationDomain::<Fr>::new(l).unwrap();

        let mut v = (0..1 << 10).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        while v.len() < l {
            v.extend_from_within(..);
        }
        let group_elems = domain.elements().collect::<Vec<_>>();

        assert_eq!(
            {
                let r = 1 << (domain.log_size_of_group >> 1);
                let c = domain.size() / r;
                let r_domain = Radix2EvaluationDomain::<Fr>::new(r).unwrap();
                let c_domain = Radix2EvaluationDomain::<Fr>::new(c).unwrap();

                let e = c_domain.elements().collect::<Vec<_>>();
                let f = r_domain.elements().collect::<Vec<_>>();

                let mut v = v.clone();
                v.resize(domain.size(), Default::default());
                let mut t = vec![Default::default(); l >> 2];
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, c, r);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                kernel.batch_fft_precomputed(&mut v, &e, r, false);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                v.par_iter_mut()
                    .enumerate()
                    .for_each(|(i, u)| *u *= group_elems[(i & (c - 1)) * (i / c)]);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, r, c);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                kernel.batch_fft_precomputed(&mut v, &f, c, false);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, c, r);
                println!("{:?}", now.elapsed());
                v
            },
            domain.fft(&v)
        );
        println!("");

        assert_eq!(
            {
                let r = 1 << (domain.log_size_of_group >> 1);
                let c = domain.size() / r;
                let r_domain = Radix2EvaluationDomain::<Fr>::new(r).unwrap();
                let c_domain = Radix2EvaluationDomain::<Fr>::new(c).unwrap();

                let e = c_domain.elements().collect::<Vec<_>>();
                let f = r_domain.elements().collect::<Vec<_>>();

                let mut v = v.clone();
                v.resize(domain.size(), Default::default());
                let mut t = vec![Default::default(); l >> 2];
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, c, r);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                kernel.batch_fft_precomputed(&mut v, &e, r, true);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                v.par_iter_mut().enumerate().for_each(|(i, u)| {
                    let j = (i & (c - 1)) * (i / c);
                    if j != 0 {
                        *u *= group_elems[l - j];
                    }
                });
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, r, c);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                kernel.batch_fft_precomputed(&mut v, &f, c, true);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, c, r);
                println!("{:?}", now.elapsed());
                v
            },
            domain.ifft(&v)
        );
        println!("");

        assert_eq!(
            {
                let r = 1 << (domain.log_size_of_group >> 1);
                let c = domain.size() / r;
                let r_domain = Radix2EvaluationDomain::<Fr>::new(r).unwrap();
                let c_domain = Radix2EvaluationDomain::<Fr>::new(c).unwrap();

                let e = c_domain.elements().collect::<Vec<_>>();
                let f = r_domain.elements().collect::<Vec<_>>();

                let mut v = v.clone();
                v.resize(domain.size(), Default::default());
                let mut t = vec![Default::default(); l >> 2];
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, c, r);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                v.chunks_mut(c).for_each(|group| {
                    // group.copy_from_slice(&c_domain.fft(group));
                    kernel.fft_precomputed(group, &e, false);
                });
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                v.par_iter_mut()
                    .enumerate()
                    .for_each(|(i, u)| *u *= group_elems[(i & (c - 1)) * (i / c)]);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, r, c);
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                v.chunks_mut(r).for_each(|group| {
                    kernel.fft_precomputed(group, &f, false);
                    // group.copy_from_slice(&r_domain.fft(group));
                });
                println!("{:?}", now.elapsed());
                let now = Instant::now();
                ip_transpose(&mut v, &mut t, c, r);
                println!("{:?}", now.elapsed());
                v
            },
            domain.fft(&v)
        );

        {
            let now = Instant::now();
            domain.fft_in_place(&mut v);
            println!("{:?}", now.elapsed());
        }
        {
            domain.fft(&v);
            let mut r = v.clone();
            kernel.fft(&mut r, &domain.group_gen, false);
        }

        {
            let now = Instant::now();
            let s = domain.fft(&v);
            println!("cpu: {:?}", now.elapsed());

            let now = Instant::now();
            let mut r = v.clone();
            kernel.fft_precomputed(&mut r, &group_elems, false);
            println!("gpu: {:?}", now.elapsed());

            assert_eq!(s, r);
        }

        {
            let now = Instant::now();
            let s = domain.ifft(&v);
            println!("cpu: {:?}", now.elapsed());

            let now = Instant::now();
            let mut r = v.clone();
            kernel.fft_precomputed(&mut r, &group_elems, true);
            println!("gpu: {:?}", now.elapsed());

            assert_eq!(s, r);
        }

        {
            let now = Instant::now();
            let s = domain.coset_fft(&v);
            println!("cpu: {:?}", now.elapsed());

            let now = Instant::now();
            let mut r = v.clone();
            Radix2EvaluationDomain::distribute_powers(&mut r, Fr::multiplicative_generator());
            kernel.fft_precomputed(&mut r, &group_elems, false);
            println!("gpu: {:?}", now.elapsed());

            assert_eq!(s, r);
        }

        {
            let now = Instant::now();
            let s = domain.coset_ifft(&v);
            println!("cpu: {:?}", now.elapsed());

            let now = Instant::now();
            let mut r = v.clone();
            kernel.fft_precomputed(&mut r, &group_elems, true);
            Radix2EvaluationDomain::distribute_powers(&mut r, domain.generator_inv);
            println!("gpu: {:?}", now.elapsed());

            assert_eq!(s, r);
        }
    }

    #[test]
    fn test_gpu_large_fft() {
        use std::time::Instant;

        use ark_ff::UniformRand;
        use rand::thread_rng;

        let l = 1 << 28;

        let file = File::create("mmap1").unwrap();
        file.set_len(32 * l as u64).unwrap();
        let file = File::create("mmap2").unwrap();
        file.set_len(32 * l as u64).unwrap();

        let mut v1 = unsafe {
            MutMmap::<Fr>::map(&OpenOptions::new().read(true).write(true).open("mmap1").unwrap())
                .unwrap()
        };
        let mut v2 = unsafe {
            MutMmap::<Fr>::map(&OpenOptions::new().read(true).write(true).open("mmap2").unwrap())
                .unwrap()
        };

        let rng = &mut thread_rng();

        let mut k = 1 << 10;
        v1[..k].copy_from_slice(&(0..k).map(|_| Fr::rand(rng)).collect::<Vec<_>>());
        while k < l {
            v1.copy_within(0..k, k);
            k <<= 1;
        }
        v2.copy_from_slice(&v1);

        let domain = Domain::new(l);

        let now = Instant::now();
        domain.fft_io(&mut v1);
        println!("{:?}", now.elapsed());

        let now = Instant::now();
        fft_helper_in_place(&mut v2, domain.generator());
        println!("{:?}", now.elapsed());
    }

    #[test]
    fn test_gpu_large_ifft() {
        use std::time::Instant;

        use ark_ff::UniformRand;
        use rand::thread_rng;

        let l = 1 << 28;

        let file = File::create("mmap1").unwrap();
        file.set_len(32 * l as u64).unwrap();
        let file = File::create("mmap2").unwrap();
        file.set_len(32 * l as u64).unwrap();

        let mut v1 = unsafe {
            MutMmap::<Fr>::map(&OpenOptions::new().read(true).write(true).open("mmap1").unwrap())
                .unwrap()
        };
        let mut v2 = unsafe {
            MutMmap::<Fr>::map(&OpenOptions::new().read(true).write(true).open("mmap2").unwrap())
                .unwrap()
        };

        let rng = &mut thread_rng();

        let mut k = 1 << 10;
        v1[..k].copy_from_slice(&(0..k).map(|_| Fr::rand(rng)).collect::<Vec<_>>());
        while k < l {
            v1.copy_within(0..k, k);
            k <<= 1;
        }
        v2.copy_from_slice(&v1);

        let domain = Domain::new(l);

        let now = Instant::now();
        domain.ifft_oi(&mut v1);
        println!("{:?}", now.elapsed());

        let now = Instant::now();
        ifft_helper_in_place(&mut v2, domain.generator_inv());
        println!("{:?}", now.elapsed());
    }

    #[test]
    fn test_transpose() {
        let rng = &mut thread_rng();

        let d = 27;
        let l = 1 << d;

        let file = File::create("mmap1").unwrap();
        file.set_len(32 * l as u64).unwrap();
        let file = File::create("mmap2").unwrap();
        file.set_len(32 * l as u64).unwrap();

        let mut v_file = unsafe {
            MutMmap::<Fr>::map(&OpenOptions::new().read(true).write(true).open("mmap1").unwrap())
                .unwrap()
        };
        let mut w_file = unsafe {
            MutMmap::<Fr>::map(&OpenOptions::new().read(true).write(true).open("mmap2").unwrap())
                .unwrap()
        };

        let mut v_mem = (0..1 << 10).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        while v_mem.len() < l {
            v_mem.extend_from_within(..);
        }
        let mut w_mem = vec![Default::default(); l];

        v_file.copy_from_slice(&v_mem);
        let mut t = vec![Default::default(); l >> 2];

        let now = Instant::now();
        ip_transpose(&mut v_mem, &mut t, 1 << (d / 2), l >> (d / 2));
        println!("memory-memory, in-place {:?}", now.elapsed());

        let now = Instant::now();
        oop_transpose(&v_mem, &mut w_mem, 1 << (d / 2), l >> (d / 2));
        println!("memory-memory, out-of-place {:?}", now.elapsed());

        let now = Instant::now();
        ip_transpose(&mut v_file, &mut t, 1 << (d / 2), l >> (d / 2));
        println!("file-file, in-place {:?}", now.elapsed());

        let now = Instant::now();
        oop_transpose(&v_file, &mut w_file, 1 << (d / 2), l >> (d / 2));
        println!("file-file, out-of-place {:?}", now.elapsed());

        let now = Instant::now();
        oop_transpose(&v_file, &mut w_mem, 1 << (d / 2), l >> (d / 2));
        println!("file-memory, out-of-place {:?}", now.elapsed());

        let now = Instant::now();
        oop_transpose(&v_mem, &mut w_file, 1 << (d / 2), l >> (d / 2));
        println!("memory-file, out-of-place {:?}", now.elapsed());
    }

    #[test]
    fn test_mul() {
        let rng = &mut thread_rng();
        let n = 1u64 << 31;

        let w = {
            let w = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            BufWriter::new(File::create("tmp").unwrap()).write_all(w.cast()).unwrap();
            unsafe { Mmap::<Fr>::map(&File::open("tmp").unwrap()).unwrap() }
        };
        let mut u = {
            let w = (0..n).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            w
        };
        u.par_iter_mut().zip_eq(w.par_iter()).for_each(|(u, w)| {
            *u *= w;
        });
    }
}
