use std::{cmp::min, time::Instant};

use ark_bls12_381::{g1::G1Projective, Fr};
use ark_ec::{msm::VariableBaseMSM, ProjectiveCurve};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::{rand::thread_rng, UniformRand};

#[cfg(feature = "gpu")]
use crate::gpu::{threadpool::Worker, MultiKernel};

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

#[cfg(feature = "gpu")]
#[test]
fn test_gpu_msm() {
    let mut kernels = MultiKernel::create(include_bytes!("./gpu/cl/lib.fatbin"));

    let pool = Worker::new();

    let rng = &mut thread_rng();

    let l = 1 << 27;

    let mut bases =
        (0..min(l, 1 << 11)).map(|_| G1Projective::rand(rng).into()).collect::<Vec<_>>();

    while bases.len() < l {
        bases.append(&mut bases.clone());
    }

    let exps = (0..l).map(|_| Fr::rand(rng).into_repr()).collect::<Vec<_>>();

    let now = Instant::now();
    let s = VariableBaseMSM::multi_scalar_mul(&bases, &exps);
    println!("cpu: {:?}", now.elapsed());

    let now = Instant::now();
    let r = kernels.multiexp(&pool, &bases, &exps, 0);
    println!("gpu: {:?}", now.elapsed());

    assert_eq!(s, r);

    let now = Instant::now();
    let r = kernels.multiexp(&pool, &bases[..l / 2], &exps[..l / 2], 0)
        + kernels.multiexp(&pool, &bases[l / 2..], &exps[l / 2..], 0);
    println!("gpu2: {:?}", now.elapsed());

    assert_eq!(s, r);

    let now = Instant::now();
    let r = kernels.multiexp(&pool, &bases[..l / 4], &exps[..l / 4], 0)
        + kernels.multiexp(&pool, &bases[l / 4..l / 2], &exps[l / 4..l / 2], 0)
        + kernels.multiexp(&pool, &bases[l / 2..3 * l / 4], &exps[l / 2..3 * l / 4], 0)
        + kernels.multiexp(&pool, &bases[3 * l / 4..], &exps[3 * l / 4..], 0);
    println!("gpu3: {:?}", now.elapsed());

    assert_eq!(s, r);
}

#[cfg(feature = "gpu")]
#[test]
fn test_gpu_fft() {
    let mut kernels = MultiKernel::create(include_bytes!("./gpu/cl/lib.fatbin"));

    let rng = &mut thread_rng();

    let l = 1 << 27;

    let domain = Radix2EvaluationDomain::<Fr>::new(l).unwrap();

    let exps = (0..l).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    {
        domain.fft(&exps);
        let mut r = exps.clone();
        kernels.radix_fft(&mut r, &domain.group_gen, domain.log_size_of_group);
    }

    {
        let now = Instant::now();
        let s = domain.fft(&exps);
        println!("cpu: {:?}", now.elapsed());

        let now = Instant::now();
        let mut r = exps.clone();
        kernels.radix_fft(&mut r, &domain.group_gen, domain.log_size_of_group);
        println!("gpu: {:?}", now.elapsed());

        assert_eq!(s, r);
    }

    {
        let now = Instant::now();
        let s = domain.ifft(&exps);
        println!("cpu: {:?}", now.elapsed());

        let now = Instant::now();
        let mut r = exps.clone();
        kernels.radix_fft(&mut r, &domain.group_gen_inv, domain.log_size_of_group);
        r.iter_mut().for_each(|val| *val *= domain.size_inv);
        println!("gpu: {:?}", now.elapsed());

        assert_eq!(s, r);
    }

    {
        let now = Instant::now();
        let s = domain.coset_fft(&exps);
        println!("cpu: {:?}", now.elapsed());

        let now = Instant::now();
        let mut r = exps.clone();
        Radix2EvaluationDomain::distribute_powers(&mut r, Fr::multiplicative_generator());
        kernels.radix_fft(&mut r, &domain.group_gen, domain.log_size_of_group);
        println!("gpu: {:?}", now.elapsed());

        assert_eq!(s, r);
    }

    {
        let now = Instant::now();
        let s = domain.coset_ifft(&exps);
        println!("cpu: {:?}", now.elapsed());

        let now = Instant::now();
        let mut r = exps.clone();
        kernels.radix_fft(&mut r, &domain.group_gen_inv, domain.log_size_of_group);
        r.iter_mut().for_each(|val| *val *= domain.size_inv);
        Radix2EvaluationDomain::distribute_powers(
            &mut r,
            Fr::multiplicative_generator().inverse().unwrap(),
        );
        println!("gpu: {:?}", now.elapsed());

        assert_eq!(s, r);
    }
}
