use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, BigInteger, PrimeField, Zero};

#[derive(Clone, Copy, Debug)]
pub struct BnAffinePoint(pub BigInt<4>, pub BigInt<4>);

pub fn wrap_g1affine(p: &G1Affine) -> BnAffinePoint {
    BnAffinePoint(p.x.into_bigint(), p.y.into_bigint())
}

pub fn unwrap_g1affine(p: &BnAffinePoint) -> G1Affine {
    G1Affine {
        x: p.0.into(),
        y: p.1.into(),
        infinity: false,
    }
}

pub fn msm(p: &[G1Affine], s: &[ScalarField]) -> G1Affine {
    let mut iter = p.iter().zip(s).filter(|(_, s)| !s.is_zero());
    let mut result = {
        let (p, s) = iter.next().unwrap();
        let mut p = wrap_g1affine(p);
        bn254_double_and_add(&mut p, s);
        p
    };
    iter.for_each(|(p, s)| {
        let mut p = wrap_g1affine(p);
        bn254_double_and_add(&mut p, s);
        bn254_add(&mut result, &p);
    });
    unwrap_g1affine(&result)
}

pub fn bn254_add(p: &mut BnAffinePoint, q: &BnAffinePoint) {
    sp1_zkvm::syscalls::syscall_bn254_add(
        p as *mut _ as *mut [u32; 16],
        q as *const _ as *const [u32; 16],
    );
}

pub fn bn254_double_and_add(p: &mut BnAffinePoint, s: &ScalarField) {
    let mut t = *p;
    let mut b = s.into_bigint().to_bits_le().into_iter();
    let mut q = {
        b.by_ref().take_while(|b| !b).for_each(|_| {
            sp1_zkvm::syscalls::syscall_bn254_double(&mut t as *mut _ as *mut [u32; 16]);
        });
        t
    };
    b.for_each(|b| {
        // double in place
        sp1_zkvm::syscalls::syscall_bn254_double(&mut t as *mut _ as *mut [u32; 16]);
        if b {
            sp1_zkvm::syscalls::syscall_bn254_add(
                &mut q as *mut _ as *mut [u32; 16],
                &t as *const _ as *const [u32; 16],
            );
        }
    });

    *p = q
}

pub type E = ark_bn254::Bn254;
pub type G1Affine = <E as Pairing>::G1Affine;
pub type ScalarField = <E as Pairing>::ScalarField;
