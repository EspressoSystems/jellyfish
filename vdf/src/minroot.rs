// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.
//! Instantiation of the MinRoot Delay function <https://eprint.iacr.org/2022/1626.pdf>.

use crate::{VDFError, VDF};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use core::marker::PhantomData;
use jf_traits::VerificationResult;

/// MinRoot compatible field
pub trait MinRootField: PrimeField {
    /// The MinRoot iteration is calculating the cubic root (or fifth-root if
    /// modulus % 3 == 1) of a field element. E.g. `EXP_COEF` should be (2 *
    /// modulus - 1) / 3 if modulus % 3 != 1.
    const EXP_COEF: Self::BigInt;
}

#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    CanonicalSerialize,
    CanonicalDeserialize,
)]

/// Public parameter for MinRoot DF,
pub struct MinRootPP {
    /// Indicates the number of iterations
    pub difficulty: u64,
}

/// A minroot element consists of a pair of field elements.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct MinRootElement<F: MinRootField>(F, F);

impl<F, T> From<T> for MinRootElement<F>
where
    T: AffineRepr<BaseField = F>,
    F: MinRootField,
{
    fn from(value: T) -> Self {
        let (x, y) = value.xy().unwrap();
        MinRootElement(*x, *y)
    }
}

/// Dummy struct for MinRoot delay function.
pub struct MinRoot<F: MinRootField> {
    _phantom: PhantomData<F>,
}

impl<F: MinRootField> VDF for MinRoot<F> {
    type PublicParameter = MinRootPP;
    type Proof = MinRootElement<F>;
    type Input = MinRootElement<F>;
    type Output = MinRootElement<F>;

    fn setup<R: ark_std::rand::CryptoRng + ark_std::rand::RngCore>(
        difficulty: u64,
        _prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, VDFError> {
        Ok(MinRootPP { difficulty })
    }

    fn eval(
        pp: &Self::PublicParameter,
        input: &Self::Input,
    ) -> Result<(Self::Output, Self::Proof), VDFError> {
        let mut output = *input;
        for i in 0..pp.difficulty {
            Self::iterate_in_place(&mut output, i)?;
        }
        Ok((output, output))
    }

    fn verify(
        _pp: &Self::PublicParameter,
        _input: &Self::Input,
        output: &Self::Output,
        proof: &Self::Proof,
    ) -> Result<VerificationResult, VDFError> {
        if proof == output {
            Ok(Ok(()))
        } else {
            Ok(Err(()))
        }
    }
}

impl<F: MinRootField> MinRoot<F> {
    #[inline]
    fn iterate_in_place(elem: &mut MinRootElement<F>, round: u64) -> Result<(), VDFError> {
        let x = elem.0;
        elem.0 = (x + elem.1).pow(F::EXP_COEF);
        // assert_eq!(elem.0.pow([5u64]), x + elem.1);
        elem.1 = x + F::from(round);
        Ok(())
    }
}

impl MinRootField for ark_bn254::Fr {
    // modulus 21888242871839275222246405745257275088548364400416034343698204186575808495617
    // modulus % 3 == 1, modulus % 5 == 2
    // coef = (4 * modulus - 3) / 5
    // coef: 17510594297471420177797124596205820070838691520332827474958563349260646796493
    const EXP_COEF: Self::BigInt = ark_ff::BigInt::<4>([
        14981214993055009997,
        6006880321387387405,
        10624953561019755799,
        2789598613442376532,
    ]);
}

impl MinRootField for ark_bls12_381::Fr {
    // modulus 52435875175126190479447740508185965837690552500527637822603658699938581184513
    // modulus % 3 == 1, modulus % 5 == 3
    // coef = (2 * modulus - 1) / 5
    // coef: 20974350070050476191779096203274386335076221000211055129041463479975432473805
    const EXP_COEF: Self::BigInt = ark_ff::BigInt::<4>([
        3689348813023923405,
        2413663763415232921,
        16233882818423549954,
        3341406743785779740,
    ]);
}

impl MinRootField for ark_pallas::Fr {
    // modulus 28948022309329048855892746252171976963363056481941647379679742748393362948097
    // modulus % 3 == 1, modulus % 5 == 2
    // coef = (4 * modulus - 3) / 5
    // coef: 23158417847463239084714197001737581570690445185553317903743794198714690358477
    const EXP_COEF: Self::BigInt = ark_ff::BigInt::<4>([
        15465117582000704717,
        5665212537877281354,
        3689348814741910323,
        3689348814741910323,
    ]);
}

#[cfg(test)]
mod test {
    use super::{MinRoot, MinRootElement, MinRootField};
    use crate::VDF;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn test_minroot() {
        test_minroot_helper::<ark_bn254::Fr>();
        test_minroot_helper::<ark_bls12_381::Fr>();
        test_minroot_helper::<ark_pallas::Fr>();
    }

    fn test_minroot_helper<F: MinRootField>() {
        let start = MinRootElement(F::one(), F::one());
        let pp = MinRoot::<F>::setup::<StdRng>(100, None).unwrap();
        let (output, proof) = MinRoot::<F>::eval(&pp, &start).unwrap();
        assert_eq!(output, proof);
        assert!(MinRoot::<F>::verify(&pp, &start, &output, &proof)
            .unwrap()
            .is_ok());
    }
}
