// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.
//! Instantiation of the hash chain delay function.

use crate::{VDFError, VDF};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use sha3::Digest;

/// Glorified bool type
type VerificationResult = Result<(), ()>;

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
    Serialize,
    Deserialize,
)]
/// Public parameter for MinRoot DF,
pub struct HashChainParam {
    /// Indicates the number of iterations
    pub difficulty: u64,
}

#[derive(Copy, Debug, Clone)]
/// Dummy struct for MinRoot delay function.
pub struct HashChain;

impl VDF for HashChain {
    type PublicParameter = HashChainParam;
    type Proof = [u8; 32];
    type Input = [u8; 32];
    type Output = [u8; 32];

    fn setup<R: ark_std::rand::CryptoRng + ark_std::rand::RngCore>(
        difficulty: u64,
        prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, VDFError> {
        Ok(HashChainParam { difficulty })
    }

    fn eval(
        pp: &Self::PublicParameter,
        input: &Self::Input,
    ) -> Result<(Self::Output, Self::Proof), VDFError> {
        let mut output = *input;
        for _ in 0..pp.difficulty {
            output = sha3::Keccak256::digest(&output).into();
        }
        Ok((output, output))
    }

    fn verify(
        _pp: &Self::PublicParameter,
        _input: &Self::Input,
        output: &Self::Output,
        proof: &Self::Proof,
    ) -> Result<crate::VerificationResult, VDFError> {
        Ok(if output == proof { Ok(()) } else { Err(()) })
    }
}

#[cfg(test)]
mod test {
    use crate::{hashchain::HashChain, VDF};
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn test_hashchain() {
        let start = [0u8; 32];
        let pp = HashChain::setup::<StdRng>(100, None).unwrap();
        let (output, proof) = HashChain::eval(&pp, &start).unwrap();
        assert_eq!(output, proof);
        assert!(HashChain::verify(&pp, &start, &output, &proof)
            .unwrap()
            .is_ok());
    }
}
