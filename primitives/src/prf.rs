// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! This module implements a pseudo random function that is derived from
//! the rescue hash function.

use crate::{
    errors::PrimitivesError,
    rescue::{sponge::RescuePRFCore, RescueParameter},
};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    UniformRand,
};

/// Trait for Pseudo-random Functions
pub trait PRF {
    // TODO: (alex) add `CanonicalDeserialize` to `Input`, `CanonicalSerialize` to
    // `Output`, both to `Seed`, when we move to arkworks 0.4.0
    /// Input to the PRF
    type Input: Clone;
    /// Output of the PRF
    type Output: Clone + Debug + PartialEq + Eq;
    /// The random seed/key that index a specific function from the PRF
    /// ensembles
    type Seed: Clone + Debug + Default + UniformRand;

    /// Compute PRF output with a user-provided randomly generated `seed`
    fn evaluate<S: Borrow<Self::Seed>, I: Borrow<Self::Input>>(
        seed: S,
        input: I,
    ) -> Result<Self::Output, PrimitivesError>;

    /// same as [`Self::evaluate`] except that we generate a fresh random seed
    /// for the evaluation
    fn evaluate_with_rand_seed<R: RngCore + CryptoRng, T: Borrow<Self::Input>>(
        rng: &mut R,
        input: T,
    ) -> Result<(Self::Seed, Self::Output), PrimitivesError> {
        let seed = Self::Seed::rand(rng);
        let output = Self::evaluate(&seed, input)?;
        Ok((seed, output))
    }
}

#[derive(Debug, Clone)]
/// A rescue-based PRF that leverages on Full State Keyed (FSK) sponge
/// construction
pub struct RescuePRF<F: RescueParameter, const INPUT_LEN: usize, const OUTPUT_LEN: usize>(
    PhantomData<F>,
);

impl<F: RescueParameter, const INPUT_LEN: usize, const OUTPUT_LEN: usize> PRF
    for RescuePRF<F, INPUT_LEN, OUTPUT_LEN>
{
    type Input = [F; INPUT_LEN];
    type Output = [F; OUTPUT_LEN];
    type Seed = F;

    fn evaluate<S: Borrow<Self::Seed>, I: Borrow<Self::Input>>(
        seed: S,
        input: I,
    ) -> Result<Self::Output, PrimitivesError> {
        let mut output = [F::zero(); OUTPUT_LEN];
        output.clone_from_slice(&RescuePRFCore::full_state_keyed_sponge_with_zero_padding(
            seed.borrow(),
            input.borrow(),
            OUTPUT_LEN,
        )?);
        Ok(output)
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        prf::{RescuePRF, PRF},
        rescue::sponge::RescuePRFCore,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as FqEd377;
    use ark_ed_on_bls12_381::Fq as FqEd381;
    use ark_ed_on_bn254::Fq as FqEd254;
    use ark_std::UniformRand;
    macro_rules! test_prf {
        ($tr:tt) => {
            let mut rng = jf_utils::test_rng();
            let seed = $tr::rand(&mut rng);
            let input = [$tr::from(1u8)];

            assert!(RescuePRF::<$tr, 1, 15>::evaluate(&seed, &input).is_ok());
            // check correctness
            assert_eq!(
                RescuePRF::<$tr, 1, 15>::evaluate(&seed, &input)
                    .unwrap()
                    .to_vec(),
                RescuePRFCore::full_state_keyed_sponge_with_zero_padding(&seed, &input, 15)
                    .unwrap()
            );
        };
    }

    #[test]
    pub fn test_prf() {
        test_prf!(FqEd254);
        test_prf!(FqEd377);
        test_prf!(FqEd381);
        test_prf!(Fq377);
    }
}
