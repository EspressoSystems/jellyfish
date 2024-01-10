// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Provides sample instantiations of merkle tree.
//! E.g. Sparse merkle tree with BigUInt index.

use super::{append_only::MerkleTree, prelude::RescueHash, DigestAlgorithm};
use crate::{
    errors::PrimitivesError,
    rescue::{sponge::RescueCRHF, RescueParameter},
};
use ark_ff::Field;
use typenum::U3;

/// Element type for interval merkle tree
#[derive(PartialEq, Eq, Copy, Clone, Hash)]
pub struct Interval<F: Field>(pub F, pub F);
// impl<F: Field> Element for Interval<F> {}

impl<F: RescueParameter> DigestAlgorithm<Interval<F>, u64, F> for RescueHash<F> {
    fn digest(data: &[F]) -> Result<F, PrimitivesError> {
        Ok(RescueCRHF::<F>::sponge_no_padding(data, 1)?[0])
    }

    fn digest_leaf(pos: &u64, elem: &Interval<F>) -> Result<F, PrimitivesError> {
        let data = [F::from(*pos), elem.0, elem.1];
        Ok(RescueCRHF::<F>::sponge_no_padding(&data, 1)?[0])
    }
}

/// Interval merkle tree instantiation for interval merkle tree using Rescue
/// hash function.
pub type IntervalMerkleTree<F> = MerkleTree<Interval<F>, RescueHash<F>, u64, U3, F>;
