// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Implementation of [`Namespacer`] for [`Advz`].

use super::{
    AffineRepr, Debug, DenseUVPolynomial, Digest, DynDigest, GenericAdvz, MerkleTreeScheme,
    PolynomialCommitmentScheme, PrimeField, UnivariatePCS, Vec, Write,
};
use crate::vid::namespace::Namespacer;

impl<P, T, H, V> Namespacer for GenericAdvz<P, T, H, V>
where
    // TODO ugly trait bounds https://github.com/EspressoSystems/jellyfish/issues/253
    P: UnivariatePCS<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Evaluation: PrimeField,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
    H: Digest + DynDigest + Default + Clone + Write,
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug,
    V::Index: From<u64>,
{
    type DataProof = ();

    fn data_proof(
        &self,
        _payload: &Self::Payload,
        _start: usize,
        _len: usize,
    ) -> crate::vid::VidResult<Self::DataProof> {
        todo!()
    }

    fn data_verify(
        &self,
        _payload: &Self::Payload,
        _start: usize,
        _len: usize,
        _proof: Self::DataProof,
    ) -> crate::vid::VidResult<Result<(), ()>> {
        todo!()
    }

    fn namespace_verify(
        &self,
        _payload: &Self::Payload,
        _namespace_index: usize,
        _commit: &Self::Commit,
        _common: &Self::Common,
    ) -> crate::vid::VidResult<Result<(), ()>> {
        todo!()
    }
}
