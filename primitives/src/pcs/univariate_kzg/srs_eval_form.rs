// Copyright (c) 2024 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Structured Reference Strings in evaluation form for univariate KZG

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::marker::PhantomData;

/// TODO: (alex) add links to protocol or write in code comment how eval form
/// srs works
#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct UnivariateUniversalParams<E: Pairing>(PhantomData<E>);
