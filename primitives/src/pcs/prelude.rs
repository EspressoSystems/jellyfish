// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Prelude
pub use crate::pcs::{
    errors::PCSError,
    multilinear_kzg::{
        srs::{MultilinearProverParam, MultilinearUniversalParams, MultilinearVerifierParam},
        util::{compute_qx_degree, get_batched_nv, merge_polynomials},
        MultilinearKzgBatchProof, MultilinearKzgPCS, MultilinearKzgProof,
    },
    structs::Commitment,
    univariate_kzg::{
        srs::{UnivariateProverParam, UnivariateUniversalParams, UnivariateVerifierParam},
        UnivariateKzgBatchProof, UnivariateKzgPCS, UnivariateKzgProof,
    },
    PolynomialCommitmentScheme, StructuredReferenceString,
};
