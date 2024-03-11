// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Crate implements various cryptography primitives, as
//! well as the plonk circuit implementation of those primitives.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(warnings)]
#![deny(missing_docs)]
#[cfg(test)]
extern crate std;

#[macro_use]
extern crate derivative;

#[cfg(any(not(feature = "std"), target_has_atomic = "ptr"))]
#[doc(hidden)]
extern crate alloc;

pub mod aead;
pub mod circuit;
pub mod commitment;
pub mod constants;
pub mod crhf;
pub mod elgamal;
pub mod errors;
pub mod hash_to_group;
pub mod merkle_tree;
pub mod pcs;
pub mod prf;
pub mod reed_solomon_code;
pub mod rescue;
pub mod signatures;
pub mod toeplitz;
pub mod vdf;
pub mod vid;
pub mod vrf;

/// dependencies required for ICICLE-related code, group import for convenience
#[cfg(feature = "icicle")]
pub mod icicle_deps {
    pub use icicle_core::{
        curve::{Affine as IcicleAffine, Curve as IcicleCurve, Projective as IcicleProjective},
        msm::{MSMConfig, MSM},
        traits::{ArkConvertible, FieldImpl},
    };
    pub use icicle_cuda_runtime::{memory::HostOrDeviceSlice, stream::CudaStream};

    /// curve-specific types both from arkworks and from ICICLE
    /// including Pairing, CurveCfg, Fr, Fq etc.
    pub mod curves {
        pub use ark_bls12_381::Bls12_381;
        pub use ark_bn254::Bn254;
        pub use icicle_bls12_381::curve::CurveCfg as IcicleBls12_381;
        pub use icicle_bn254::curve::CurveCfg as IcicleBn254;
    }

    pub use crate::pcs::univariate_kzg::icicle::GPUCommit;

    // TODO: remove this after `warmup()` is added upstream
    // https://github.com/ingonyama-zk/icicle/pull/422#issuecomment-1980881638
    /// Create a new stream and warmup
    pub fn warmup_new_stream() -> Result<CudaStream, ()> {
        let stream = CudaStream::create().unwrap();
        // TODO: consider using an error type?
        let _warmup_bytes = HostOrDeviceSlice::<'_, u8>::cuda_malloc_async(1024, &stream).unwrap();
        Ok(stream)
    }
}

pub(crate) mod utils;
