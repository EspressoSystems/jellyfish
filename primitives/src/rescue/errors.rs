// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Error types.

// using `displaydoc` instead of `thiserror`, see
// https://github.com/dtolnay/thiserror/pull/64#issuecomment-735805334
// `thiserror` does not support #![no_std]

use ark_std::string::String;
use displaydoc::Display;

/// Various error modes.
#[derive(Debug, Display, Eq, PartialEq)]
pub enum RescueError {
    /// Bad parameter in function call, {0}
    ParameterError(String),
}
