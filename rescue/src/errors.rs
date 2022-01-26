//! Error types.

// using `displaydoc` instead of `thiserror`, see
// https://github.com/dtolnay/thiserror/pull/64#issuecomment-735805334
// `thiserror` does not support #![no_std]

use ark_std::string::String;
use displaydoc::Display;

/// Various error modes.
#[derive(Debug, Display)]
pub enum RescueError {
    /// Bad parameter in function call, {0}
    ParameterError(String),
}
