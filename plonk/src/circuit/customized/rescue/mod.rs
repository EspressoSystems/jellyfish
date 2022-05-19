// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Rescue hash related gates and gadgets. Including both native and non-native
//! fields.

mod native;
pub use native::{RescueGadget, RescueStateVar};
