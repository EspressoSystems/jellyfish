// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Helper functions for circuit gadgets implementation

use crate::errors::CircuitError;
use ark_std::{cmp::Ordering, string::ToString};

// helper function to find the next multiple of `divisor` for `current` value
pub(crate) fn next_multiple(current: usize, divisor: usize) -> Result<usize, CircuitError> {
    if divisor == 0 || divisor == 1 {
        return Err(CircuitError::InternalError(
            "can only be a multiple of divisor >= 2".to_string(),
        ));
    }
    match current.cmp(&divisor) {
        Ordering::Equal => Ok(current),
        Ordering::Less => Ok(divisor),
        Ordering::Greater => Ok((current / divisor + 1) * divisor),
    }
}

#[cfg(test)]
mod test {
    use super::next_multiple;
    use crate::errors::CircuitError;

    #[test]
    fn test_helper_next_multiple() -> Result<(), CircuitError> {
        assert!(next_multiple(5, 0).is_err());
        assert!(next_multiple(5, 1).is_err());

        assert_eq!(next_multiple(5, 2)?, 6);
        assert_eq!(next_multiple(5, 3)?, 6);
        assert_eq!(next_multiple(5, 4)?, 8);
        assert_eq!(next_multiple(5, 5)?, 5);
        assert_eq!(next_multiple(5, 11)?, 11);
        Ok(())
    }
}
