// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Helper functions for circuit gadgets implementation

use crate::CircuitError;
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
    use crate::CircuitError;

    #[test]
    fn test_helper_next_multiple() -> Result<(), CircuitError> {
        // Test invalid divisors
        assert!(next_multiple(5, 0).is_err(), "Should fail for divisor 0");
        assert!(next_multiple(5, 1).is_err(), "Should fail for divisor 1");

        // Test when current equals divisor
        assert_eq!(next_multiple(2, 2)?, 2, "When current equals divisor, should return current");
        assert_eq!(next_multiple(3, 3)?, 3, "When current equals divisor, should return current");
        
        // Test when current is less than divisor
        assert_eq!(next_multiple(2, 3)?, 3, "When current < divisor, should return divisor");
        assert_eq!(next_multiple(4, 5)?, 5, "When current < divisor, should return divisor");
        
        // Test when current is greater than divisor
        assert_eq!(next_multiple(5, 2)?, 6, "Should return next multiple of 2");
        assert_eq!(next_multiple(5, 3)?, 6, "Should return next multiple of 3");
        assert_eq!(next_multiple(5, 4)?, 8, "Should return next multiple of 4");
        assert_eq!(next_multiple(7, 3)?, 9, "Should return next multiple of 3");
        assert_eq!(next_multiple(10, 7)?, 14, "Should return next multiple of 7");
        
        // Test edge cases with larger numbers
        assert_eq!(next_multiple(100, 30)?, 120, "Should handle larger numbers");
        assert_eq!(next_multiple(1000, 999)?, 1998, "Should handle numbers close to each other");
        
        // Test with maximum possible values that won't overflow
        assert_eq!(next_multiple(usize::MAX - 2, usize::MAX - 1)?, usize::MAX - 1, "Should handle large values safely");

        Ok(())
    }
}
