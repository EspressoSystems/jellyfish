// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.
// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Utilities for parallel code.

/// this function helps with slice iterator creation that optionally use
/// `par_iter()` when feature flag `parallel` is on.
///
/// # Usage
/// let v = [1, 2, 3, 4, 5];
/// let sum = parallelizable_slice_iter(&v).sum();
///
/// // the above code is a shorthand for (thus equivalent to)
/// #[cfg(feature = "parallel")]
/// let sum = v.par_iter().sum();
/// #[cfg(not(feature = "parallel"))]
/// let sum = v.iter().sum();
#[cfg(feature = "parallel")]
pub fn parallelizable_slice_iter<T: Sync>(data: &[T]) -> rayon::slice::Iter<T> {
    use rayon::iter::IntoParallelIterator;
    data.into_par_iter()
}

#[cfg(not(feature = "parallel"))]
pub fn parallelizable_slice_iter<T>(data: &[T]) -> ark_std::slice::Iter<T> {
    data.iter()
}
