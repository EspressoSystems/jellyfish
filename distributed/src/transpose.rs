use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;

/// Block size of tiling transpose
const BLOCK_SIZE: usize = 16;

/// Size for simple transpose
const SIZE_SIMPLE: usize = 16 * 16;

/// Size for tile-based transpose
const SIZE_TILE: usize = 512 * 512;

/// Recusrive limit of recursive transpose
const RECURSION_LIMIT: usize = 128;

/// Out-of Place transpose
///
/// Uses simple transpose algorithm for small matrix sizes,
/// a loop blocking algorithm for medium matrices and
/// recursive cache oblivious algorithm for larger matrices.
///
/// # Arguments
///
/// * `src` - Flattened 2D array with rows * cols elements, input
/// * `dst` - Flattened 2D array with rows * cols elements, output
/// * `rows` - Number of rows
/// * `cols` - Number of cols
pub fn oop_transpose<T: Copy>(src: &[T], dst: &mut [T], rows: usize, cols: usize) {
    if rows * cols <= SIZE_SIMPLE {
        oop_transpose_small(src, dst, rows, cols);
    } else if rows * cols <= SIZE_TILE {
        oop_transpose_medium(src, dst, rows, cols, BLOCK_SIZE);
    } else {
        oop_transpose_large(src, dst, rows, cols, BLOCK_SIZE);
    }
}

/// Simple out-of-place transpose
///
/// # Arguments
///
/// * `src` - Flattened 2D array with rows * cols elements, input
/// * `dst` - Flattened 2D array with rows * cols elements, output
/// * `rows` - Number of rows
/// * `cols` - Number of cols
///
/// # Unsafe
///
/// src.len() and dst.len() must equal rows * cols
pub fn oop_transpose_small<T: Copy>(src: &[T], dst: &mut [T], rows: usize, cols: usize) {
    assert!(src.len() == rows * cols, "{} != {}", src.len(), rows * cols);
    assert!(dst.len() == rows * cols, "{} != {}", dst.len(), rows * cols);

    for r in 0..rows {
        for c in 0..cols {
            let i = c + r * cols;
            let j = r + c * rows;
            unsafe {
                *dst.get_unchecked_mut(j) = *src.get_unchecked(i);
            }
        }
    }
}

pub fn par_oop_transpose_small<T: Copy + std::marker::Sync + std::marker::Send>(
    src: &[T],
    dst: &mut [T],
    rows: usize,
    cols: usize,
) {
    assert!(src.len() == rows * cols, "{} != {}", src.len(), rows * cols);
    assert!(dst.len() == rows * cols, "{} != {}", dst.len(), rows * cols);
    dst.par_iter_mut().enumerate().for_each(|(j, d)| {
        let r = j % rows;
        let c = j / rows;
        let i = c + r * cols;
        unsafe {
            *d = *src.get_unchecked(i);
        }
    });
    // (0..cols).into_par_iter().for_each(|c| {
    //     for r in 0..rows {
    //         let i = c + r * cols;
    //         let j = r + c * rows;
    //         unsafe {
    //             *dst.get_unchecked_mut(j) = *src.get_unchecked(i);
    //         }
    //     }
    // });
}

/// Transpose with loop blocking optimzation #2
///
/// Splits rows and columns into blocks of size `block_size`.
/// This enhances cache locality of the transpose and is known als
/// loop blocking or tiling optimization.
///
/// # Arguments
///
/// * `src` - Flattened 2D array with rows * cols elements, input
/// * `dst` - Flattened 2D array with rows * cols elements, output
/// * `rows` - Number of rows
/// * `cols` - Number of cols
/// * `block_size` - Size of each block, its total length is `block_size` * `block_size`
///
/// # Unsafe
///
/// src.len() and dst.len() must equal rows * cols
pub fn oop_transpose_medium<T: Copy>(
    src: &[T],
    dst: &mut [T],
    rows: usize,
    cols: usize,
    block_size: usize,
) {
    assert!(src.len() == rows * cols, "{} != {}", src.len(), rows * cols);
    assert!(dst.len() == rows * cols, "{} != {}", dst.len(), rows * cols);
    // Number of blocks needed
    let block_rows = rows / block_size;
    let block_cols = cols / block_size;
    let remain_rows = rows - block_rows * block_size;
    let remain_cols = cols - block_cols * block_size;
    //
    // Loop over blocks
    //
    for block_col in 0..block_cols {
        for block_row in 0..block_rows {
            //
            // Loop over block entries
            //
            unsafe {
                transpose_tile(
                    src,
                    dst,
                    rows,
                    cols,
                    block_row * block_size,
                    block_col * block_size,
                    block_size,
                    block_size,
                );
            }
        }
    }

    //
    // Loop over remainders
    //
    if remain_cols > 0 {
        for block_row in 0..block_rows {
            unsafe {
                transpose_tile(
                    src,
                    dst,
                    rows,
                    cols,
                    block_row * block_size,
                    cols - remain_cols,
                    block_size,
                    remain_cols,
                );
            }
        }
    }

    if remain_rows > 0 {
        for block_col in 0..block_cols {
            unsafe {
                transpose_tile(
                    src,
                    dst,
                    rows,
                    cols,
                    rows - remain_rows,
                    block_col * block_size,
                    remain_rows,
                    block_size,
                );
            }
        }
    }

    if remain_cols > 0 && remain_rows > 0 {
        unsafe {
            transpose_tile(
                src,
                dst,
                rows,
                cols,
                rows - remain_rows,
                cols - remain_cols,
                remain_rows,
                remain_cols,
            );
        }
    }
}

/// Transpose a single sub-Tile
#[allow(clippy::too_many_arguments)]
unsafe fn transpose_tile<T: Copy>(
    src: &[T],
    dst: &mut [T],
    rows: usize,
    cols: usize,
    first_row: usize,
    first_col: usize,
    num_rows_per_block: usize,
    num_cols_per_block: usize,
) {
    for tile_col in 0..num_cols_per_block {
        for tile_row in 0..num_rows_per_block {
            let mat_row = first_row + tile_row;
            let mat_col = first_col + tile_col;
            let i = mat_col + mat_row * cols;
            let j = mat_row + mat_col * rows;
            *dst.get_unchecked_mut(j) = *src.get_unchecked(i);
        }
    }
}

/// Transpose based on recursion and loop-blocking
///
/// Divide matrix recursively into smaller submatrixes until number of rows
/// and columns falls below a treshold. These submatrices are
/// then transposed using the loop-blocking based approach, see [`transpose_tiling`].
///
/// # Arguments
///
/// * `src` - Flattened 2D array with rows * cols elements, input
/// * `dst` - Flattened 2D array with rows * cols elements, output
/// * `rows` - Number of rows
/// * `cols` - Number of cols
/// * `block_size` - Size of each block, its total length is `block_size` * `block_size`
///
/// # Unsafe
///
/// src.len() and dst.len() must equal rows * cols
pub fn oop_transpose_large<T: Copy>(
    src: &[T],
    dst: &mut [T],
    rows: usize,
    cols: usize,
    block_size: usize,
) {
    assert!(src.len() == rows * cols, "{} != {}", src.len(), rows * cols);
    assert!(dst.len() == rows * cols, "{} != {}", dst.len(), rows * cols);
    transpose_recursive(src, dst, 0, 0, rows, cols, rows, cols, block_size);
}

/// Transpose based on recursive division of rows and cols
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn transpose_recursive<T: Copy>(
    src: &[T],
    dst: &mut [T],
    first_row: usize,
    first_col: usize,
    num_rows: usize,
    num_cols: usize,
    total_rows: usize,
    total_cols: usize,
    block_size: usize,
) {
    if (num_rows <= RECURSION_LIMIT) & (num_cols < RECURSION_LIMIT) {
        // Number of blocks needed
        let block_rows = num_rows / block_size;
        let block_cols = num_cols / block_size;
        let remain_rows = num_rows - block_rows * block_size;
        let remain_cols = num_cols - block_cols * block_size;
        //
        // Loop over blocks
        //
        for block_col in 0..block_cols {
            for block_row in 0..block_rows {
                //
                // Loop over block entries
                //
                unsafe {
                    transpose_tile(
                        src,
                        dst,
                        total_rows,
                        total_cols,
                        block_row * block_size + first_row,
                        block_col * block_size + first_col,
                        block_size,
                        block_size,
                    );
                }
            }
        }

        //
        // Loop over remainders
        //
        if remain_cols > 0 {
            for block_row in 0..block_rows {
                unsafe {
                    transpose_tile(
                        src,
                        dst,
                        total_rows,
                        total_cols,
                        block_row * block_size + first_row,
                        num_cols - remain_cols + first_col,
                        block_size,
                        remain_cols,
                    );
                }
            }
        }

        if remain_rows > 0 {
            for block_col in 0..block_cols {
                unsafe {
                    transpose_tile(
                        src,
                        dst,
                        total_rows,
                        total_cols,
                        num_rows - remain_rows + first_row,
                        block_col * block_size + first_col,
                        remain_rows,
                        block_size,
                    );
                }
            }
        }

        if remain_cols > 0 && remain_rows > 0 {
            unsafe {
                transpose_tile(
                    src,
                    dst,
                    total_rows,
                    total_cols,
                    num_rows - remain_rows + first_row,
                    num_cols - remain_cols + first_col,
                    remain_rows,
                    remain_cols,
                );
            }
        }
    //
    // Subdivide rows
    //
    } else if num_rows >= num_cols {
        transpose_recursive(
            src,
            dst,
            first_row,
            first_col,
            num_rows / 2,
            num_cols,
            total_rows,
            total_cols,
            block_size,
        );
        transpose_recursive(
            src,
            dst,
            first_row + num_rows / 2,
            first_col,
            num_rows - num_rows / 2,
            num_cols,
            total_rows,
            total_cols,
            block_size,
        );
    //
    // Subdivide cols
    //
    } else {
        transpose_recursive(
            src,
            dst,
            first_row,
            first_col,
            num_rows,
            num_cols / 2,
            total_rows,
            total_cols,
            block_size,
        );
        transpose_recursive(
            src,
            dst,
            first_row,
            first_col + num_cols / 2,
            num_rows,
            num_cols - num_cols / 2,
            total_rows,
            total_cols,
            block_size,
        );
    }
}

/// In-Place transpose of square and rectangular matrices
///
/// The input array `src` is overwritten by its transpose.
/// A work-space must be provided with a minimum size of 2 and a maximum
/// size of `rows` * `cols` which is used internally for out-of-place transposes.
/// The larger the provided workspace, the more efficient the transpose should be.
///
///  # Parameters
///
/// * `a`: Matrix of size cols x rows, with cols <= rows
/// * `w`: work-space. Used for out-of-place transpose of submatrices.
/// * `rows`: Number of rows
/// * `cols`: Number of cols
pub fn ip_transpose<T: Copy>(src: &mut [T], w: &mut [T], rows: usize, cols: usize) {
    assert!(src.len() == rows * cols, "{} != {}", src.len(), rows * cols);
    let iw = w.len();
    if rows >= cols {
        row_transpose(src, cols, rows, w, iw);
    } else {
        column_transpose(src, cols, rows, w, iw);
    }
}

/// In-Place transpose of a square matrix
///
/// # Parameters
///
/// * src - Square matrix of size n x n
/// * n - Number of rows and cols
pub fn square_transpose<T: Copy>(src: &mut [T], n: usize) {
    assert!(src.len() == n * n, "{} != {}", src.len(), n * n);
    for c in 0..n - 1 {
        for r in c + 1..n {
            let i = r * n + c;
            let j = c * n + r;
            src.swap(i, j);
        }
    }
}

/// Exchange operation takes two contiguous vectors
/// of length p and q and reverses their order in-place:
/// a1 .. ap b1 .. bq
/// ->
/// b1 .. bq a1 .. ap
///
/// # Parameters
///
/// * v - Vector of length (p + q)
/// * p - Size of first vector a
/// * q - Size of second vector b
fn exchange<T: Copy>(v: &mut [T], p: usize, q: usize) {
    if p >= q {
        for i in 0..q {
            v.swap(i, i + p);
        }
        if p != q {
            exchange(&mut v[q..], p - q, q);
        }
    } else {
        for i in 0..p {
            v.swap(i, i + q);
        }
        exchange(&mut v[..q], p, q - p);
    }
}
/// Return largest power of 2 of *m*.
///
/// For example, returns 4 for *m*=7
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]
fn largest_power_of_two(m: usize) -> usize {
    2_usize.pow((m as f64 - 1.).log2() as u32)
}

/// Unshuffle pairs of shuffled vectors
///
/// # Parameters
///
/// * v - Vector of length (la + lb)m made up of m shuffled pairs of vectors
/// of length la and lb
///
/// # Reference
/// F. Gustavson and D. Walker - Algorithms for in-place matrix transposition (2018)
fn unshuffle<T: Copy>(v: &mut [T], la: usize, lb: usize, m: usize) {
    if m > 1 {
        let m1 = largest_power_of_two(m);
        unshuffle(v, la, lb, m1);
        unshuffle(&mut v[(la + lb) * m1..], la, lb, m - m1);
        if (la * (m - m1) > 0) & (lb * m1 > 0) {
            exchange(&mut v[la * m1..], lb * m1, la * (m - m1));
        }
    }
}

/// Shuffle pairs of unshuffled vectors
///
/// # Parameters
///
/// * v - Vector of length (la + lb)m made up of m shuffled pairs of vectors
/// of length la and lb
fn shuffle<T: Copy>(v: &mut [T], la: usize, lb: usize, m: usize) {
    if m > 1 {
        let m1 = largest_power_of_two(m);
        if (la * (m - m1) > 0) & (lb * m1 > 0) {
            exchange(&mut v[la * m1..], la * (m - m1), lb * m1);
        }
        shuffle(v, la, lb, m1);
        shuffle(&mut v[(la + lb) * m1..], la, lb, m - m1);
    }
}

/// Swap-Bases Matrix Transpose of Panel of Square Matrices
///
/// # Parameters
///
/// * a: Matrix A of size qn x n
fn partition<T: Copy>(a: &mut [T], q: usize, n: usize) {
    if q == 1 {
        square_transpose(&mut a[..n * n], n);
    } else {
        let q2 = q / 2;
        let q1 = q - q2;
        unshuffle(a, q1 * n, q2 * n, n);
        partition(a, q1, n);
        partition(&mut a[q1 * n * n..], q2, n);
    }
}

/// Swap-Bases Matrix Transpose of Panel of Square Matrices
///
/// # Parameters
///
/// * a: Matrix A of size n x qn
fn join<T: Copy>(a: &mut [T], q: usize, n: usize) {
    if q == 1 {
        square_transpose(&mut a[..n * n], n);
    } else {
        let q2 = q / 2;
        let q1 = q - q2;
        join(a, q1, n);
        join(&mut a[q1 * n * n..], q2, n);
        shuffle(a, q1 * n, q2 * n, n);
    }
}

///  In-Place Swap-Based Matrix Transpose
///
///  # Parameters
///
/// * `a`: Matrix of size cols x rows, with cols >= rows
/// * `rows`: Number of rows
/// * `cols`: Number of cols
/// * `w`: work-space of size iw
/// * `iw`: work-space size
///
///  # Reference
///
/// F. Gustavson and D. Walker - Algorithms for in-place matrix
/// transposition (2018)
fn column_transpose<T: Copy>(a: &mut [T], rows: usize, cols: usize, w: &mut [T], iw: usize) {
    if rows * cols <= iw {
        oop_transpose(a, &mut w[..rows * cols], rows, cols);
    } else {
        let q = rows / cols;
        let r = rows % cols;
        unshuffle(a, q * cols, r, cols);
        partition(a, q, cols);
        row_transpose(&mut a[q * cols * cols..], r, cols, w, iw);
    }
}

///  In-Place Swap-Based Matrix Transpose
///
///  # Parameters
///
/// * `a`: Matrix of size cols x rows, with cols <= rows
/// * `rows`: Number of rows
/// * `cols`: Number of cols
/// * `w`: work-space of size iw
/// * `iw`: work-space size
///
///  # Reference
///
/// F. Gustavson and D. Walker - Algorithms for in-place matrix
/// transposition (2018)
fn row_transpose<T: Copy>(a: &mut [T], rows: usize, cols: usize, w: &mut [T], iw: usize) {
    if rows * cols <= iw {
        oop_transpose(a, &mut w[..rows * cols], rows, cols);
    } else {
        let q = cols / rows;
        let r = cols % rows;
        column_transpose(&mut a[q * rows * rows..], rows, r, w, iw);
        join(a, q, rows);
        shuffle(a, q * rows, r, rows);
    }
}
