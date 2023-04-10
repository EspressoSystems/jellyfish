// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Toeplitz matrices and Circulant matrices operations
//! References: https://eprint.iacr.org/2020/1516.pdf

use crate::errors::PrimitivesError;
use ark_ff::Field;
use ark_std::string::ToString;
// use ark_std::ops::Mul;

/// An `NxN` [Circulant Matrix](https://en.wikipedia.org/wiki/Circulant_matrix)
/// is unambiguously represented by its first column, and has the form:
///
/// [c_0   c_N-1 c_N-2 ... c_1]
/// [c_1   c_0   c_N-1 ... c_2]
/// [c_2   c_1   c_0   ... c_3]
/// [..    ..    ..    ... .. ]
/// [c_N-1 c_N-2 c_N-3 ... c_0]
///
/// It is a special case of [`ToeplitzMatrix`].
// TODO: (alex) remove this clippy exception
#[allow(dead_code)]
pub struct CirculantMatrix<F: Field, const N: usize> {
    col: [F; N],
}

// TODO: (alex) need FFT over group elements first.
// impl<F: Field> Mul<>

// impl<F: Field> Mul<>

/// An `NxN` [Toeplitz Matrix](https://en.wikipedia.org/wiki/Toeplitz_matrix) is
/// unambiguously represented by its first column and first row, and has the
/// form:
///
/// [a_0   a_-1  a_-2  ...  a_-(N-1)]
/// [a_1   a_0   a_-1  ...  a_-(N-2)]
/// [a_2   a_1   a_0   ...  a_-(N-3)]
/// [..    ..    ..    ...    ..    ]
/// [a_N-1 a_N-2 ..    ...  a_0     ]
// TODO: (alex) remove this clippy exception
#[allow(dead_code)]
pub struct ToeplitzMatrix<F: Field, const N: usize> {
    col: [F; N],
    row: [F; N],
}

impl<F: Field, const N: usize> ToeplitzMatrix<F, N> {
    /// constructor for a new Toeplitz matrice.
    pub fn new(col: [F; N], row: [F; N]) -> Result<Self, PrimitivesError> {
        if N == 0 {
            return Err(PrimitivesError::ParameterError(
                "Matrix dimension should be positive".to_string(),
            ));
        }
        if col[0] != row[0] {
            return Err(PrimitivesError::ParameterError(
                "1st value in 1st column and 1st row of Toeplitz matrix should be the same"
                    .to_string(),
            ));
        }

        Ok(Self { col, row })
    }

    /// Embeds a Toeplitz matrix of size N to a Circulant matrix of size 2N.
    ///
    /// Details see Section 2.3.1 of [Tomescu20](https://eprint.iacr.org/2020/1516.pdf).
    // TODO: (alex) turn this into concurrent code after: https://github.com/EspressoSystems/jellyfish/issues/111
    pub fn circulant_embedding<const M: usize>(
        &self,
    ) -> Result<CirculantMatrix<F, M>, PrimitivesError> {
        if M != 2 * N {
            return Err(PrimitivesError::ParameterError(
                "Circulant embedding should be twice the size".to_string(),
            ));
        }
        let mut extended_col = [self.col[0]; M];
        extended_col[..N].copy_from_slice(&self.col);
        extended_col[N] = self.col[0];
        for (i, v) in self.row.iter().enumerate().skip(1) {
            extended_col[2 * N - i] = *v;
        }

        Ok(CirculantMatrix { col: extended_col })
    }
}

impl<F: Field, const N: usize> From<CirculantMatrix<F, N>> for ToeplitzMatrix<F, N> {
    fn from(c: CirculantMatrix<F, N>) -> Self {
        let mut row = [c.col[0]; N];
        for (i, v) in c.col.iter().enumerate().skip(1) {
            row[N - i] = *v;
        }
        Self { col: c.col, row }
    }
}

impl<F: Field, const N: usize> TryFrom<ToeplitzMatrix<F, N>> for CirculantMatrix<F, N> {
    type Error = PrimitivesError;

    fn try_from(t: ToeplitzMatrix<F, N>) -> Result<Self, Self::Error> {
        if (1..N).any(|i| t.row[i] != t.col[N - i]) {
            return Err(PrimitivesError::ParameterError(
                "Not a Circulant Matrix".to_string(),
            ));
        }
        Ok(Self { col: t.col })
    }
}
