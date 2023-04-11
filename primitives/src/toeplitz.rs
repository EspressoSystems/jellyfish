// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Toeplitz matrices and Circulant matrices operations
//! References: `https://eprint.iacr.org/2020/1516.pdf`

use crate::errors::PrimitivesError;
use ark_ff::FftField;
use ark_poly::{domain::DomainCoeff, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{ops::Mul, string::ToString};
use jf_utils::hadamard_product;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CirculantMatrix<F: FftField, const N: usize> {
    col: [F; N],
}

impl<F: FftField, const N: usize> CirculantMatrix<F, N> {
    /// Fast multiplication of a Circulant matrix by a vector via FFT
    /// Details see Section 2.2.1 of [Tomescu20](https://eprint.iacr.org/2020/1516.pdf).
    // TODO: (alex) think of ways to extend to arbitrary length vector (simply
    // truncate doesn't work).
    pub fn fast_vec_mul<T>(&self, m: [T; N]) -> Result<[T; N], PrimitivesError>
    where
        T: for<'a> Mul<&'a F, Output = T> + DomainCoeff<F> + Default,
    {
        if !N.is_power_of_two() {
            return Err(PrimitivesError::ParameterError(
                "Fast Circulant Matrix mul only supports vector size of power of two.".to_string(),
            ));
        }
        let domain: GeneralEvaluationDomain<F> =
            GeneralEvaluationDomain::new(N).expect("Should init an evaluation domain");

        let m_evals = domain.fft(&m); // DFT(m)
        let col_evals = domain.fft(&self.col); // DFT(c_N)
        let eval_prod = // DFT(c_N) * DFT(m)
            hadamard_product(&col_evals, &m_evals).expect("Hadmard product should succeed");
        let mut res = [T::default(); N]; // iDFT(DFT(c_N) * DFT(m))
        res.copy_from_slice(&domain.ifft(&eval_prod)[..N]);
        Ok(res)
    }
}

/// An `NxN` [Toeplitz Matrix](https://en.wikipedia.org/wiki/Toeplitz_matrix) is
/// unambiguously represented by its first column and first row, and has the
/// form:
///
/// [a_0   a_-1  a_-2  ...  a_-(N-1)]
/// [a_1   a_0   a_-1  ...  a_-(N-2)]
/// [a_2   a_1   a_0   ...  a_-(N-3)]
/// [..    ..    ..    ...    ..    ]
/// [a_N-1 a_N-2 ..    ...  a_0     ]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToeplitzMatrix<F: FftField, const N: usize> {
    col: [F; N],
    row: [F; N],
}

impl<F: FftField, const N: usize> ToeplitzMatrix<F, N> {
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

    /// Fast multiplication of a Toeplitz matrix by embedding it into a
    /// circulant matrix and multiply there.
    ///
    /// Details see Section 2.3.1 of [Tomescu20](https://eprint.iacr.org/2020/1516.pdf).
    pub fn fast_vec_mul<T, const M: usize>(&self, v: [T; N]) -> Result<[T; N], PrimitivesError>
    where
        T: for<'a> Mul<&'a F, Output = T> + DomainCoeff<F> + Default,
    {
        if !N.is_power_of_two() {
            return Err(PrimitivesError::ParameterError(
                "Fast Toeplitz Matrix mul only supports vector size of power of two.".to_string(),
            ));
        }
        let cir_repr = self.circulant_embedding::<M>()?;
        let mut padded_v = [T::default(); M];
        padded_v[..N].copy_from_slice(&v);

        let out = cir_repr.fast_vec_mul(padded_v)?;
        let mut res = [T::default(); N];
        res.copy_from_slice(&out[..N]);
        Ok(res)
    }
}

impl<F: FftField, const N: usize> From<CirculantMatrix<F, N>> for ToeplitzMatrix<F, N> {
    fn from(c: CirculantMatrix<F, N>) -> Self {
        let mut row = [c.col[0]; N];
        for (i, v) in c.col.iter().enumerate().skip(1) {
            row[N - i] = *v;
        }
        Self { col: c.col, row }
    }
}

impl<F: FftField, const N: usize> TryFrom<ToeplitzMatrix<F, N>> for CirculantMatrix<F, N> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ff::Field;
    use ark_std::{convert::Into, ops::AddAssign, UniformRand};
    use jf_utils::test_rng;

    // a MxN matrix, M rows, N cols.
    struct Matrix<T, const M: usize, const N: usize>([[T; N]; M]);
    struct Vector<T, const N: usize>([T; N]);

    impl<T: Copy, const M: usize, const N: usize> Matrix<T, M, N> {
        fn transpose(self) -> Matrix<T, N, M> {
            let mut transposed = [[self.0[0][0]; M]; N];
            for i in 0..M {
                for j in 0..N {
                    transposed[j][i] = self.0[i][j];
                }
            }
            Matrix(transposed)
        }
    }

    impl<T: Copy, const N: usize> From<Matrix<T, 1, N>> for Vector<T, N> {
        fn from(m: Matrix<T, 1, N>) -> Self {
            let mut v = [m.0[0][0]; N];
            v.copy_from_slice(&m.0[0]);
            Vector(v)
        }
    }

    impl<F: FftField, const N: usize> CirculantMatrix<F, N> {
        fn full_matrix(self) -> Matrix<F, N, N> {
            let t: ToeplitzMatrix<F, N> = self.into();
            let mut row_vecs = [t.row; N];
            let mut cur_row = t.row;

            for i in 1..N {
                cur_row.rotate_right(1);
                row_vecs[i] = cur_row;
            }
            // some arbitrary sanity check
            assert_eq!(row_vecs[N - 1][0], row_vecs[0][1]);
            assert_eq!(row_vecs[1][0], row_vecs[0][N - 1]);
            assert_eq!(row_vecs[N - 1][N - 1], row_vecs[0][0]);

            Matrix(row_vecs)
        }
    }

    impl<F: FftField, const N: usize> ToeplitzMatrix<F, N> {
        fn full_matrix(self) -> Matrix<F, N, N> {
            let mut matrix = [[F::zero(); N]; N];
            for i in 0..N {
                matrix[i][0] = self.col[i];
                matrix[0][i] = self.row[i];
            }
            for i in 1..N {
                for j in 1..N {
                    matrix[i][j] = matrix[i - 1][j - 1];
                }
            }
            Matrix(matrix)
        }
    }

    fn naive_matrix_mul<F, T, const M: usize, const N: usize, const K: usize>(
        a: Matrix<F, M, N>,
        b: Matrix<T, N, K>,
    ) -> Matrix<T, M, K>
    where
        F: Field,
        T: for<'a> Mul<&'a F, Output = T> + AddAssign<T> + Copy + Default,
    {
        let mut c = [[T::default(); K]; M];

        for i in 0..M {
            for j in 0..K {
                for k in 0..N {
                    c[i][j] += b.0[k][j] * &a.0[i][k];
                }
            }
        }
        Matrix(c)
    }

    #[test]
    fn test_circulant_mul() -> Result<(), PrimitivesError> {
        let mut rng = test_rng();
        const N: usize = 16;

        let mut cir_col = [Fr::default(); N];
        for f in cir_col.iter_mut() {
            *f = Fr::rand(&mut rng);
        }
        let cir_matrix = CirculantMatrix { col: cir_col };

        let mut msgs = [G1Projective::default(); N];
        for m in msgs.iter_mut() {
            *m = G1Projective::rand(&mut rng);
        }
        let msg_matrix = Matrix([msgs]);

        let expected: Vector<G1Projective, N> =
            naive_matrix_mul(cir_matrix.clone().full_matrix(), msg_matrix.transpose())
                .transpose()
                .into();
        let got: [G1Projective; N] = cir_matrix.fast_vec_mul(msgs).unwrap();
        assert_eq!(expected.0, got, "Fast Circulant Matrix mul is incorrect.");
        Ok(())
    }

    #[test]
    fn test_toeplitz_mul() -> Result<(), PrimitivesError> {
        let mut rng = test_rng();
        const N: usize = 16;
        const M: usize = 32;

        let mut rand_col = [Fr::default(); N];
        for f in rand_col.iter_mut() {
            *f = Fr::rand(&mut rng);
        }
        let mut rand_row = [rand_col[0]; N];
        for f in rand_row.iter_mut().skip(1) {
            *f = Fr::rand(&mut rng);
        }
        let toep_matrix = ToeplitzMatrix::new(rand_col, rand_row)?;

        let mut msgs = [G1Projective::default(); N];
        for m in msgs.iter_mut() {
            *m = G1Projective::rand(&mut rng);
        }
        let msg_matrix = Matrix([msgs]);

        let expected: Vector<G1Projective, N> =
            naive_matrix_mul(toep_matrix.clone().full_matrix(), msg_matrix.transpose())
                .transpose()
                .into();
        let got: [G1Projective; N] = toep_matrix.fast_vec_mul::<_, M>(msgs).unwrap();
        assert_eq!(expected.0, got, "Fast Toeplitz Matrix mul is incorrect.");

        Ok(())
    }
}
