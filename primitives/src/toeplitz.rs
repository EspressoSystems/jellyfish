// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Toeplitz matrices and Circulant matrices operations
//! References: `https://eprint.iacr.org/2020/1516.pdf`

use crate::errors::PrimitivesError;
use ark_ff::FftField;
use ark_poly::{domain::DomainCoeff, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{format, ops::Mul, string::ToString, vec::Vec};
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
pub struct CirculantMatrix<F: FftField> {
    col: Vec<F>,
}

impl<F: FftField> CirculantMatrix<F> {
    /// Construct a Circulant matrix by its first column vector
    pub fn new(col: Vec<F>) -> Self {
        Self { col }
    }

    /// Fast multiplication of a Circulant matrix by a vector via FFT
    /// Details see Section 2.2.1 of [Tomescu20](https://eprint.iacr.org/2020/1516.pdf).
    // TODO: (alex) think of ways to extend to arbitrary length vector (simply
    // truncate doesn't work).
    pub fn fast_vec_mul<T>(&self, m: &[T]) -> Result<Vec<T>, PrimitivesError>
    where
        T: for<'a> Mul<&'a F, Output = T> + DomainCoeff<F>,
    {
        if !m.len().is_power_of_two() {
            return Err(PrimitivesError::ParameterError(
                "Fast Circulant Matrix mul only supports vector size of power of two.".to_string(),
            ));
        }
        if m.len() != self.col.len() {
            return Err(PrimitivesError::ParameterError(
                "Wrong input dimension for matrix mul.".to_string(),
            ));
        }
        let domain: GeneralEvaluationDomain<F> =
            GeneralEvaluationDomain::new(m.len()).expect("Should init an evaluation domain");

        let m_evals = domain.fft(m); // DFT(m)
        let col_evals = domain.fft(&self.col); // DFT(c_N)
        let eval_prod = // DFT(c_N) * DFT(m)
            hadamard_product(col_evals, m_evals).expect("Hadamard product should succeed");
        let res = domain.ifft(&eval_prod); // iDFT(DFT(c_N) * DFT(m))
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
pub struct ToeplitzMatrix<F: FftField> {
    col: Vec<F>,
    row: Vec<F>,
}

impl<F: FftField> ToeplitzMatrix<F> {
    /// constructor for a new Toeplitz matrix.
    pub fn new(col: Vec<F>, row: Vec<F>) -> Result<Self, PrimitivesError> {
        if col.is_empty() || col.len() != row.len() {
            return Err(PrimitivesError::ParameterError(format!(
                "row: {}, col: {} should be both positive and equal",
                row.len(),
                col.len()
            )));
        }
        if col[0] != row[0] {
            return Err(PrimitivesError::ParameterError(format!(
                "1st value in 1st col: {:?} should be the same as that in 1st row: {:?}",
                col[0], row[0]
            )));
        }

        Ok(Self { col, row })
    }

    /// Embeds a Toeplitz matrix of size N to a Circulant matrix of size 2N.
    ///
    /// Details see Section 2.3.1 of [Tomescu20](https://eprint.iacr.org/2020/1516.pdf).
    // TODO: (alex) turn this into concurrent code after: https://github.com/EspressoSystems/jellyfish/issues/111
    pub fn circulant_embedding(&self) -> Result<CirculantMatrix<F>, PrimitivesError> {
        let mut extension_col = self.row.clone();
        extension_col.rotate_left(1);
        extension_col.reverse();

        Ok(CirculantMatrix {
            col: [self.col.clone(), extension_col].concat(),
        })
    }

    /// Fast multiplication of a Toeplitz matrix by embedding it into a
    /// circulant matrix and multiply there.
    ///
    /// Details see Section 2.3.1 of [Tomescu20](https://eprint.iacr.org/2020/1516.pdf).
    pub fn fast_vec_mul<T>(&self, v: &[T]) -> Result<Vec<T>, PrimitivesError>
    where
        T: for<'a> Mul<&'a F, Output = T> + DomainCoeff<F>,
    {
        if !v.len().is_power_of_two() {
            return Err(PrimitivesError::ParameterError(
                "Fast Toeplitz Matrix mul only supports vector size of power of two.".to_string(),
            ));
        }
        if v.len() != self.col.len() {
            return Err(PrimitivesError::ParameterError(
                "Wrong input dimension for matrix mul.".to_string(),
            ));
        }

        let cir_repr = self.circulant_embedding()?;
        let mut padded_v = Vec::from(v);
        padded_v.resize(2 * v.len(), T::zero());

        let mut res = cir_repr.fast_vec_mul(&padded_v)?;
        res.truncate(v.len());
        Ok(res)
    }
}

impl<F: FftField> From<CirculantMatrix<F>> for ToeplitzMatrix<F> {
    fn from(c: CirculantMatrix<F>) -> Self {
        let mut row = c.col.clone();
        row.rotate_left(1);
        row.reverse();

        Self { col: c.col, row }
    }
}

impl<F: FftField> TryFrom<ToeplitzMatrix<F>> for CirculantMatrix<F> {
    type Error = PrimitivesError;

    fn try_from(t: ToeplitzMatrix<F>) -> Result<Self, Self::Error> {
        let mut expected_col = t.row;
        expected_col.reverse();
        expected_col.rotate_right(1);
        if expected_col != t.col {
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
    use ark_std::{convert::Into, ops::AddAssign, vec, UniformRand};
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

    impl<T: Copy, const N: usize> From<Vector<T, N>> for Vec<T> {
        fn from(v: Vector<T, N>) -> Self {
            Vec::from(&v.0[..])
        }
    }

    impl<F: FftField> CirculantMatrix<F> {
        fn full_matrix<const N: usize>(self) -> Matrix<F, N, N> {
            assert_eq!(self.col.len(), N);
            let t: ToeplitzMatrix<F> = self.into();

            let mut first_row = [F::default(); N];
            first_row.copy_from_slice(&t.row);
            let mut row_vecs = [first_row; N];
            let mut cur_row = first_row;

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

    impl<F: FftField> ToeplitzMatrix<F> {
        fn full_matrix<const N: usize>(self) -> Matrix<F, N, N> {
            assert_eq!(self.col.len(), N);
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
        // happy path
        const N: usize = 16;

        let cir_matrix = CirculantMatrix::new((0..N).map(|_| Fr::rand(&mut rng)).collect());

        let msgs = [G1Projective::rand(&mut rng); N];
        let msg_matrix = Matrix([msgs]);

        let expected: Vector<G1Projective, N> =
            naive_matrix_mul(cir_matrix.clone().full_matrix(), msg_matrix.transpose())
                .transpose()
                .into();
        let got = cir_matrix.fast_vec_mul(&msgs)?;
        assert_eq!(
            <Vector<G1Projective, N> as Into<Vec<G1Projective>>>::into(expected),
            got,
            "Fast Circulant Matrix mul for EC group is incorrect."
        );

        let f_msgs = [Fr::rand(&mut rng); N];
        let f_msg_matrix = Matrix([f_msgs]);

        let expected: Vector<Fr, N> =
            naive_matrix_mul(cir_matrix.clone().full_matrix(), f_msg_matrix.transpose())
                .transpose()
                .into();
        let got = cir_matrix.fast_vec_mul(&f_msgs)?;
        assert_eq!(
            <Vector<Fr, N> as Into<Vec<Fr>>>::into(expected),
            got,
            "Fast Circulant Matrix mul for field is incorrect."
        );

        // bad path
        // mismatched matrix.col.len() and msgs.len() should fail
        let bad_msg = vec![msgs.to_vec(), vec![G1Projective::rand(&mut rng)]].concat();
        assert!(cir_matrix.fast_vec_mul(&bad_msg).is_err());

        // non power-of-two matrix fast mul should fail
        let m = bad_msg.len(); // same dimension as the message, but not a power-of-two
        let cir_matrix = CirculantMatrix::new((0..m).map(|_| Fr::rand(&mut rng)).collect());

        assert!(
            !m.is_power_of_two()
                && m == cir_matrix.col.len()
                && cir_matrix.fast_vec_mul(&bad_msg).is_err()
        );

        Ok(())
    }

    #[test]
    fn test_toeplitz_mul() -> Result<(), PrimitivesError> {
        let mut rng = test_rng();
        const N: usize = 16;

        let rand_col: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
        let rand_row = (0..N)
            .map(|i| {
                if i == 0 {
                    rand_col[0]
                } else {
                    Fr::rand(&mut rng)
                }
            })
            .collect();
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
        let got = toep_matrix.fast_vec_mul(&msgs)?;
        assert_eq!(
            <Vector<G1Projective, N> as Into<Vec<G1Projective>>>::into(expected),
            got,
            "Fast Toeplitz Matrix mul is incorrect."
        );

        Ok(())
    }
}
