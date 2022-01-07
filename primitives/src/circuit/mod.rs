use jf_plonk::circuit::Variable;

pub mod commitment;
pub mod elgamal;
pub mod merkle_tree;
pub mod prf;
pub mod schnorr_dsa;

use ark_std::vec::Vec;
#[inline]
fn pad_with(vec: &mut Vec<Variable>, multiple: usize, var: Variable) {
    let len = vec.len();
    let new_len = if len % multiple == 0 {
        len
    } else {
        len + multiple - len % multiple
    };
    vec.resize(new_len, var);
}
