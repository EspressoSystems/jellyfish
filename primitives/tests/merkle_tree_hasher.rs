use jf_primitives::{
    errors::PrimitivesError,
    merkle_tree::{hasher::HasherMerkleTree, MerkleCommitment, MerkleTreeScheme},
};
use sha2::Sha256;

#[test]
fn doctest_example() -> Result<(), PrimitivesError> {
    let my_data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    let mt = HasherMerkleTree::<Sha256, usize>::from_elems(2, &my_data)?;
    let root = mt.commitment().digest();
    let (val, proof) = mt.lookup(2).expect_ok()?;
    assert_eq!(val, 3);
    assert!(HasherMerkleTree::<Sha256, usize>::verify(root, proof)?.is_ok());
    Ok(())
}
