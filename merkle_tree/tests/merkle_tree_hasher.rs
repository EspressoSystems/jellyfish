use jf_merkle_tree::{errors::MerkleTreeError, hasher::HasherMerkleTree, MerkleTreeScheme};
use sha2::Sha256;

#[test]
fn doctest_example() -> Result<(), MerkleTreeError> {
    let my_data = [1, 2, 3, 4, 5, 6, 7, 8, 9];

    // payload type is `usize`, hash function is `Sha256`.
    let mt = HasherMerkleTree::<Sha256, usize>::from_elems(Some(2), my_data)?;

    let commitment = mt.commitment();
    let (val, proof) = mt.lookup(2).expect_ok()?;
    assert_eq!(val, &3);
    assert!(HasherMerkleTree::<Sha256, usize>::verify(commitment, 2, val, proof)?.is_ok());
    Ok(())
}
