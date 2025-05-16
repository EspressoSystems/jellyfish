#![no_main]

use ark_bls12_377::Fr as Fr377;
use ark_bls12_381::Fr as Fr381;
use ark_bn254::Fr as Fr254;
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use jf_rescue::{crhf::RescueCRHF, RescueParameter};
use jf_merkle_tree::{prelude::RescueMerkleTree, MerkleTreeScheme};
use ark_ff::{Field, PrimeField, Zero};


#[derive(Debug, Arbitrary)]
struct ExtensionAttackInput {
    forged_val: u64,
    attack_pos: u64,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    test_extension_attack_helper::<Fr254>(&mut u);
    test_extension_attack_helper::<Fr377>(&mut u);
    test_extension_attack_helper::<Fr381>(&mut u);
});

fn test_extension_attack_helper<F: RescueParameter>(u: &mut Unstructured) {
    if let Ok(input) = ExtensionAttackInput::arbitrary(&mut u) {
        let forged_val = F::from(input.forged_val);
        let attack_pos = input.attack_pos;
        let forged_pos = attack_pos * 3 + 2;

        let data = [F::zero(), F::from(forged_pos), forged_val];
        let squeezed = RescueCRHF::<F>::sponge_no_padding(&data, 1).unwrap();
        let val = squeezed[0];

        let elems = vec![val; attack_pos as usize + 1];
        let mt = RescueMerkleTree::<F>::from_elems(None, elems).unwrap();
        let commit = mt.commitment();

        let lookup_result = mt.lookup(attack_pos);
        let (elem, mut proof) = lookup_result.expect_ok().unwrap();

        let verify_ok = RescueMerkleTree::<F>::verify(&commit, attack_pos, elem, &proof).unwrap();
        assert!(verify_ok.is_ok());

        proof.0.insert(0, vec![F::zero(), F::from(attack_pos)]);
        let verify_forged = RescueMerkleTree::<F>::verify(&commit, forged_pos, forged_val, &proof).unwrap();
        assert!(verify_forged.is_err());
    }
}