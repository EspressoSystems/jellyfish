(function() {
    var implementors = Object.fromEntries([["jf_aead",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_aead/struct.EncKey.html\" title=\"struct jf_aead::EncKey\">EncKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_aead/struct.KeyPair.html\" title=\"struct jf_aead::KeyPair\">KeyPair</a>"]]],["jf_elgamal",[["impl&lt;P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_elgamal/struct.EncKey.html\" title=\"struct jf_elgamal::EncKey\">EncKey</a>&lt;P&gt;<div class=\"where\">where\n    P: Config,</div>"]]],["jf_merkle_tree",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_merkle_tree/prelude/struct.Keccak256Node.html\" title=\"struct jf_merkle_tree::prelude::Keccak256Node\">Keccak256Node</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_merkle_tree/prelude/struct.Sha3Node.html\" title=\"struct jf_merkle_tree::prelude::Sha3Node\">Sha3Node</a>"],["impl&lt;H&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_merkle_tree/hasher/struct.HasherNode.html\" title=\"struct jf_merkle_tree::hasher::HasherNode\">HasherNode</a>&lt;H&gt;<div class=\"where\">where\n    H: Digest,</div>"]]],["jf_pcs",[["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_pcs/prelude/struct.UnivariateProverParam.html\" title=\"struct jf_pcs::prelude::UnivariateProverParam\">UnivariateProverParam</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div>"],["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_pcs/prelude/struct.UnivariateUniversalParams.html\" title=\"struct jf_pcs::prelude::UnivariateUniversalParams\">UnivariateUniversalParams</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,\n    E::G2Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div>"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_pcs/prelude/struct.Commitment.html\" title=\"struct jf_pcs::prelude::Commitment\">Commitment</a>&lt;E&gt;"],["impl&lt;E: Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_pcs/prelude/struct.UnivariateVerifierParam.html\" title=\"struct jf_pcs::prelude::UnivariateVerifierParam\">UnivariateVerifierParam</a>&lt;E&gt;"]]],["jf_plonk",[["impl&lt;F&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_plonk/proof_system/structs/struct.ProofEvaluations.html\" title=\"struct jf_plonk::proof_system::structs::ProofEvaluations\">ProofEvaluations</a>&lt;F&gt;<div class=\"where\">where\n    F: Field,</div>"]]],["jf_poseidon2",[["impl&lt;F, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.86.0/std/primitive.usize.html\">usize</a>, const R: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.86.0/std/primitive.usize.html\">usize</a>, P&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_poseidon2/sponge/struct.Poseidon2SpongeState.html\" title=\"struct jf_poseidon2::sponge::Poseidon2SpongeState\">Poseidon2SpongeState</a>&lt;F, N, R, P&gt;<div class=\"where\">where\n    F: PrimeField,\n    P: <a class=\"trait\" href=\"jf_poseidon2/trait.Poseidon2Params.html\" title=\"trait jf_poseidon2::Poseidon2Params\">Poseidon2Params</a>&lt;F, N&gt;,</div>"]]],["jf_relation",[["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ultraplonk/mod_arith/struct.FpElem.html\" title=\"struct jf_relation::gadgets::ultraplonk::mod_arith::FpElem\">FpElem</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ultraplonk/mod_arith/struct.FpElemVar.html\" title=\"struct jf_relation::gadgets::ultraplonk::mod_arith::FpElemVar\">FpElemVar</a>&lt;F&gt;"],["impl&lt;F: FftField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_relation/constraint_system/struct.PlonkCircuit.html\" title=\"struct jf_relation::constraint_system::PlonkCircuit\">PlonkCircuit</a>&lt;F&gt;"],["impl&lt;F: PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/emulated/struct.SWPoint.html\" title=\"struct jf_relation::gadgets::ecc::emulated::SWPoint\">SWPoint</a>&lt;F&gt;"],["impl&lt;F: PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.TEPoint.html\" title=\"struct jf_relation::gadgets::ecc::TEPoint\">TEPoint</a>&lt;F&gt;"]]],["jf_rescue",[["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"jf_rescue/trait.RescueParameter.html\" title=\"trait jf_rescue::RescueParameter\">RescueParameter</a>, const INPUT_LEN: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.86.0/std/primitive.usize.html\">usize</a>, const INPUT_LEN_PLUS_ONE: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.86.0/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_rescue/commitment/struct.FixedLengthRescueCommitment.html\" title=\"struct jf_rescue::commitment::FixedLengthRescueCommitment\">FixedLengthRescueCommitment</a>&lt;F, INPUT_LEN, INPUT_LEN_PLUS_ONE&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"jf_rescue/trait.RescueParameter.html\" title=\"trait jf_rescue::RescueParameter\">RescueParameter</a>, const RATE: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.86.0/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_rescue/sponge/struct.RescueSponge.html\" title=\"struct jf_rescue::sponge::RescueSponge\">RescueSponge</a>&lt;F, RATE&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_rescue/struct.RescueVector.html\" title=\"struct jf_rescue::RescueVector\">RescueVector</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"jf_rescue/trait.RescueParameter.html\" title=\"trait jf_rescue::RescueParameter\">RescueParameter</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_rescue/struct.PRP.html\" title=\"struct jf_rescue::PRP\">PRP</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"jf_rescue/trait.RescueParameter.html\" title=\"trait jf_rescue::RescueParameter\">RescueParameter</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"jf_rescue/struct.Permutation.html\" title=\"struct jf_rescue::Permutation\">Permutation</a>&lt;F&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[530,346,988,2219,413,800,2046,2902]}