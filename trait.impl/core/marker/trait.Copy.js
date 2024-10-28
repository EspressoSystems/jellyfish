(function() {
    var implementors = Object.fromEntries([["jf_aead",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_aead/struct.AEADError.html\" title=\"struct jf_aead::AEADError\">AEADError</a>"]]],["jf_merkle_tree",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_merkle_tree/prelude/struct.Keccak256Node.html\" title=\"struct jf_merkle_tree::prelude::Keccak256Node\">Keccak256Node</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_merkle_tree/prelude/struct.Sha3Node.html\" title=\"struct jf_merkle_tree::prelude::Sha3Node\">Sha3Node</a>"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + <a class=\"trait\" href=\"jf_rescue/trait.RescueParameter.html\" title=\"trait jf_rescue::RescueParameter\">RescueParameter</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_merkle_tree/prelude/struct.RescueHash.html\" title=\"struct jf_merkle_tree::prelude::RescueHash\">RescueHash</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + Field&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_merkle_tree/examples/struct.Interval.html\" title=\"struct jf_merkle_tree::examples::Interval\">Interval</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>, P: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>, N: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"enum\" href=\"jf_merkle_tree/enum.LookupResult.html\" title=\"enum jf_merkle_tree::LookupResult\">LookupResult</a>&lt;F, P, N&gt;"],["impl&lt;H&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_merkle_tree/hasher/struct.HasherNode.html\" title=\"struct jf_merkle_tree::hasher::HasherNode\">HasherNode</a>&lt;H&gt;<div class=\"where\">where\n    H: Digest,\n    &lt;&lt;H as OutputSizeUser&gt;::OutputSize as ArrayLength&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.82.0/std/primitive.u8.html\">u8</a>&gt;&gt;::ArrayType: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>,</div>"]]],["jf_pcs",[["impl&lt;E: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + Pairing&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_pcs/prelude/struct.Commitment.html\" title=\"struct jf_pcs::prelude::Commitment\">Commitment</a>&lt;E&gt;<div class=\"where\">where\n    E::G1Affine: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>,</div>"]]],["jf_relation",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"enum\" href=\"jf_relation/constraint_system/enum.MergeableCircuitType.html\" title=\"enum jf_relation::constraint_system::MergeableCircuitType\">MergeableCircuitType</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"enum\" href=\"jf_relation/constraint_system/enum.PlonkType.html\" title=\"enum jf_relation::constraint_system::PlonkType\">PlonkType</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_relation/constraint_system/struct.BoolVar.html\" title=\"struct jf_relation::constraint_system::BoolVar\">BoolVar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.PointVariable.html\" title=\"struct jf_relation::gadgets::ecc::PointVariable\">PointVariable</a>"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/emulated/struct.SWPoint.html\" title=\"struct jf_relation::gadgets::ecc::emulated::SWPoint\">SWPoint</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ecc/struct.TEPoint.html\" title=\"struct jf_relation::gadgets::ecc::TEPoint\">TEPoint</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ultraplonk/mod_arith/struct.FpElem.html\" title=\"struct jf_relation::gadgets::ultraplonk::mod_arith::FpElem\">FpElem</a>&lt;F&gt;"],["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + PrimeField&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_relation/gadgets/ultraplonk/mod_arith/struct.FpElemVar.html\" title=\"struct jf_relation::gadgets::ultraplonk::mod_arith::FpElemVar\">FpElemVar</a>&lt;F&gt;"]]],["jf_rescue",[["impl&lt;F: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.82.0/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> for <a class=\"struct\" href=\"jf_rescue/struct.RescueVector.html\" title=\"struct jf_rescue::RescueVector\">RescueVector</a>&lt;F&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[268,2990,632,3118,436]}