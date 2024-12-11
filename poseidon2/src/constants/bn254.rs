//! Poseidon2 constants for the scalar field of BN254

use super::from_hex;
use crate::{define_poseidon2_params, Poseidon2Params};
use ark_bn254::Fr;
use lazy_static::lazy_static;

define_poseidon2_params!(
    Poseidon2ParamsBn3,
    3,             // State size
    5,             // S-box size
    8,             // External rounds
    56,            // Internal rounds
    RC3_EXT,       // External round constants
    RC3_INT,       // Internal round constants
    MAT_DIAG3_M_1  // Diagonal matrix constant
);

// adapted from <https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs>
lazy_static! {
    /// internal diagonal matrix, state size = 3
    pub static ref MAT_DIAG3_M_1: [Fr; 3] = [
        from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
        from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
        from_hex("0000000000000000000000000000000000000000000000000000000000000002"),
    ];

    /// external round constants, state size = 3
    pub static ref RC3_EXT: [[Fr; 3]; 8] = [
        [
            from_hex("1d066a255517b7fd8bddd3a93f7804ef7f8fcde48bb4c37a59a09a1a97052816"),
            from_hex("29daefb55f6f2dc6ac3f089cebcc6120b7c6fef31367b68eb7238547d32c1610"),
            from_hex("1f2cb1624a78ee001ecbd88ad959d7012572d76f08ec5c4f9e8b7ad7b0b4e1d1"),
        ],
        [
            from_hex("0aad2e79f15735f2bd77c0ed3d14aa27b11f092a53bbc6e1db0672ded84f31e5"),
            from_hex("2252624f8617738cd6f661dd4094375f37028a98f1dece66091ccf1595b43f28"),
            from_hex("1a24913a928b38485a65a84a291da1ff91c20626524b2b87d49f4f2c9018d735"),
        ],
        [
            from_hex("22fc468f1759b74d7bfc427b5f11ebb10a41515ddff497b14fd6dae1508fc47a"),
            from_hex("1059ca787f1f89ed9cd026e9c9ca107ae61956ff0b4121d5efd65515617f6e4d"),
            from_hex("02be9473358461d8f61f3536d877de982123011f0bf6f155a45cbbfae8b981ce"),
        ],
        [
            from_hex("0ec96c8e32962d462778a749c82ed623aba9b669ac5b8736a1ff3a441a5084a4"),
            from_hex("292f906e073677405442d9553c45fa3f5a47a7cdb8c99f9648fb2e4d814df57e"),
            from_hex("274982444157b86726c11b9a0f5e39a5cc611160a394ea460c63f0b2ffe5657e"),
        ],
        [
            from_hex("1acd63c67fbc9ab1626ed93491bda32e5da18ea9d8e4f10178d04aa6f8747ad0"),
            from_hex("19f8a5d670e8ab66c4e3144be58ef6901bf93375e2323ec3ca8c86cd2a28b5a5"),
            from_hex("1c0dc443519ad7a86efa40d2df10a011068193ea51f6c92ae1cfbb5f7b9b6893"),
        ],
        [
            from_hex("14b39e7aa4068dbe50fe7190e421dc19fbeab33cb4f6a2c4180e4c3224987d3d"),
            from_hex("1d449b71bd826ec58f28c63ea6c561b7b820fc519f01f021afb1e35e28b0795e"),
            from_hex("1ea2c9a89baaddbb60fa97fe60fe9d8e89de141689d1252276524dc0a9e987fc"),
        ],
        [
            from_hex("0478d66d43535a8cb57e9c1c3d6a2bd7591f9a46a0e9c058134d5cefdb3c7ff1"),
            from_hex("19272db71eece6a6f608f3b2717f9cd2662e26ad86c400b21cde5e4a7b00bebe"),
            from_hex("14226537335cab33c749c746f09208abb2dd1bd66a87ef75039be846af134166"),
        ],
        [
            from_hex("01fd6af15956294f9dfe38c0d976a088b21c21e4a1c2e823f912f44961f9a9ce"),
            from_hex("18e5abedd626ec307bca190b8b2cab1aaee2e62ed229ba5a5ad8518d4e5f2a57"),
            from_hex("0fc1bbceba0590f5abbdffa6d3b35e3297c021a3a409926d0e2d54dc1c84fda6"),
        ],
    ];

    /// internal round constants, state size = 3
    pub static ref RC3_INT: [Fr; 56] = [
        from_hex("1a1d063e54b1e764b63e1855bff015b8cedd192f47308731499573f23597d4b5"),
        from_hex("26abc66f3fdf8e68839d10956259063708235dccc1aa3793b91b002c5b257c37"),
        from_hex("0c7c64a9d887385381a578cfed5aed370754427aabca92a70b3c2b12ff4d7be8"),
        from_hex("1cf5998769e9fab79e17f0b6d08b2d1eba2ebac30dc386b0edd383831354b495"),
        from_hex("0f5e3a8566be31b7564ca60461e9e08b19828764a9669bc17aba0b97e66b0109"),
        from_hex("18df6a9d19ea90d895e60e4db0794a01f359a53a180b7d4b42bf3d7a531c976e"),
        from_hex("04f7bf2c5c0538ac6e4b782c3c6e601ad0ea1d3a3b9d25ef4e324055fa3123dc"),
        from_hex("29c76ce22255206e3c40058523748531e770c0584aa2328ce55d54628b89ebe6"),
        from_hex("198d425a45b78e85c053659ab4347f5d65b1b8e9c6108dbe00e0e945dbc5ff15"),
        from_hex("25ee27ab6296cd5e6af3cc79c598a1daa7ff7f6878b3c49d49d3a9a90c3fdf74"),
        from_hex("138ea8e0af41a1e024561001c0b6eb1505845d7d0c55b1b2c0f88687a96d1381"),
        from_hex("306197fb3fab671ef6e7c2cba2eefd0e42851b5b9811f2ca4013370a01d95687"),
        from_hex("1a0c7d52dc32a4432b66f0b4894d4f1a21db7565e5b4250486419eaf00e8f620"),
        from_hex("2b46b418de80915f3ff86a8e5c8bdfccebfbe5f55163cd6caa52997da2c54a9f"),
        from_hex("12d3e0dc0085873701f8b777b9673af9613a1af5db48e05bfb46e312b5829f64"),
        from_hex("263390cf74dc3a8870f5002ed21d089ffb2bf768230f648dba338a5cb19b3a1f"),
        from_hex("0a14f33a5fe668a60ac884b4ca607ad0f8abb5af40f96f1d7d543db52b003dcd"),
        from_hex("28ead9c586513eab1a5e86509d68b2da27be3a4f01171a1dd847df829bc683b9"),
        from_hex("1c6ab1c328c3c6430972031f1bdb2ac9888f0ea1abe71cffea16cda6e1a7416c"),
        from_hex("1fc7e71bc0b819792b2500239f7f8de04f6decd608cb98a932346015c5b42c94"),
        from_hex("03e107eb3a42b2ece380e0d860298f17c0c1e197c952650ee6dd85b93a0ddaa8"),
        from_hex("2d354a251f381a4669c0d52bf88b772c46452ca57c08697f454505f6941d78cd"),
        from_hex("094af88ab05d94baf687ef14bc566d1c522551d61606eda3d14b4606826f794b"),
        from_hex("19705b783bf3d2dc19bcaeabf02f8ca5e1ab5b6f2e3195a9d52b2d249d1396f7"),
        from_hex("09bf4acc3a8bce3f1fcc33fee54fc5b28723b16b7d740a3e60cef6852271200e"),
        from_hex("1803f8200db6013c50f83c0c8fab62843413732f301f7058543a073f3f3b5e4e"),
        from_hex("0f80afb5046244de30595b160b8d1f38bf6fb02d4454c0add41f7fef2faf3e5c"),
        from_hex("126ee1f8504f15c3d77f0088c1cfc964abcfcf643f4a6fea7dc3f98219529d78"),
        from_hex("23c203d10cfcc60f69bfb3d919552ca10ffb4ee63175ddf8ef86f991d7d0a591"),
        from_hex("2a2ae15d8b143709ec0d09705fa3a6303dec1ee4eec2cf747c5a339f7744fb94"),
        from_hex("07b60dee586ed6ef47e5c381ab6343ecc3d3b3006cb461bbb6b5d89081970b2b"),
        from_hex("27316b559be3edfd885d95c494c1ae3d8a98a320baa7d152132cfe583c9311bd"),
        from_hex("1d5c49ba157c32b8d8937cb2d3f84311ef834cc2a743ed662f5f9af0c0342e76"),
        from_hex("2f8b124e78163b2f332774e0b850b5ec09c01bf6979938f67c24bd5940968488"),
        from_hex("1e6843a5457416b6dc5b7aa09a9ce21b1d4cba6554e51d84665f75260113b3d5"),
        from_hex("11cdf00a35f650c55fca25c9929c8ad9a68daf9ac6a189ab1f5bc79f21641d4b"),
        from_hex("21632de3d3bbc5e42ef36e588158d6d4608b2815c77355b7e82b5b9b7eb560bc"),
        from_hex("0de625758452efbd97b27025fbd245e0255ae48ef2a329e449d7b5c51c18498a"),
        from_hex("2ad253c053e75213e2febfd4d976cc01dd9e1e1c6f0fb6b09b09546ba0838098"),
        from_hex("1d6b169ed63872dc6ec7681ec39b3be93dd49cdd13c813b7d35702e38d60b077"),
        from_hex("1660b740a143664bb9127c4941b67fed0be3ea70a24d5568c3a54e706cfef7fe"),
        from_hex("0065a92d1de81f34114f4ca2deef76e0ceacdddb12cf879096a29f10376ccbfe"),
        from_hex("1f11f065202535987367f823da7d672c353ebe2ccbc4869bcf30d50a5871040d"),
        from_hex("26596f5c5dd5a5d1b437ce7b14a2c3dd3bd1d1a39b6759ba110852d17df0693e"),
        from_hex("16f49bc727e45a2f7bf3056efcf8b6d38539c4163a5f1e706743db15af91860f"),
        from_hex("1abe1deb45b3e3119954175efb331bf4568feaf7ea8b3dc5e1a4e7438dd39e5f"),
        from_hex("0e426ccab66984d1d8993a74ca548b779f5db92aaec5f102020d34aea15fba59"),
        from_hex("0e7c30c2e2e8957f4933bd1942053f1f0071684b902d534fa841924303f6a6c6"),
        from_hex("0812a017ca92cf0a1622708fc7edff1d6166ded6e3528ead4c76e1f31d3fc69d"),
        from_hex("21a5ade3df2bc1b5bba949d1db96040068afe5026edd7a9c2e276b47cf010d54"),
        from_hex("01f3035463816c84ad711bf1a058c6c6bd101945f50e5afe72b1a5233f8749ce"),
        from_hex("0b115572f038c0e2028c2aafc2d06a5e8bf2f9398dbd0fdf4dcaa82b0f0c1c8b"),
        from_hex("1c38ec0b99b62fd4f0ef255543f50d2e27fc24db42bc910a3460613b6ef59e2f"),
        from_hex("1c89c6d9666272e8425c3ff1f4ac737b2f5d314606a297d4b1d0b254d880c53e"),
        from_hex("03326e643580356bf6d44008ae4c042a21ad4880097a5eb38b71e2311bb88f8f"),
        from_hex("268076b0054fb73f67cee9ea0e51e3ad50f27a6434b5dceb5bdde2299910a4c9"),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::bls12_381::tests::consistent_perm_helper, Poseidon2};

    #[test]
    fn consistent_perm() {
        consistent_perm_helper::<Fr, 3, Poseidon2ParamsBn3>();
    }

    // copied from <https://github.com/HorizenLabs/poseidon2/blob/055bde3f4782731ba5f5ce5888a440a94327eaf3/plain_implementations/src/poseidon2/poseidon2.rs#L425>
    #[test]
    fn fixed_test_vector() {
        let mut input = [Fr::from(0), Fr::from(1), Fr::from(2)];
        Poseidon2::permute_mut::<Poseidon2ParamsBn3, 3>(&mut input);
        assert_eq!(
            input[0],
            from_hex("0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033")
        );
        assert_eq!(
            input[1],
            from_hex("303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570")
        );
        assert_eq!(
            input[2],
            from_hex("1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8")
        );
    }
}
