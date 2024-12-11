//! Poseidon2 constants for the scalar field of BLS12-381

use super::from_hex;
use crate::{define_poseidon2_params, Poseidon2Params};
use ark_bls12_381::Fr;
use lazy_static::lazy_static;

define_poseidon2_params!(
    Poseidon2ParamsBls2,
    2,             // State size
    5,             // S-box size
    8,             // External rounds
    56,            // Internal rounds
    RC2_EXT,       // External round constants
    RC2_INT,       // Internal round constants
    MAT_DIAG2_M_1  // Diagonal matrix constant
);

// adapted from <https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2_instance_bls12.rs>
lazy_static! {
    /// internal diagonal matrix, state size = 2
    pub static ref MAT_DIAG2_M_1: [Fr; 2] = [
        from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
        from_hex("0000000000000000000000000000000000000000000000000000000000000002"),
    ];

    /// internal round constants, state size = 2
    pub static ref RC2_INT: [Fr; 56] = [
        from_hex("6c0dc9eb332b5d968bec8ad68fe24ce34087ea54093f153618434475bce402f8"),
        from_hex("0af5bafd335dae5c86967b11d5dcefb986a54c9d60d35eb06dc7a3fd779b3906"),
        from_hex("6e12847918f030f2626c150ab69e4be0f13d202ae1f8bc87ea74323e93372e3b"),
        from_hex("5565d40e21d059a26db241ca125d9316283eadf144b1318e604e253eeae1fe9a"),
        from_hex("608e01b42d3dca09fed9b54eadaaba3e4ce6aefe92b0dc954a0fa4683a9678f2"),
        from_hex("16bbe434b24f94e2c40ed1f4f9bd7d17e5be96c3aec15579b35fd80f0f80de9e"),
        from_hex("0d1be811a8e73220cab01ce981d475522c3d7dd9e2716c3a2cf4ddd541546890"),
        from_hex("5997a3affb18f942868b86f8ee10a68966e90bac7bbd8c65ede7e6e5ef1f6320"),
        from_hex("4d92e86d270041061eec80278079fca771499dea5ccdc99682a953bb3a038b8e"),
        from_hex("616c8c5ce232b9314f694fc6a968446ea9daf7a4079ce1a75fcc950741d680bb"),
        from_hex("677e31e7846d9131bdc350eaf11a8ff918dd258ddd800444424afab34dfdfe3d"),
        from_hex("4e7d7f85aefc110b233525ee3e53851aee7d3241e2a132585e0e25005eee0b0e"),
        from_hex("06a8b4539488b7dddc48c3a226dbda313f906e106f844196d55013d321244f13"),
        from_hex("5091517b6a85783108999f8e6bda3c793bef3f2e9589641d260bdfde8bdef00d"),
        from_hex("0d2703e5b30f54d7f414e901802d54f8c14cd6355415df6e0f063d16bef9c43a"),
        from_hex("56f69096811148eb38eec143d32565c077b3d1a4a4351f2b458f43b1659d4495"),
        from_hex("622d94d38d1ded428afd062008c5709b43a678f6ba518ec56383e8ffba473504"),
        from_hex("2730c607bba7333723a4a44577819b7db82a24574f6d13eee4c856c1ca3de9c7"),
        from_hex("01ac5f59256c5004dc1043c53b23800a3fbab53eb1a83f551056f227b514b9f6"),
        from_hex("0790b92523c973f1c95b94937afbb5796d89481e7a56328b44bab5ba81ae42f3"),
        from_hex("1d63b59d97bc269d13964fb3e8771d0acc749bc83eb2f0372484e266142bb8c0"),
        from_hex("1a52d04e5f14a3a05f7a01262df9e68c77fdf7e2bfb56c8b252d2140efdf0914"),
        from_hex("5aa9b3b808812b284857e8622843a8717fa5cb49b217017f31d79e8d0f963fc0"),
        from_hex("6a3d18fdbeb1d77ec1304539b00e6188786dbbc4435269b4c6281367f42656e3"),
        from_hex("4743e860df269a85dd76fb99dbe9d840eb669dc859754b3f74805e57ba288b00"),
        from_hex("6c32cac3946825f80a434c5ab397fc1a1c6a9bdfaab53175d4cf3d29ddb6cbc6"),
        from_hex("333b0eea5da7ed1e3959d16280a361aa77dd24ecbfb28e1b2583ac4e9894305c"),
        from_hex("3b503fc333b795ccc0c5bb3ae26b077dc3742cb745ec8821648c5ce7ebd9df18"),
        from_hex("4fa5853188d9f728a17532d94bee6fb28fee510380a5d50927c6c5b1ce283444"),
        from_hex("5d2ed8a6603a905bac490ebfb9e6c18f0bc9da1bbc2173291b18de6b6186118f"),
        from_hex("2d830a53584c5556264852f075c78f7f9eb068016ae88af9cda933d6ae52eca7"),
        from_hex("0250f4d6780ad29ae60e55f135b9ac80ccc7c81e3add37db276c26f1a2b1b86e"),
        from_hex("6e3e9595f59220599e23e830728d4a0c4d62515ec1ed10b72446cf4df5b4c308"),
        from_hex("2cd3314555d6faf23ee90cdb884f1c4697ebe98e3a450a624c4d896233b93cd5"),
        from_hex("584a408d0f370543b8413fee70a060a394e561f504d8679f7bece4bf222e4108"),
        from_hex("499cd53437b9fcbf7479c00fcc21295759074ce9bd1bb1fbd3460237aef4759e"),
        from_hex("56a9b567bd0646effd0608d74d537991136098d9a06af6cb3ff8f010efb57578"),
        from_hex("6a5fae2b00d968b931441b374e27ba4d03b306bd602d48731677169e75a67e8c"),
        from_hex("2e1cc28e390e64aa1d60edb99c0aeda7c8c32bdb01ba11abbad5026b46eccb27"),
        from_hex("2d4820000675df7c276beac408fe2e851e734a7008ae09bbcb3c96c70024f71b"),
        from_hex("0c2fe101a2b52b538b902c6b2dc992cb266f7636e05b0c068385b5fa19e97142"),
        from_hex("209b790b78c0e7927c6a178ef2f00b8687fc7bd4f21a9e02578551535002bc95"),
        from_hex("2dd0926cf56bbaaec6491513d08a9983f94a910852a7b4ea4bd4222b93e14c10"),
        from_hex("4316b39dd7d65b1bb575198104d409b169236a7ade371f7ab176fcbae75a5f0d"),
        from_hex("540276d61041b91f6ea3068ec260a9338b6e3da15d934e648c24f35aee04e535"),
        from_hex("37af612900b839977b146324c84772c58a4ccc0f6494cc054571827e74bfd2d3"),
        from_hex("2af00c93d59ed14c9911e5cb3781d772371e83228e4267bbce11d065c1955338"),
        from_hex("62b48779b0cf7ff2c10fd9b91a6ff7b7a99f935e961a5a94aa38f9d4f71c8b4c"),
        from_hex("540bf5bbe01f28563bcbe11a2ce346d8231a2cdd0fe07641f9fa89e5c21978e3"),
        from_hex("232b6c847a6d23912cb10ecbe50b53491f67f71e9b87a4a30446f2218017874b"),
        from_hex("0ab34adbe77b8f1e57a370e4fd626071eea74b3f0b66644a629efaa0e96456c0"),
        from_hex("1a83e43ef118c90046b1bdbeab8dd5cdcab632807c2cd0dc9147cbc5b7084be8"),
        from_hex("1ec6fa41b41b672d9005468720918130b642567462a3d557a595d4dc6c56f2f9"),
        from_hex("01f81a153199a751a111b8f5212cfc5bf82aacf0287d03e1864f8e5713fe4a17"),
        from_hex("2617307587a675f4ecd73a54a7b206162d751cabf3d9fd007bcca4de2c6f0649"),
        from_hex("1647be94c515178c7974a245624b642bb1ae6e2d4e1682087e362d7f98bc953f"),
    ];

    /// external round constants, state size = 2
    pub static ref RC2_EXT: [[Fr; 2]; 8] = [
        [
            from_hex("6267f5556c88257324c1c8b00d5871b2eba13cc39d72aa10dde6b69bc44c41c7"),
            from_hex("30347723511438a085118166c68bf0c4f4ab5c10a2c55adb5cf87cc9e030f60f"),
        ],
        [
            from_hex("10db856965e40038eb6427303181e7b7439f1a051aa4630c26cf86d0a0451a4b"),
            from_hex("5a3d2dcd541e4faaae7eb143eec847a0f652b6dc1b92e3f39ec23c808b3a5d63"),
        ],
        [
            from_hex("3b07f0ff7edcf93b1dd0487bc9fab1c6905f9ceee38dcce83efeb3a320398526"),
            from_hex("40c73c524b9fd0fab63128175befe07b5c63ccdde9ca10e1a37205c9607fdf8a"),
        ],
        [
            from_hex("3a933861cf23752376d94dbb24b0f3c61630787928875c07672b68abfb9191e0"),
            from_hex("71cc165e208570b2d5ef81db84e3c5e714ea4edfb36fc7fb11ef65a64b2d9755"),
        ],
        [
            from_hex("6e690b956e00b9e339dec49d675586f661f9b081ee3fa7696d73977658aa6fea"),
            from_hex("660b85bc22de06d476c47bf084ad436f59874f1d630c0f5c91fbef51d5e738c5"),
        ],
        [
            from_hex("32bf3d451b69dde075fc370eaa8c1b77b5c0bc2aab1c7b46da7ef9d1840b0419"),
            from_hex("73924b40beaa9c1ce4074c2154d1af4d658c09395a568b99b2fbcc3b5685e810"),
        ],
        [
            from_hex("17cbb3ee0adcb9d977e96e9152b36042925244fdd0aa184c7a89a58a2dc40097"),
            from_hex("29d76a821e3220775c552f6b5977ab94956e52b8dac36ef88ace050d553766a3"),
        ],
        [
            from_hex("62b1a6c06ab26881a1fe57eceac56b5aec0b96da7211557f4e27ec24296d7db6"),
            from_hex("0dfc474151e5c605a693a51ae8227cc0a99fdc4524fc2810c6eda9035d04334d"),
        ],
    ];
}

#[cfg(test)]
mod tests {
    use ark_std::{test_rng, UniformRand};

    use super::*;
    use crate::Poseidon2;

    #[test]
    fn consistent_perm() {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let input1 = [Fr::rand(rng), Fr::rand(rng)];
            let input2 = [Fr::rand(rng), Fr::rand(rng)];

            // same input get the same permutated output
            assert_eq!(
                Poseidon2::permute::<Poseidon2ParamsBls2, 2>(&input1),
                Poseidon2::permute::<Poseidon2ParamsBls2, 2>(&input1)
            );
            // diff input get diff permutated output
            assert_ne!(
                Poseidon2::permute::<Poseidon2ParamsBls2, 2>(&input1),
                Poseidon2::permute::<Poseidon2ParamsBls2, 2>(&input2)
            );
        }
    }

    // copied from <https://github.com/HorizenLabs/poseidon2/blob/055bde3f4782731ba5f5ce5888a440a94327eaf3/plain_implementations/src/poseidon2/poseidon2.rs#L425>
    #[test]
    fn fixed_test_vector() {
        let mut input = [Fr::from(0), Fr::from(1)];
        Poseidon2::permute_mut::<Poseidon2ParamsBls2, 2>(&mut input);
        assert_eq!(
            input[0],
            from_hex("73c46dd530e248a87b61d19e67fa1b4ed30fc3d09f16531fe189fb945a15ce4e")
        );
        assert_eq!(
            input[1],
            from_hex("1f0e305ee21c9366d5793b80251405032a3fee32b9dd0b5f4578262891b043b4")
        );
    }
}
