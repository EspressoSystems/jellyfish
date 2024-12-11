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

define_poseidon2_params!(
    Poseidon2ParamsBls3,
    3,             // State size
    5,             // S-box size
    8,             // External rounds
    56,            // Internal rounds
    RC3_EXT,       // External round constants
    RC3_INT,       // Internal round constants
    MAT_DIAG3_M_1  // Diagonal matrix constant
);

// adapted from <https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2_instance_bls12.rs>
lazy_static! {
    /// internal diagonal matrix, state size = 2
    pub static ref MAT_DIAG2_M_1: [Fr; 2] = [
        from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
        from_hex("0000000000000000000000000000000000000000000000000000000000000002"),
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

    /// internal diagonal matrix, state size = 3
    pub static ref MAT_DIAG3_M_1: [Fr; 3] = [
        from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
        from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
        from_hex("0000000000000000000000000000000000000000000000000000000000000002"),
    ];

    /// external round constants, state size = 3
    pub static ref RC3_EXT: [[Fr; 3]; 8] = [
        [
            from_hex("6f007a551156b3a449e44936b7c093644a0ed33f33eaccc628e942e836c1a875"),
            from_hex("360d7470611e473d353f628f76d110f34e71162f31003b7057538c2596426303"),
            from_hex("4b5fec3aa073df44019091f007a44ca996484965f7036dce3e9d0977edcdc0f6"),
        ],
        [
            from_hex("67cf1868af6396c0b84cce715e539f849e06cd1c383ac5b06100c76bcc973a11"),
            from_hex("555db4d1dced819f5d3de70fde83f1c7d3e8c98968e516a23a771a5c9c8257aa"),
            from_hex("2bab94d7ae222d135dc3c6c5febfaa314908ac2f12ebe06fbdb74213bf63188b"),
        ],
        [
            from_hex("66f44be5296682c4fa7882799d6dd049b6d7d2c950ccf98cf2e50d6d1ebb77c2"),
            from_hex("150c93fef652fb1c2bf03e1a29aa871fef77e7d736766c5d0939d92753cc5dc8"),
            from_hex("3270661e68928b3a955d55db56dc57c103cc0a60141e894e14259dce537782b2"),
        ],
        [
            from_hex("073f116f04122e25a0b7afe4e2057299b407c370f2b5a1ccce9fb9ffc345afb3"),
            from_hex("409fda22558cfe4d3dd8dce24f69e76f8c2aaeb1dd0f09d65e654c71f32aa23f"),
            from_hex("2a32ec5c4ee5b1837affd09c1f53f5fd55c9cd2061ae93ca8ebad76fc71554d8"),
        ],
        [
            from_hex("6cbac5e1700984ebc32da15b4bb9683faabab55f67ccc4f71d9560b3475a77eb"),
            from_hex("4603c403bbfa9a17738a5c6278eaab1c37ec30b0737aa2409fc4898069eb983c"),
            from_hex("6894e7e22b2c1d5c70a712a6345ae6b192a9c833a9234c31c56aacd16bc2f100"),
        ],
        [
            from_hex("5be2cbbc44053ad08afa4d1eabc7f3d231eea799b93f226e905b7d4d65c58ebb"),
            from_hex("58e55f287b453a9808624a8c2a353d528da0f7e713a5c6d0d7711e47063fa611"),
            from_hex("366ebfafa3ad381c0ee258c9b8fdfccdb868a7d7e1f1f69a2b5dfcc5572555df"),
        ],
        [
            from_hex("45766ab728968c642f90d97ccf5504ddc10518a819ebbcc4d09c3f5d784d67ce"),
            from_hex("39678f65512f1ee404db3024f41d3f567ef66d89d044d022e6bc229e95bc76b1"),
            from_hex("463aed1d2f1f955e3078be5bf7bfc46fc0eb8c51551906a8868f18ffae30cf4f"),
        ],
        [
            from_hex("21668f016a8063c0d58b7750a3bc2fe1cf82c25f99dc01a4e534c88fe53d85fe"),
            from_hex("39d00994a8a5046a1bc749363e98a768e34dea56439fe1954bef429bc5331608"),
            from_hex("4d7f5dcd78ece9a933984de32c0b48fac2bba91f261996b8e9d1021773bd07cc"),
        ]
    ];

    /// internal round constants, state size = 3
    pub static ref RC3_INT: [Fr; 56] = [
        from_hex("5848ebeb5923e92555b7124fffba5d6bd571c6f984195eb9cfd3a3e8eb55b1d4"),
        from_hex("270326ee039df19e651e2cfc740628ca634d24fc6e2559f22d8ccbe292efeead"),
        from_hex("27c6642ac633bc66dc100fe7fcfa54918af895bce012f182a068fc37c182e274"),
        from_hex("1bdfd8b01401c70ad27f57396989129d710e1fb6ab976a459ca18682e26d7ff9"),
        from_hex("491b9ba6983bcf9f05fe4794adb44a30879bf8289662e1f57d90f672414e8a4a"),
        from_hex("162a14c62f9a89b814b9d6a9c84dd678f4f6fb3f9054d373c832d824261a35ea"),
        from_hex("2d193e0f76de586b2af6f79e3127feeaac0a1fc71e2cf0c0f79824667b5b6bec"),
        from_hex("46efd8a9a262d6d8fdc9ca5c04b0982f24ddcc6e9863885a6a732a3906a07b95"),
        from_hex("509717e0c200e3c92d8dca2973b3db45f0788294351ad07ae75cbb780693a798"),
        from_hex("7299b28464a8c94fb9d4df61380f39c0dca9c2c014118789e227252820f01bfc"),
        from_hex("044ca3cc4a85d73b81696ef1104e674f4feff82984990ff85d0bf58dc8a4aa94"),
        from_hex("1cbaf2b371dac6a81d0453416d3e235cb8d9e2d4f314f46f6198785f0cd6b9af"),
        from_hex("1d5b2777692c205b0e6c49d061b6b5f4293c4ab038fdbbdc343e07610f3fede5"),
        from_hex("56ae7c7a5293bdc23e85e1698c81c77f8ad88c4b33a5780437ad047c6edb59ba"),
        from_hex("2e9bdbba3dd34bffaa30535bdd749a7e06a9adb0c1e6f962f60e971b8d73b04f"),
        from_hex("2de11886b18011ca8bd5bae36969299fde40fbe26d047b05035a13661f22418b"),
        from_hex("2e07de1780b8a70d0d5b4a3f1841dcd82ab9395c449be947bc998884ba96a721"),
        from_hex("0f69f1854d20ca0cbbdb63dbd52dad16250440a99d6b8af3825e4c2bb74925ca"),
        from_hex("5dc987318e6e59c1afb87b655dd58cc1d22e513a05838cd4585d04b135b957ca"),
        from_hex("48b725758571c9df6c01dc639a85f07297696b1bb678633a29dc91de95ef53f6"),
        from_hex("5e565e08c0821099256b56490eaee1d573afd10bb6d17d13ca4e5c611b2a3718"),
        from_hex("2eb1b25417fe17670d135dc639fb09a46ce5113507f96de9816c059422dc705e"),
        from_hex("115cd0a0643cfb988c24cb44c3fab48aff36c661d26cc42db8b1bdf4953bd82c"),
        from_hex("26ca293f7b2c462d066d7378b999868bbb57ddf14e0f958ade801612311d04cd"),
        from_hex("4147400d8e1aaccf311a6b5b762011ab3e45326e4d4b9de26992816b99c528ac"),
        from_hex("6b0db7dccc4ba1b268f6bdcc4d372848d4a72976c268ea30519a2f73e6db4d55"),
        from_hex("17bf1b93c4c7e01a2a830aa162412cd90f160bf9f71e967ff5209d14b24820ca"),
        from_hex("4b431cd9efedbc94cf1eca6f9e9c1839d0e66a8bffa8c8464cac81a39d3cf8f1"),
        from_hex("35b41a7ac4f3c571a24f8456369c85dfe03c0354bd8cfd3805c86f2e7dc293c5"),
        from_hex("3b1480080523c439435927994849bea964e14d3beb2dddde72ac156af435d09e"),
        from_hex("2cc6810031dc1b0d4950856dc907d57508e286442a2d3eb2271618d874b14c6d"),
        from_hex("6f4141c8401c5a395ba6790efd71c70c04afea06c3c92826bcabdd5cb5477d51"),
        from_hex("25bdbbeda1bde8c1059618e2afd2ef999e517aa93b78341d91f318c09f0cb566"),
        from_hex("392a4a8758e06ee8b95f33c25dde8ac02a5ed0a27b61926cc6313487073f7f7b"),
        from_hex("272a55878a08442b9aa6111f4de009485e6a6fd15db89365e7bbcef02eb5866c"),
        from_hex("631ec1d6d28dd9e824ee89a30730aef7ab463acfc9d184b355aa05fd6938eab5"),
        from_hex("4eb6fda10fd0fbde02c7449bfbddc35bcd8225e7e5c3833a0818a100409dc6f2"),
        from_hex("2d5b308b0cf02cdfefa13c4e60e26239a6ebba011694dd129b925b3c5b21e0e2"),
        from_hex("16549fc6af2f3b72dd5d293d72e2e5f244dff42f18b46c56ef38c57c311673ac"),
        from_hex("42332677ff359c5e8db836d9f5fb54822e39bd5e22340bb9ba975ba1a92be382"),
        from_hex("49d7d2c0b449e5179bc5ccc3b44c6075d9849b5610465f09ea725ddc97723a94"),
        from_hex("64c20fb90d7a003831757cc4c6226f6e4985fc9ecb416b9f684ca0351d967904"),
        from_hex("59cff40de83b52b41bc443d7979510d771c940b9758ca820fe73b5c8d5580934"),
        from_hex("53db2731730c39b04edd875fe3b7c882808285cdbc621d7af4f80dd53ebb71b0"),
        from_hex("1b10bb7a82afce39fa69c3a2ad52f76d76398265344203119b7126d9b46860df"),
        from_hex("561b6012d666bfe179c4dd7f84cdd1531596d3aac7c5700ceb319f91046a63c9"),
        from_hex("0f1e7505ebd91d2fc79c2df7dc98a3bed1b36968ba0405c090d27f6a00b7dfc8"),
        from_hex("2f313faf0d3f6187537a7497a3b43f46797fd6e3f18eb1caff457756b819bb20"),
        from_hex("3a5cbb6de450b481fa3ca61c0ed15bc55cad11ebf0f7ceb8f0bc3e732ecb26f6"),
        from_hex("681d93411bf8ce63f6716aefbd0e24506454c0348ee38fabeb264702714ccf94"),
        from_hex("5178e940f50004312646b436727f0e80a7b8f2e9ee1fdc677c4831a7672777fb"),
        from_hex("3dab54bc9bef688dd92086e253b439d651baa6e20f892b62865527cbca915982"),
        from_hex("4b3ce75311218f9ae905f84eaa5b2b3818448bbf3972e1aad69de321009015d0"),
        from_hex("06dbfb42b979884de280d31670123f744c24b33b410fefd4368045acf2b71ae3"),
        from_hex("068d6b4608aae810c6f039ea1973a63eb8d2de72e3d2c9eca7fc32d22f18b9d3"),
        from_hex("4c5c254589a92a36084a57d3b1d964278acc7e4fe8f69f2955954f27a79cebef"),
    ];
}

#[cfg(test)]
pub(crate) mod tests {
    use ark_ff::PrimeField;
    use ark_std::test_rng;

    use super::*;
    use crate::Poseidon2;

    pub(crate) fn consistent_perm_helper<
        F: PrimeField,
        const N: usize,
        P: Poseidon2Params<F, N>,
    >() {
        let rng = &mut test_rng();
        for _ in 0..10 {
            let input1 = [F::rand(rng); N];
            let input2 = [F::rand(rng); N];

            // same input get the same permutated output
            assert_eq!(
                Poseidon2::permute::<P, N>(&input1),
                Poseidon2::permute::<P, N>(&input1)
            );
            // diff input get diff permutated output
            assert_ne!(
                Poseidon2::permute::<P, N>(&input1),
                Poseidon2::permute::<P, N>(&input2)
            );
        }
    }
    #[test]
    fn consistent_perm() {
        consistent_perm_helper::<Fr, 2, Poseidon2ParamsBls2>();
        consistent_perm_helper::<Fr, 3, Poseidon2ParamsBls3>();
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

        let mut input = [Fr::from(0), Fr::from(1), Fr::from(2)];
        Poseidon2::permute_mut::<Poseidon2ParamsBls3, 3>(&mut input);
        assert_eq!(
            input[0],
            from_hex("1b152349b1950b6a8ca75ee4407b6e26ca5cca5650534e56ef3fd45761fbf5f0")
        );
        assert_eq!(
            input[1],
            from_hex("4c5793c87d51bdc2c08a32108437dc0000bd0275868f09ebc5f36919af5b3891")
        );
        assert_eq!(
            input[2],
            from_hex("1fc8ed171e67902ca49863159fe5ba6325318843d13976143b8125f08b50dc6b")
        );
    }
}
