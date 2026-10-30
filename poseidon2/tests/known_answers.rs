//! Pins the CRHF outputs so a change to the sponge underneath, such as a
//! spongefish or arkworks upgrade, cannot silently change hashes.

use ark_ff::PrimeField;
use jf_crhf::CRHF;
use jf_poseidon2::{
    crhf::{FixedLenPoseidon2Hash, VariableLenPoseidon2Hash},
    sponge::{bls12_381::*, bn254::*},
};

type Bn = ark_bn254::Fr;
type Bls = ark_bls12_381::Fr;

fn inputs<F: PrimeField>(n: u64) -> Vec<F> {
    (1..=n).map(|i| F::from(i * 1_000_003 + 7)).collect()
}

fn decimal<F: PrimeField>(output: &[F]) -> Vec<String> {
    output.iter().map(ToString::to_string).collect()
}

#[test]
fn fixed_len_hash_outputs_are_pinned() {
    assert_eq!(
        decimal(
            &FixedLenPoseidon2Hash::<Bn, Poseidon2SpongeBnN3R1, 3, 1>::evaluate(inputs(3)).unwrap()
        ),
        ["4464458877522364539471584738317999562715830277574510533322401943197155325115"]
    );
    assert_eq!(
        decimal(
            &FixedLenPoseidon2Hash::<Bn, Poseidon2SpongeBnN3R2, 6, 2>::evaluate(inputs(5)).unwrap()
        ),
        [
            "20193035806739619928987409995416624505381783759330867597139903748903823087126",
            "2571266934587040736311003661062364493189718201916932127291330881634346967600",
        ]
    );
    assert_eq!(
        decimal(
            &FixedLenPoseidon2Hash::<Bls, Poseidon2SpongeBlsN2R1, 4, 1>::evaluate(inputs(4))
                .unwrap()
        ),
        ["34305784493878488792890520743896583120236846794354339124775448435521411818808"]
    );
    assert_eq!(
        decimal(
            &FixedLenPoseidon2Hash::<Bls, Poseidon2SpongeBlsN3R2, 4, 3>::evaluate(inputs(4))
                .unwrap()
        ),
        [
            "48634051642301714791839796962009877220562833182194046062128362787737530336740",
            "19026328281981314449935751193092875760286056259672652317257402083300508992385",
            "45861045251147849720982897709487265823785653689302884984840428419478385430248",
        ]
    );
}

#[test]
fn variable_len_hash_outputs_are_pinned() {
    let bn: [(u64, [&str; 2]); 5] = [
        (
            0,
            [
                "2820430044171165092709918704747590965614342875549110429217681435604321658469",
                "19925043150861972771414976152643064823112161093174302135360730904809431098445",
            ],
        ),
        (
            1,
            [
                "5398373259994479392901169664258038529141652410103426463822631506005832464335",
                "2113344489230302425066604638390488436844637840376131857438928968121166956427",
            ],
        ),
        (
            2,
            [
                "3394137167723578248357162209641175924552929124927812870157452855844368477861",
                "20105012542309385987657740625043296408390285727017580531678614834236458145424",
            ],
        ),
        (
            3,
            [
                "18901778702962813694517221752756190364248001201151457653411646886698066278119",
                "8705263765095860638623811022523527484177426547809361537077038456562670331182",
            ],
        ),
        (
            7,
            [
                "7963401822950382000021771154336665239909592035426309292249729266393898359131",
                "16907981892525608269560735260658232936528547187053941080306205046254450285060",
            ],
        ),
    ];
    for (len, expected) in bn {
        assert_eq!(
            decimal(
                &VariableLenPoseidon2Hash::<Bn, Poseidon2SpongeBnN3R1, 2>::evaluate(inputs(len))
                    .unwrap()
            ),
            expected,
            "bn254 input length {len}"
        );
    }

    let bls: [(u64, &str); 5] = [
        (
            0,
            "23747150044703437224482898620069908913220872141521272649776994718382840848787",
        ),
        (
            1,
            "13476928309984997707307163308093103690972919527246282352144284866092349912204",
        ),
        (
            2,
            "33584369615996264140438215350867723572103125590208568614422396572888958612622",
        ),
        (
            3,
            "13229846105570906761319222862620938003154871075647889491659136024518728622511",
        ),
        (
            7,
            "9203913952914498272401141125621519465375161378732979004104466271007539593088",
        ),
    ];
    for (len, expected) in bls {
        assert_eq!(
            decimal(
                &VariableLenPoseidon2Hash::<Bls, Poseidon2SpongeBlsN3R2, 1>::evaluate(inputs(len))
                    .unwrap()
            ),
            [expected],
            "bls12-381 input length {len}"
        );
    }
}
