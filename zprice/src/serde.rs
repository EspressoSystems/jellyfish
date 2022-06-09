use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    boxed::Box,
    io::{BufReader, Read, Write},
    path::PathBuf,
    print, println,
    time::Instant,
    vec::Vec,
};
use jf_plonk::prelude::*;

const DEFAULT_UNIVERSAL_SRS_FILENAME: &str = "srs";
const DEFAULT_PROVING_KEY_FILENAME: &str = "pk";
const DEFAULT_VERIFICATION_KEY_FILENAME: &str = "vk";

/// Create and store universal parameter in a file.
pub fn store_srs(max_degree: usize, dest: Option<PathBuf>) {
    let mut rng = rand::thread_rng();
    let universal_param =
        PlonkKzgSnark::<Bls12_381>::universal_setup(max_degree, &mut rng).unwrap();
    let dest = match dest {
        Some(dest) => dest,
        None => default_path(DEFAULT_UNIVERSAL_SRS_FILENAME, "bin"),
    };

    let now = Instant::now();
    print!(
        "Storing universal parameter to: {} ...",
        dest.to_str().unwrap()
    );
    store_data(&universal_param, dest);
    println!(" done in {} ms", now.elapsed().as_millis());
}

/// Load universal parameter from a file.
pub fn load_srs(src: Option<PathBuf>) -> Box<UniversalSrs<Bls12_381>> {
    let src = match src {
        Some(src) => src,
        None => default_path(DEFAULT_UNIVERSAL_SRS_FILENAME, "bin"),
    };

    let now = Instant::now();
    print!(
        "Loading universal parameter from: {} ...",
        src.to_str().unwrap()
    );
    let param = load_data(src);
    println!(" done in {} ms", now.elapsed().as_millis());
    Box::new(param)
}

/// Create and store SNARK proving key in a file.
pub fn store_proving_and_verification_key(
    srs: Box<UniversalSrs<Bls12_381>>,
    pk_dest: Option<PathBuf>,
    vk_dest: Option<PathBuf>,
) {
    let mut rng = rand::thread_rng();

    let pk_dest = match pk_dest {
        Some(pk_dest) => pk_dest,
        None => default_path(DEFAULT_PROVING_KEY_FILENAME, "bin"),
    };
    let vk_dest = match vk_dest {
        Some(vk_dest) => vk_dest,
        None => default_path(DEFAULT_VERIFICATION_KEY_FILENAME, "bin"),
    };

    // invoke preprocessing to get proving key and verification key
    let circuit = crate::generate_circuit(&mut rng).unwrap();
    let (pk, vk) = PlonkKzgSnark::<Bls12_381>::preprocess(&srs, &circuit).unwrap();

    // storing proving key
    let now = Instant::now();
    print!("Storing proving key to: {} ...", pk_dest.to_str().unwrap());
    store_data(&pk, pk_dest);
    println!(" done in {} ms", now.elapsed().as_millis());

    // storing verification key
    let now = Instant::now();
    print!(
        "Storing verification key to: {} ...",
        vk_dest.to_str().unwrap()
    );
    store_data(&vk, vk_dest);
    println!(" done in {} ms", now.elapsed().as_millis());
}

/// Load SNARK proving key from a file.
pub fn load_proving_key(src: Option<PathBuf>) -> Box<ProvingKey<'static, Bls12_381>> {
    let src = match src {
        Some(src) => src,
        None => default_path(DEFAULT_PROVING_KEY_FILENAME, "bin"),
    };

    let now = Instant::now();
    print!("Loading proving key from: {} ...", src.to_str().unwrap());
    let pk = load_data(src);
    println!(" done in {} ms", now.elapsed().as_millis());
    Box::new(pk)
}

/// Load SNARK verification key from a file.
pub fn load_verification_key(src: Option<PathBuf>) -> VerifyingKey<Bls12_381> {
    let src = match src {
        Some(src) => src,
        None => default_path(DEFAULT_VERIFICATION_KEY_FILENAME, "bin"),
    };

    let now = Instant::now();
    print!(
        "Loading verification key from: {} ...",
        src.to_str().unwrap()
    );
    let vk = load_data(src);
    println!(" done in {} ms", now.elapsed().as_millis());
    vk
}

// serialize any serde-Serializable data using `bincode` and store to `dest`
fn store_data<T>(data: &T, dest: PathBuf)
where
    T: CanonicalSerialize,
{
    let mut bytes = Vec::new();
    data.serialize_unchecked(&mut bytes).unwrap();
    store_bytes(&bytes, dest);
}

// deserialize any serde-deserializable data using `bincode` from `src`
fn load_data<T>(src: PathBuf) -> T
where
    T: CanonicalDeserialize,
{
    let bytes = load_bytes(src);
    T::deserialize_unchecked(&bytes[..]).unwrap()
}

// by default, all parameters are stored in `$CAP_UNIV_PARAM_DIR/data/`
fn default_path(filename: &str, extension: &str) -> PathBuf {
    let mut d = PathBuf::from(ark_std::env::var("CARGO_MANIFEST_DIR").unwrap());
    d.push("data");
    d.push(filename);
    d.set_extension(extension);
    d
}

fn store_bytes(bytes: &[u8], dest: PathBuf) {
    let mut f = ark_std::fs::File::create(dest).unwrap();
    f.write_all(bytes).unwrap();
}

fn load_bytes(src: PathBuf) -> Vec<u8> {
    let f = ark_std::fs::File::open(src).unwrap();
    let mut reader = BufReader::new(f);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}
