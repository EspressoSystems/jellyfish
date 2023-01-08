use std::{
    collections::HashMap,
    fs::File,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use once_cell::sync::Lazy;
use serde::Deserialize;

pub const TREE_HEIGHT: u8 = 21;
pub const NUM_MEMBERSHIP_PROOFS: usize = 1024;

pub const NUM_WIRE_TYPES: usize = 5;

pub const CHUNK_SIZE: usize = 1 << 30;

#[derive(Clone, Deserialize)]
pub struct NetworkConfig {
    pub workers: Vec<SocketAddr>,
    pub dispatcher: IpAddr,
}

#[derive(Clone, Deserialize)]
pub struct GpuConfig {
    // TODO: rename to excluded_ids
    pub disabled_ids: Vec<usize>,
}

pub static DATA_DIR: Lazy<PathBuf> =
    Lazy::new(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("data"));

pub static CONFIG_DIR: Lazy<PathBuf> =
    Lazy::new(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("config"));

pub static NETWOKR_CONFIG: Lazy<NetworkConfig> = Lazy::new(|| {
    serde_json::from_reader(
        File::open(CONFIG_DIR.join("network.json")).unwrap(),
    )
    .unwrap()
});

pub static GPU_CONFIG: Lazy<GpuConfig> = Lazy::new(|| {
    serde_json::from_reader(
        File::open(CONFIG_DIR.join("gpu.json")).unwrap(),
    )
    .unwrap()
});

pub static WORKERS: Lazy<&'static [SocketAddr]> = Lazy::new(|| &NETWOKR_CONFIG.workers);

pub static IP_NAME_MAP: Lazy<HashMap<IpAddr, String>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(NETWOKR_CONFIG.dispatcher, "Dispatcher".to_string());
    for (i, addr) in NETWOKR_CONFIG.workers.iter().enumerate() {
        map.insert(addr.ip(), format!("Worker{}", i));
    }
    map
});
