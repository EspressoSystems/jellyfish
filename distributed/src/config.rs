use std::net::SocketAddr;

use serde::Deserialize;

#[derive(Clone, Deserialize, Default)]
pub struct NetworkConfig {
    pub slaves: Vec<SocketAddr>,
    pub peers: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct FftWorkload {
    pub row_start: usize,
    pub row_end: usize,
    pub col_start: usize,
    pub col_end: usize,
}

impl FftWorkload {
    pub const fn num_rows(&self) -> usize {
        self.row_end - self.row_start
    }

    pub const fn num_cols(&self) -> usize {
        self.col_end - self.col_start
    }
}

#[derive(Clone, Debug)]
pub struct MsmWorkload {
    pub start: usize,
    pub end: usize,
}
