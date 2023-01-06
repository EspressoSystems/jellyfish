#![feature(array_zip)]
pub mod plonk_capnp {
    include!(concat!(env!("OUT_DIR"), "/protocol/plonk_capnp.rs"));
}
pub mod utils;
pub mod playground;
pub mod playground2;
pub mod playground3;

pub mod config;

pub mod transpose;

pub mod gpu;

pub mod circuit;
pub mod circuit2;
pub mod polynomial;

pub mod worker;
pub mod dispatcher;
pub mod constants;
