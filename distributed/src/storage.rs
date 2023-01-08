use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    mem::size_of,
    path::{Path, PathBuf},
};

use crate::{mmap::Mmap, utils::CastSlice};

pub struct SliceStorage {
    pub path: PathBuf,
}

impl SliceStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self { path: PathBuf::from(path.as_ref()) }
    }

    pub fn create(&self) -> io::Result<()> {
        File::create(&self.path)?;
        Ok(())
    }

    pub fn append<T>(&self, data: &[T]) -> io::Result<()> {
        BufWriter::new(OpenOptions::new().append(true).open(&self.path)?).write_all(data.cast())
    }

    pub fn store<T>(&self, data: &[T]) -> io::Result<()> {
        BufWriter::new(File::create(&self.path)?).write_all(data.cast())
    }

    pub fn load<T>(&self) -> io::Result<Vec<T>> {
        let file = File::open(&self.path)?;
        let len = file.metadata()?.len() as usize / size_of::<T>();
        let mut data = Vec::with_capacity(len);
        unsafe { data.set_len(len) };
        BufReader::new(file).read_exact(data.cast_mut())?;
        Ok(data)
    }

    pub fn mmap<T>(&self) -> io::Result<Mmap<T>> {
        let file = File::open(&self.path)?;
        unsafe { Mmap::map(&file) }
    }

    pub fn store_and_mmap<T>(&self, data: &[T]) -> io::Result<Mmap<T>> {
        self.store(data)?;
        self.mmap()
    }
}
