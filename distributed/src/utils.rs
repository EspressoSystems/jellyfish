use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    mem::size_of,
    ops::{Deref, DerefMut},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    ptr,
    slice::{from_raw_parts, from_raw_parts_mut},
    sync::atomic::{AtomicUsize, Ordering},
};

#[macro_export]
macro_rules! timer {
    ($name:expr, $task:expr) => {{
        use ark_std::end_timer;
        let _timer = ark_std::start_timer!(|| $name);
        let _result = $task;
        ark_std::end_timer!(_timer);
        _result
    }};
}

#[macro_export]
macro_rules! set_data {
    ($r:expr, $init_data:ident, $data:expr) => {
        $r.get().$init_data(crate::utils::serialize($data));
    };
}

#[macro_export]
macro_rules! set_chunk {
    ($r:expr, $init_data:ident, $data:expr) => {
        let chunk = crate::utils::serialize($data);
        let mut builder = $r.get().$init_data();
        builder.set_data(chunk);
        builder.set_hash(xxhash_rust::xxh3::xxh3_64(chunk));
    };
}

#[macro_export]
macro_rules! set_chunks {
    ($r:expr, $init_data:ident, $data:expr) => {
        let chunks = crate::utils::serialize($data).chunks(crate::constants::CAPNP_CHUNK_SIZE);
        let mut builder = $r.get().$init_data(chunks.len() as u32);
        for (i, chunk) in chunks.enumerate() {
            let mut t = builder.reborrow().get(i as u32);
            t.set_data(chunk);
            t.set_hash(xxhash_rust::xxh3::xxh3_64(chunk));
        }
    };
}

#[macro_export]
macro_rules! get_req_chunks {
    ($p:expr, $get_data:ident, $action:expr) => {
        for i in $p.$get_data().unwrap() {
            let s = i.get_data().unwrap();
            if xxhash_rust::xxh3::xxh3_64(s) != i.get_hash() {
                return Promise::err(capnp::Error::failed("hash mismatch".into()));
            }
            $action(crate::utils::deserialize(s));
        }
    };
}

#[macro_export]
macro_rules! send_chunks_until_ok {
    ($request:expr) => {
        loop {
            match $request.send().promise.await {
                Ok(r) => break r,
                Err(e) => match e.kind {
                    capnp::ErrorKind::Failed => continue,
                    _ => panic!(),
                },
            }
        }
    };
}

#[macro_export]
macro_rules! receive_chunk_until_ok {
    ($request:expr, $get_data:ident, $action:expr) => {
        loop {
            let res = $request.send().promise.await.unwrap();

            let i = res.get().unwrap().$get_data().unwrap();
            let s = i.get_data().unwrap();
            if xxhash_rust::xxh3::xxh3_64(s) == i.get_hash() {
                $action(crate::utils::deserialize(s));
                break;
            }
        }
    };
}

#[macro_export]
macro_rules! receive_poly_until_ok {
    ($connection:expr, $method:ident, $get_data:ident, $length:expr) => {
        async {
            let mut w: Vec<Fr> = vec![];
            let mut i = 0;
            let step = crate::constants::CAPNP_CHUNK_SIZE / std::mem::size_of::<Fr>();
            while i < $length {
                receive_chunk_until_ok!(
                    {
                        let mut req = $connection.$method();
                        req.get().set_start(i as u64);
                        req.get().set_end(std::cmp::min(i + step, $length) as u64);
                        req
                    },
                    $get_data,
                    |s| w.extend_from_slice(s)
                );
                i += step;
            }
            w
        }
    };
}

extern crate libc;

pub trait ToBuf<T> where Self: AsRef<[T]> {
    fn to_buf(&self) -> &[u8] {
        unsafe { from_raw_parts(self.as_ref() as *const _ as *const u8, self.as_ref().len() * size_of::<T>()) }
    }
}

impl<T> ToBuf<T> for &[T] {}

impl<T> ToBuf<T> for [T] {}

pub trait FromBuf where Self: AsRef<[u8]> {
    fn from_buf<T>(&self) -> &[T] {
        unsafe { from_raw_parts(self.as_ref() as *const _ as *const T, self.as_ref().len() / size_of::<T>()) }
    }

    fn from_buf_mut<T>(&mut self) -> &mut [T] {
        unsafe { from_raw_parts_mut(self.as_ref() as *const _ as *mut T, self.as_ref().len() / size_of::<T>()) }
    }
}

impl FromBuf for &[u8] {}
impl FromBuf for [u8] {}

pub fn serialize<T>(v: &[T]) -> &[u8] {
    unsafe { from_raw_parts(v as *const _ as *const u8, v.len() * size_of::<T>()) }
}

pub fn deserialize<T>(r: &[u8]) -> &[T] {
    unsafe { from_raw_parts(r as *const _ as *const T, r.len() / size_of::<T>()) }
}

fn page_size() -> usize {
    static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

    match PAGE_SIZE.load(Ordering::Relaxed) {
        0 => {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

            PAGE_SIZE.store(page_size, Ordering::Relaxed);

            page_size
        }
        page_size => page_size,
    }
}

pub struct MmapConfig {
    pub path: PathBuf,
}

impl MmapConfig {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self { path: PathBuf::from(path.as_ref()) }
    }

    pub fn create(&self) -> io::Result<()> {
        File::create(&self.path)?;
        Ok(())
    }

    pub fn append<T>(&self, data: &[T]) -> io::Result<()> {
        BufWriter::new(OpenOptions::new().append(true).open(&self.path)?).write_all(serialize(data))
    }

    pub fn store<T>(&self, data: &[T]) -> io::Result<()> {
        BufWriter::new(File::create(&self.path)?).write_all(serialize(data))
    }

    pub fn load<T>(&self) -> io::Result<Mmap<T>> {
        let file = File::open(&self.path)?;
        unsafe { Mmap::map(&file) }
    }
}

pub struct Mmap<T> {
    pub ptr: *const T,
    pub len: usize,
}

impl<T> Mmap<T> {
    pub unsafe fn map(file: &File) -> io::Result<Self> {
        let len = file.metadata()?.len() as usize;

        if len == 0 {
            return Ok(Self::default());
        }

        let ptr = unsafe {
            libc::mmap(ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
        };

        if ptr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { ptr: ptr as *const T, len })
        }
    }
}

impl<T> Drop for Mmap<T> {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        let alignment = self.ptr as usize % page_size();
        let len = self.len + alignment;
        unsafe {
            let ptr = (self.ptr as *mut libc::c_void).offset(-(alignment as isize));
            assert_eq!(0, libc::munmap(ptr, len));
        }
    }
}

unsafe impl<T> Sync for Mmap<T> {}
unsafe impl<T> Send for Mmap<T> {}

impl<T> Default for Mmap<T> {
    fn default() -> Self {
        Mmap { ptr: ptr::null(), len: 0 }
    }
}

impl<T> Deref for Mmap<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        unsafe { from_raw_parts(self.ptr, self.len / size_of::<T>()) }
    }
}

impl<T> AsRef<[T]> for Mmap<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.deref()
    }
}

pub struct MutMmap<T> {
    ptr: *mut T,
    len: usize,
}

impl<T> MutMmap<T> {
    pub unsafe fn map(file: &File) -> io::Result<Self> {
        let len = file.metadata()?.len() as usize;

        if len == 0 {
            return Ok(Self::default());
        }

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { ptr: ptr as *mut T, len })
        }
    }
}

impl<T> Drop for MutMmap<T> {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }
        let alignment = self.ptr as usize % page_size();
        let len = self.len + alignment;
        unsafe {
            let ptr = (self.ptr as *mut libc::c_void).offset(-(alignment as isize));
            assert_eq!(0, libc::munmap(ptr, len));
        }
    }
}

unsafe impl<T> Sync for MutMmap<T> {}
unsafe impl<T> Send for MutMmap<T> {}

impl<T> Default for MutMmap<T> {
    fn default() -> Self {
        MutMmap { ptr: ptr::null_mut(), len: 0 }
    }
}

impl<T> Deref for MutMmap<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        unsafe { from_raw_parts(self.ptr, self.len / size_of::<T>()) }
    }
}

impl<T> DerefMut for MutMmap<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { from_raw_parts_mut(self.ptr, self.len / size_of::<T>()) }
    }
}

impl<T> AsRef<[T]> for MutMmap<T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.deref()
    }
}

impl<T> AsMut<[T]> for MutMmap<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.deref_mut()
    }
}
