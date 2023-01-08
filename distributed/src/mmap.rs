use std::{
    fs::File,
    io,
    mem::size_of,
    ops::{Deref, DerefMut},
    os::fd::AsRawFd,
    ptr,
    slice::{from_raw_parts, from_raw_parts_mut},
    sync::atomic::{AtomicUsize, Ordering},
};

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
