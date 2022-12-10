pub fn serialize<T>(v: &[T]) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            v as *const _ as *const u8,
            v.len() * std::mem::size_of::<T>(),
        )
    }
}

pub fn deserialize<T>(r: &[u8]) -> &[T] {
    unsafe {
        std::slice::from_raw_parts(
            r as *const _ as *const T,
            r.len() / std::mem::size_of::<T>(),
        )
    }
}
