use std::{
    mem::size_of,
    slice::{from_raw_parts, from_raw_parts_mut},
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

pub trait CastSlice<From> where Self: AsRef<[From]> {
    #[inline]
    fn cast<To>(&self) -> &[To] {
        let slice = self.as_ref();
        unsafe { from_raw_parts(slice as *const _ as *const To, slice.len() * size_of::<From>() / size_of::<To>()) }
    }

    #[inline]
    fn cast_mut<To>(&mut self) -> &mut [To] {
        let slice = self.as_ref();
        unsafe { from_raw_parts_mut(slice as *const _ as *mut To, slice.len() * size_of::<From>() / size_of::<To>()) }
    }
}

impl<From> CastSlice<From> for &[From] {}
impl<From> CastSlice<From> for [From] {}
