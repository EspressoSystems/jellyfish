//! Helper functions for micro-benchmarks

use ark_std::{thread_local, time::Instant};
use core::{cell::RefCell, time::Duration};

thread_local!(static FFT_START_TIME: RefCell<Instant> = RefCell::new(Instant::now()));
thread_local!(static FFT_TIMER_LOCK: RefCell<bool> = RefCell::new(false));
thread_local!(static FFT_TOTAL_TIME: RefCell<Duration> = RefCell::new(Duration::ZERO));

thread_local!(static MSM_START_TIME: RefCell<Instant> = RefCell::new(Instant::now()));
thread_local!(static MSM_TIMER_LOCK: RefCell<bool> = RefCell::new(false));
thread_local!(static MSM_TOTAL_TIME: RefCell<Duration> = RefCell::new(Duration::ZERO));

thread_local!(static POLY_EVAL_START_TIME: RefCell<Instant> = RefCell::new(Instant::now()));
thread_local!(static POLY_EVAL_TIMER_LOCK: RefCell<bool> = RefCell::new(false));
thread_local!(static POLY_EVAL_TOTAL_TIME: RefCell<Duration> = RefCell::new(Duration::ZERO));

/// Initializing the timers
#[inline]
pub fn init_timers() {
    #[cfg(feature = "bench")]
    {
        FFT_TOTAL_TIME.with(|timer| {
            *timer.borrow_mut() = Duration::ZERO;
        });
        FFT_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = false;
        });
        MSM_TOTAL_TIME.with(|timer| {
            *timer.borrow_mut() = Duration::ZERO;
        });
        MSM_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = false;
        });
        POLY_EVAL_TOTAL_TIME.with(|timer| {
            *timer.borrow_mut() = Duration::ZERO;
        });
        POLY_EVAL_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = false;
        });
    }
}

/// Get the total time that we have spend on FFT related computations
#[inline]
pub fn total_fft_time() -> Duration {
    #[cfg(feature = "bench")]
    {
        FFT_TOTAL_TIME.with(|duration| *duration.borrow())
    }
    #[cfg(not(feature = "bench"))]
    Duration::ZERO
}

/// Get the total time that we have spend on MSM related computations
#[inline]
pub fn total_msm_time() -> Duration {
    #[cfg(feature = "bench")]
    {
        MSM_TOTAL_TIME.with(|duration| *duration.borrow())
    }
    #[cfg(not(feature = "bench"))]
    Duration::ZERO
}

/// Get the total time that we have spend on polynomial evaluations
#[inline]
pub fn total_poly_eval_time() -> Duration {
    #[cfg(feature = "bench")]
    {
        POLY_EVAL_TOTAL_TIME.with(|duration| *duration.borrow())
    }
    #[cfg(not(feature = "bench"))]
    Duration::ZERO
}

#[inline]
pub(crate) fn fft_start() {
    #[cfg(feature = "bench")]
    {
        if FFT_TIMER_LOCK.with(|lock| *lock.borrow()) {
            panic!("another FFT timer has already started somewhere else");
        }

        FFT_START_TIME.with(|timer| {
            *timer.borrow_mut() = Instant::now();
        });

        FFT_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = true;
        })
    }
}

#[inline]
pub(crate) fn fft_end() {
    #[cfg(feature = "bench")]
    {
        if !FFT_TIMER_LOCK.with(|lock| *lock.borrow()) {
            panic!("FFT timer has not started yet");
        }

        let start_time = FFT_START_TIME.with(|timer| *timer.borrow());
        let end_time = Instant::now();
        FFT_TOTAL_TIME.with(|duration| {
            *duration.borrow_mut() += end_time - start_time;
        });
        FFT_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = false;
        })
    }
}

#[inline]
pub(crate) fn msm_start() {
    #[cfg(feature = "bench")]
    {
        if MSM_TIMER_LOCK.with(|lock| *lock.borrow()) {
            panic!("another MSM timer has already started somewhere else");
        }

        MSM_START_TIME.with(|timer| {
            *timer.borrow_mut() = Instant::now();
        });

        MSM_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = true;
        })
    }
}

#[inline]
pub(crate) fn msm_end() {
    #[cfg(feature = "bench")]
    {
        if !MSM_TIMER_LOCK.with(|lock| *lock.borrow()) {
            panic!("MSM timer has not started yet");
        }
        let start_time = MSM_START_TIME.with(|timer| *timer.borrow());
        let end_time = Instant::now();
        MSM_TOTAL_TIME.with(|duration| {
            *duration.borrow_mut() += end_time - start_time;
        });
        MSM_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = false;
        })
    }
}

#[inline]
pub(crate) fn poly_eval_start() {
    #[cfg(feature = "bench")]
    {
        if POLY_EVAL_TIMER_LOCK.with(|lock| *lock.borrow()) {
            panic!("another poly eval timer has already started somewhere else");
        }

        POLY_EVAL_START_TIME.with(|timer| {
            *timer.borrow_mut() = Instant::now();
        });

        POLY_EVAL_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = true;
        })
    }
}

#[inline]
pub(crate) fn poly_eval_end() {
    #[cfg(feature = "bench")]
    {
        if !POLY_EVAL_TIMER_LOCK.with(|lock| *lock.borrow()) {
            panic!("poly eval timer has not started yet");
        }
        let start_time = POLY_EVAL_START_TIME.with(|timer| *timer.borrow());
        let end_time = Instant::now();
        POLY_EVAL_TOTAL_TIME.with(|duration| {
            *duration.borrow_mut() += end_time - start_time;
        });
        POLY_EVAL_TIMER_LOCK.with(|lock| {
            *lock.borrow_mut() = false;
        })
    }
}
