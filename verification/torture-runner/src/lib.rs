//! I/O fault-injection harness — the Rust-faithful analog of curl's
//! allocation-failure torture testing.
//!
//! # Why I/O, not allocation
//!
//! curl's `torture` model overrides `malloc` to fail on the Nth call,
//! exercising every out-of-memory path in C code. That model does **not**
//! transfer cleanly to Rust: safe-Rust collection APIs (`Vec::with_capacity`,
//! `Box::new`, `String::from`, etc.) abort the process via
//! `handle_alloc_error` on null-return from `GlobalAlloc` — they do not
//! return `Result<_, AllocError>`. There is no stable Rust pathway from
//! "alloc returns null" to a clean `Err` propagation, so "fail Nth alloc"
//! in Rust produces aborts, not the `Result` error-path exercise we want.
//!
//! The Rust analog is **I/O fault injection**. Every `?` operator on an
//! `std::io::Read` (and every error variant in `WSError`/`CoreError`) is a
//! reachable error path *by design*. If we can drive a `Read` impl that
//! returns an `Err` at a chosen byte offset, we exercise the same kind of
//! "every error branch reached" coverage curl's torture model achieves —
//! but on the surface Rust actually surfaces errors on.
//!
//! # Workflow
//!
//! For a target function `f(reader) -> Result<_, _>` and a valid byte input
//! of length `N`, the torture runner:
//!
//! 1. Calls `f` once on the full input (no fault) — sanity-check it
//!    returns `Ok` and the function actually consumes input.
//! 2. Re-runs `f` `N + 1` times, each with a `FaultyReader` that returns
//!    `Err(ErrorKind::Interrupted)` after byte `k` (for `k = 0..=N`).
//! 3. Asserts that **every** run returns cleanly — `Ok(_)` if `f`
//!    happened to finish before the fault point, `Err(_)` otherwise. A
//!    `panic` from any run is a torture failure.
//!
//! This guarantees the target's error handling reaches every byte offset
//! at which a real I/O error could occur — corrupt files, truncated
//! network reads, short syscall returns.

use std::io::{Read, Result as IoResult};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// A `Read` that returns the first `fail_at` bytes of `data` cleanly, then
/// returns `ErrorKind::Interrupted` on every subsequent call.
pub struct FaultyReader<'a> {
    data: &'a [u8],
    fail_at: usize,
    bytes_read: usize,
}

impl<'a> FaultyReader<'a> {
    pub fn new(data: &'a [u8], fail_at: usize) -> Self {
        Self {
            data,
            fail_at,
            bytes_read: 0,
        }
    }
}

impl<'a> Read for FaultyReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // EOF wins over fault: once the input is exhausted, no more "reads"
        // can plausibly happen — surfacing a fault past EOF would test a
        // scenario the OS never produces. This also makes the "fail_at >=
        // input.len()" run a clean no-fault sanity check.
        if self.bytes_read >= self.data.len() {
            return Ok(0);
        }
        if self.bytes_read >= self.fail_at {
            // `ErrorKind::Other` (NOT `Interrupted`) — `std::io::Read`
            // documents that callers SHOULD retry `Interrupted`, and several
            // stdlib wrappers (BufReader, read_to_end, …) silently auto-retry
            // it. Using `Other` makes the fault terminal so the target's
            // error path actually fires.
            return Err(std::io::Error::other(
                "torture: injected fault at requested offset",
            ));
        }
        let remaining = self.data.len() - self.bytes_read;
        let cap_to_fault = self.fail_at - self.bytes_read;
        let to_read = remaining.min(buf.len()).min(cap_to_fault);
        if to_read == 0 {
            return Ok(0);
        }
        buf[..to_read].copy_from_slice(&self.data[self.bytes_read..self.bytes_read + to_read]);
        self.bytes_read += to_read;
        Ok(to_read)
    }
}

/// Outcome of a single torture iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Target returned `Ok` — the fault point was past where the target read.
    Ok,
    /// Target returned `Err` — the fault was surfaced cleanly through the
    /// target's error path.
    Err,
    /// Target panicked — torture failure.
    Panic,
}

/// Drive `target` against every byte offset of `input` as a fault point.
///
/// Returns one `Outcome` per offset `0..=input.len()`. Prints a summary.
/// Panics if any iteration panicked (the torture failure condition).
pub fn torture_io<T, R>(label: &str, input: &[u8], target: T) -> Vec<Outcome>
where
    T: Fn(&mut FaultyReader<'_>) -> Result<(), R>,
{
    let mut outcomes = Vec::with_capacity(input.len() + 1);
    let mut ok = 0usize;
    let mut err = 0usize;
    let mut panicked = 0usize;
    let mut panic_points = Vec::new();

    for fail_at in 0..=input.len() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut reader = FaultyReader::new(input, fail_at);
            target(&mut reader)
        }));
        let outcome = match result {
            Ok(Ok(())) => {
                ok += 1;
                Outcome::Ok
            }
            Ok(Err(_)) => {
                err += 1;
                Outcome::Err
            }
            Err(_) => {
                panicked += 1;
                panic_points.push(fail_at);
                Outcome::Panic
            }
        };
        outcomes.push(outcome);
    }

    println!(
        "[{label}] input {} bytes — {} fault points exercised: ok={ok} err={err} panic={panicked}",
        input.len(),
        outcomes.len()
    );

    if panicked > 0 {
        panic!(
            "[{label}] TORTURE FAILURE — {} panic(s) at fault offsets {:?}",
            panicked, panic_points
        );
    }

    outcomes
}
