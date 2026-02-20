//! CrashRustler: macOS crash report capture and analysis.
//!
//! This crate provides a Rust equivalent of CrashWrangler's `CrashReport` Objective-C class,
//! capturing all the state needed to represent a macOS crash report including process
//! information, exception details, thread backtraces, binary image mappings, and crash
//! analysis metadata.
//!
//! # Key Types
//!
//! - [`CrashRustler`] — The main crash report struct holding all crash state.
//! - [`ExceptionType`] — Mach exception types (e.g., `EXC_BAD_ACCESS`).
//! - [`CpuType`] — CPU architecture constants (x86, ARM, PowerPC).
//! - [`BinaryImage`] — A loaded binary image in the crashed process.
//!
//! # Example
//!
//! ```
//! use crashrustler::{CrashRustler, CpuType};
//!
//! let mut cr = CrashRustler::default();
//! cr.cpu_type = CpuType::ARM64;
//! cr.is_64_bit = true;
//! cr.exception_type = 1; // EXC_BAD_ACCESS
//! cr.signal = 11; // SIGSEGV
//!
//! assert_eq!(cr.exception_type_description(), "EXC_BAD_ACCESS");
//! assert_eq!(cr.signal_name(), "SIGSEGV");
//! assert_eq!(cr.short_arch_name(), "arm64");
//! ```

mod accessors;
mod analysis;
mod backtrace;
mod crash_rustler;
pub mod exploitability;
mod formatting;
mod init;
mod memory;
mod types;
pub mod unwind;

pub use crash_rustler::CrashRustler;
pub use types::*;

#[cfg(test)]
mod test_helpers;

#[cfg(all(test, target_arch = "aarch64"))]
mod dummy;
