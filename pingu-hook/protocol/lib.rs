//! pingu-hook's safe protocol core: the pure, `no_std`, unsafe-forbidden
//! decision logic for the two compatibility paths, with no knowledge of libc,
//! signals, or process memory. `runtime/` is the unsafe FFI/signal-handling
//! shell that drives this crate.
//!
//! - [`reflex`]: the Reflex/Denuvo protocol (the `Host` trait pattern, CPUID
//!   identities, KUSER patch recipes, per-title quirks).
//! - [`artifact`]: the Artifact VBS 1.9/2.0 protocol (handshake, CPUID
//!   profiles, KUSER identity writes).
//! - The remaining modules are shared: path selection, CPUID register types,
//!   debug line formatting, faketime offset math, Gamescope and Wine
//!   environment string parsing.
//!
//! See `docs/ARCHITECTURE.md` for how the two crates fit together.
#![forbid(unsafe_code)]
#![no_std]

pub mod artifact;
pub mod cpuid;
pub mod debug;
pub mod environment;
pub mod faketime;
pub mod gamescope;
pub mod path;
pub mod reflex;

/// The size of Windows' `KUSER_SHARED_DATA` page.
pub const PAGE_SIZE: usize = 4096;
