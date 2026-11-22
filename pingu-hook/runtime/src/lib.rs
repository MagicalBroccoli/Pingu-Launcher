//! pingu-hook's unsafe runtime shell: the libc/signal/syscall interposition
//! that drives the safe `pingu_protocol` (`protocol/`) crate's decision logic.
//!
//! The library carries two compatibility paths and picks one per process at
//! load time from `PINGU_HOOK_PATH` (`reflex`, the default, or `artifact`):
//!
//! - [`reflex`]: the Reflex/Denuvo protocol.
//! - [`artifact`]: the Artifact VBS 1.9/2.0 protocol.
//!
//! Everything else is shared by both: signal and allocator hooks, debug
//! logging, Gamescope and Wine environment handling, faketime, `INT 2E`
//! emulation and the `/proc` helpers. The libc symbols both paths interpose
//! are exported once, from [`interpose`], and forwarded to the active path.
//! See `docs/ARCHITECTURE.md` for the module map.
//!
//! Compiled to a static library and linked into `pingu-hook.so` by `xtask`,
//! with the exported C ABI surface and linker hardening it verifies.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]
#![cfg_attr(all(not(debug_assertions), panic = "abort"), no_std)]

#[cfg(all(not(debug_assertions), panic = "abort"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { libc::abort() }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
)))]
compile_error!("pingu-hook-runtime requires Linux x86_64 with glibc and 64-bit pointers");

mod clock;
mod errno;
mod int2e;
mod maps;
mod page_guard;
mod procmem;

pub(crate) mod alert;
pub mod artifact;
pub mod debug;
pub mod environment;
pub mod faketime;
pub mod gamescope;
pub mod hooks;
#[cfg(not(test))]
pub mod interpose;
pub mod path;
pub mod reflex;
pub mod registry;
