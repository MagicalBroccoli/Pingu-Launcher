//! The Reflex/Denuvo path, selected by `PINGU_HOOK_PATH=reflex` (the default).
//! Drives `pingu_protocol::reflex` through its `Host` trait ([`session`]),
//! answers CPUID traps ([`cpuid`]), patches `KUSER_SHARED_DATA` ([`kuser`])
//! and routes trapped syscalls ([`syscall`]).
pub(crate) mod config;
pub(crate) mod cpuid;
pub(crate) mod kuser;
pub(crate) mod session;
pub(crate) mod syscall;
