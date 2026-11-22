//! Syscall interception, split along the three independent boundaries
//! `docs/protocol/syscall-routing.md` names: the KUSER dispatcher bridge
//! (`kuser_dispatch`) that classifies calls arriving through Wine's KUSER
//! dispatcher slot, the SIGSYS router (`sigsys_router`) that decides
//! Wine-vs-Reflex for a trapped syscall, a fixup (`pe_stub_layout`) for
//! anti-tamper code that expects Windows' own thunk bytes, and one narrow
//! Wine window-list compatibility fix (`win32u_zero_list`). This file is a
//! thin facade: it declares the submodules and re-exports the few entry
//! points other files in `runtime/` call by name.

#[cfg(feature = "debug")]
mod diagnostics;
mod kuser_dispatch;
mod markers;
mod mem;
mod pe_export;
pub(crate) mod pe_stub_layout;
mod sigsys_router;

pub(crate) use sigsys_router::syscallhook;
mod unixlib_repair;
mod win32u_zero_list;

#[cfg(feature = "debug")]
pub(crate) fn trace_null_fault(address: usize, rip: u64, tid: u64) {
    diagnostics::dump_on_null_fault(address, rip, tid);
}

pub(crate) fn register_reflex_dispatch_handler(handler: u64) {
    kuser_dispatch::register_reflex_dispatch_handler(handler);
}

pub(crate) fn install_wine_syscall_dispatcher_bridge() -> bool {
    kuser_dispatch::install()
}
