//! Syscall interception: the KUSER dispatcher bridge (`kuser_dispatch`) that
//! classifies calls arriving through Wine's KUSER dispatcher slot, the SIGSYS
//! router (`sigsys_router`) that routes Artifact SYS_USER_DISPATCH calls,
//! and the `mmap` observer (`pe_stub_layout`) used by the Artifact loader and
//! CPUID mapping tracker.

mod flags;
mod kuser_dispatch;
pub(crate) mod pe_stub_layout;
mod sigsys_router;

pub(crate) use sigsys_router::syscallhook;

pub(crate) fn install_wine_syscall_dispatcher_bridge() -> bool {
    kuser_dispatch::install()
}
