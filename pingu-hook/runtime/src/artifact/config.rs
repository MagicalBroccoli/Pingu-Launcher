//! Startup-only runtime option selectors, with no environment reads in traps.
use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static RESOLVER_BRIDGE: AtomicBool = AtomicBool::new(false);

/// `PINGU_VBS20`: 1 forces the VBS 2.0 hypervisor's CPU and KUSER view,
/// 0 forces VBS 1.9; unset (or anything else) selects automatically.
static VBS20: AtomicU8 = AtomicU8::new(VBS20_AUTO);
const VBS20_AUTO: u8 = 0;
const VBS20_ON: u8 = 1;
const VBS20_OFF: u8 = 2;

/// Set when this process's `artifact.dll` contains the VBS 2.0 marker.
static VBS20_MARKER: AtomicBool = AtomicBool::new(false);

/// `PINGU_SYSCALL_LEAK_TRAP=0` turns off the seccomp trap for Windows
/// syscalls that bypass Wine's syscall user dispatch (diagnosis only).
static SYSCALL_LEAK_TRAP: AtomicBool = AtomicBool::new(true);

pub(crate) fn syscall_leak_trap_enabled() -> bool {
    SYSCALL_LEAK_TRAP.load(Ordering::Acquire)
}

/// The VBS generation for the registered Artifact release: the override,
/// else what its `artifact.dll` was built for (see
/// `pingu_protocol::artifact::profile::select_generation`).
pub(crate) fn artifact_generation() -> pingu_protocol::artifact::profile::Generation {
    let forced = match VBS20.load(Ordering::Acquire) {
        VBS20_ON => Some(true),
        VBS20_OFF => Some(false),
        _ => None,
    };
    pingu_protocol::artifact::profile::select_generation(
        forced,
        VBS20_MARKER.load(Ordering::Acquire),
    )
}

/// Record whether this process's `artifact.dll` contains the VBS 2.0
/// marker. Set once, before Artifact's DllMain runs.
pub(crate) fn set_artifact_vbs20_marker(found: bool) {
    VBS20_MARKER.store(found, Ordering::Release);
}

pub(crate) fn resolver_bridge_enabled() -> bool {
    RESOLVER_BRIDGE.load(Ordering::Acquire)
}

fn env_flag_set(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"1"
}

fn env_flag_off(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"0"
}

unsafe extern "C" fn initialize() {
    if crate::path::is_artifact() {
        // The artifact path needs the resolver bridge; the launcher sets only
        // LD_PRELOAD. "0" remains an explicit opt-out for diagnosis.
        RESOLVER_BRIDGE.store(!env_flag_off(c"PINGU_RESOLVER_BRIDGE"), Ordering::Release);
        VBS20.store(
            if env_flag_set(c"PINGU_VBS20") {
                VBS20_ON
            } else if env_flag_off(c"PINGU_VBS20") {
                VBS20_OFF
            } else {
                VBS20_AUTO
            },
            Ordering::Release,
        );
        SYSCALL_LEAK_TRAP.store(!env_flag_off(c"PINGU_SYSCALL_LEAK_TRAP"), Ordering::Release);
    }
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
