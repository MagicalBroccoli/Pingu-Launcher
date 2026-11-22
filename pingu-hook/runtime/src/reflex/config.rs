//! `PINGU_LEGACY_PROFILE` handling: a process-wide flag, read once at
//! startup, that forces the legacy CPU/KUSER presentation for the whole
//! process rather than letting `cpuid.rs`'s per-caller Reflex-image
//! detection decide it. Kept in its own tiny module (rather than inline in
//! `cpuid.rs`) because it's read from an `.init_array` constructor before
//! most other runtime state exists.
use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, Ordering};

static LEGACY_PROFILE: AtomicBool = AtomicBool::new(false);

pub(crate) fn legacy_profile_forced() -> bool {
    LEGACY_PROFILE.load(Ordering::Acquire)
}

fn env_flag_set(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"1"
}

unsafe extern "C" fn initialize() {
    if crate::path::is_reflex() {
        LEGACY_PROFILE.store(env_flag_set(c"PINGU_LEGACY_PROFILE"), Ordering::Release);
    }
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
