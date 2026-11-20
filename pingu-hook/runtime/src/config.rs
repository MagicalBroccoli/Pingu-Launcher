//! Process-wide flags, read once at startup: `PINGU_LEGACY_PROFILE` forces the
//! legacy CPU/KUSER presentation for the whole process rather than letting
//! `cpuid.rs`'s per-caller Reflex-image detection decide it,
//! `PINGU_ARTIFACT_PROTOCOL` enables the Artifact registration protocol and
//! `PINGU_ARTIFACT_VARIANT=3` forces Artifact variant 3. Kept in its own tiny
//! module (rather than inline in `cpuid.rs`) because it's read from an
//! `.init_array` constructor before most other runtime state exists.
#[cfg(feature = "cpuid")]
use core::ffi::CStr;
#[cfg(feature = "cpuid")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "cpuid")]
static LEGACY_PROFILE: AtomicBool = AtomicBool::new(false);

#[cfg(all(
    feature = "cpuid",
    feature = "reflex",
    feature = "syscall",
    feature = "kuser"
))]
static ARTIFACT_PROTOCOL: AtomicBool = AtomicBool::new(false);

#[cfg(all(
    feature = "cpuid",
    feature = "reflex",
    feature = "syscall",
    feature = "kuser"
))]
static ARTIFACT_VARIANT3: AtomicBool = AtomicBool::new(false);

#[cfg(all(
    feature = "cpuid",
    feature = "reflex",
    feature = "syscall",
    feature = "kuser"
))]
pub(crate) fn artifact_protocol_enabled() -> bool {
    ARTIFACT_PROTOCOL.load(Ordering::Acquire)
}

#[cfg(all(
    feature = "cpuid",
    feature = "reflex",
    feature = "syscall",
    feature = "kuser"
))]
pub(crate) fn artifact_variant3_forced() -> bool {
    ARTIFACT_VARIANT3.load(Ordering::Acquire)
}

#[cfg(feature = "cpuid")]
pub(crate) fn legacy_profile_forced() -> bool {
    LEGACY_PROFILE.load(Ordering::Acquire)
}

#[cfg(feature = "cpuid")]
fn env_is(name: &CStr, expected: &[u8]) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == expected
}

unsafe extern "C" fn initialize() {
    #[cfg(feature = "cpuid")]
    LEGACY_PROFILE.store(env_is(c"PINGU_LEGACY_PROFILE", b"1"), Ordering::Release);
    #[cfg(all(
        feature = "cpuid",
        feature = "reflex",
        feature = "syscall",
        feature = "kuser"
    ))]
    ARTIFACT_PROTOCOL.store(env_is(c"PINGU_ARTIFACT_PROTOCOL", b"1"), Ordering::Release);
    #[cfg(all(
        feature = "cpuid",
        feature = "reflex",
        feature = "syscall",
        feature = "kuser"
    ))]
    ARTIFACT_VARIANT3.store(env_is(c"PINGU_ARTIFACT_VARIANT", b"3"), Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
