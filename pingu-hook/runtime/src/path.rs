//! Selects the compatibility path of this process. Runs first among the
//! constructors: every module that behaves differently per path reads
//! [`active`] afterwards. Child processes inherit the variable, so a whole
//! Wine/Proton process tree runs one path.
use core::ffi::CStr;
use core::sync::atomic::{AtomicU8, Ordering};
use pingu_protocol::path::HookPath;

const ENV: &CStr = c"PINGU_HOOK_PATH";

static ACTIVE: AtomicU8 = AtomicU8::new(HookPath::Reflex as u8);

pub(crate) fn active() -> HookPath {
    HookPath::from_raw(ACTIVE.load(Ordering::Acquire))
}

pub(crate) fn is_reflex() -> bool {
    active() == HookPath::Reflex
}

pub(crate) fn is_artifact() -> bool {
    active() == HookPath::Artifact
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pingu_setup_path() {
    let value = unsafe { libc::getenv(ENV.as_ptr()) };
    let value = (!value.is_null()).then(|| unsafe { CStr::from_ptr(value) }.to_bytes());
    ACTIVE.store(HookPath::from_env(value) as u8, Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array.00100")]
static INITIALIZE: unsafe extern "C" fn() = pingu_setup_path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_name_matches_the_protocol_constant() {
        assert_eq!(ENV.to_bytes(), HookPath::ENV.as_bytes());
    }
}
