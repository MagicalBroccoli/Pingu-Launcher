//! Interposes `mmap` so pingu-hook observes new mappings for the Artifact loader
//! (`resolver::observe`), CPUID Wine-view cache invalidation
//! (`cpuid::note_mapping`), and file-mapping generation tracking
//! (`maps::note_file_mapping`).

#[cfg(not(test))]
use core::ffi::{c_int, c_void};
#[cfg(not(test))]
use core::ptr;
#[cfg(not(test))]
use core::sync::atomic::{AtomicPtr, Ordering};

#[cfg(not(test))]
static REAL_MMAP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[cfg(not(test))]
type Mmap =
    unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, libc::off_t) -> *mut c_void;

#[cfg(not(test))]
fn resolve(slot: &AtomicPtr<c_void>, name: &core::ffi::CStr) -> *mut c_void {
    let mut symbol = slot.load(Ordering::Acquire);
    if symbol.is_null() {
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) };
        if !symbol.is_null() {
            slot.store(symbol, Ordering::Release);
        }
    }
    symbol
}

/// Excluded from test builds so exporting `mmap` does not self-shadow
/// `libc::mmap` in unit tests or under Miri.
#[cfg(not(test))]
pub(crate) unsafe extern "C" fn mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
) -> *mut c_void {
    let real = {
        let _errno = crate::errno::Errno::save();
        resolve(&REAL_MMAP, c"mmap")
    };
    let result = if real.is_null() {
        unsafe {
            libc::syscall(
                libc::SYS_mmap,
                addr,
                length,
                prot as libc::c_long,
                flags as libc::c_long,
                fd as libc::c_long,
                offset as libc::c_long,
            ) as *mut c_void
        }
    } else {
        unsafe {
            core::mem::transmute::<*mut c_void, Mmap>(real)(addr, length, prot, flags, fd, offset)
        }
    };
    if result != libc::MAP_FAILED {
        crate::artifact::cpuid::note_mapping(result as u64, length as u64);
        if fd >= 0 && flags & libc::MAP_ANONYMOUS == 0 {
            crate::maps::note_file_mapping();
        }
        crate::artifact::resolver::observe(result as usize, prot, fd, offset);
    }
    result
}
