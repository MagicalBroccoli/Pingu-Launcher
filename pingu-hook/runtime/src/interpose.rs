//! The libc functions that the paths interpose, exported once and forwarded
//! to the active path. The path that has no use for a function hands the call
//! on to the next definition (`dlsym(RTLD_NEXT)`, or the raw syscall when that
//! cannot be resolved), so it behaves as if the function were not interposed.
//!
//! | Function | Reflex | Artifact |
//! |---|---|---|
//! | `mmap` | PE stub layout fixups, file-mapping tracking | Loader/resolver observer, file-mapping tracking |
//! | `read`, `pread` | PE stub tail normalization | not interposed |
//! | `mprotect` | not interposed | Loader/resolver observer |
//!
//! The signal, allocator, environment and time interposers (`sigaction`,
//! `malloc`, `free`, `setenv`, `unsetenv`, `gettimeofday`) serve both paths
//! and live in [`hooks`](crate::hooks), [`gamescope`](crate::gamescope) and
//! [`faketime`](crate::faketime).
//!
//! Excluded from test builds so exporting these functions does not shadow
//! libc's own in unit tests or under Miri.

use core::ffi::{CStr, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

type Read = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
type Pread = unsafe extern "C" fn(c_int, *mut c_void, usize, libc::off_t) -> isize;

static REAL_READ: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REAL_PREAD: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

fn resolve(slot: &AtomicPtr<c_void>, name: &CStr) -> *mut c_void {
    let _errno = crate::errno::Errno::save();
    let mut symbol = slot.load(Ordering::Acquire);
    if symbol.is_null() {
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) };
        if !symbol.is_null() {
            slot.store(symbol, Ordering::Release);
        }
    }
    symbol
}

/// # Safety
/// The caller must satisfy the same pointer and buffer requirements as libc's
/// `read` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(fd: c_int, buffer: *mut c_void, count: usize) -> isize {
    if crate::path::is_reflex() {
        return unsafe { crate::reflex::syscall::pe_stub_layout::read(fd, buffer, count) };
    }
    let real = resolve(&REAL_READ, c"read");
    if real.is_null() {
        unsafe { libc::syscall(libc::SYS_read, fd as libc::c_long, buffer, count) as isize }
    } else {
        unsafe { core::mem::transmute::<*mut c_void, Read>(real)(fd, buffer, count) }
    }
}

/// # Safety
/// The caller must satisfy the same pointer and buffer requirements as libc's
/// `pread` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pread(
    fd: c_int,
    buffer: *mut c_void,
    count: usize,
    offset: libc::off_t,
) -> isize {
    if crate::path::is_reflex() {
        return unsafe { crate::reflex::syscall::pe_stub_layout::pread(fd, buffer, count, offset) };
    }
    let real = resolve(&REAL_PREAD, c"pread");
    if real.is_null() {
        unsafe {
            libc::syscall(libc::SYS_pread64, fd as libc::c_long, buffer, count, offset) as isize
        }
    } else {
        unsafe { core::mem::transmute::<*mut c_void, Pread>(real)(fd, buffer, count, offset) }
    }
}

/// # Safety
/// The caller must satisfy the same requirements as libc's `mmap` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
) -> *mut c_void {
    if crate::path::is_reflex() {
        return unsafe {
            crate::reflex::syscall::pe_stub_layout::mmap(addr, length, prot, flags, fd, offset)
        };
    }
    unsafe { crate::artifact::syscall::pe_stub_layout::mmap(addr, length, prot, flags, fd, offset) }
}

/// # Safety
/// The caller must satisfy the same requirements as libc's `mprotect` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int {
    if crate::path::is_artifact() {
        return unsafe { crate::artifact::resolver::mprotect(address, length, protection) };
    }
    unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            address,
            length,
            protection as libc::c_long,
        ) as c_int
    }
}
