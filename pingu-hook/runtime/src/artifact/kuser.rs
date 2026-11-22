//! Artifact's process-private view of Wine's shared user data.
//!
//! Preparation runs only on a Wine PE thread. Signal handlers may publish
//! preallocated identity bytes; they never map pages, start workers, or wait.
use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence,
};
use pingu_protocol::cpuid::Vendor;

const PAGE_SIZE: usize = 4096;
const USER_DATA: usize = 0x7ffe_0000;
const DISPATCH_PAGE: usize = 0x7ffe_1000;
const ARCH_SET_GS: libc::c_long = 0x1001;
const ARCH_SET_CPUID: libc::c_long = 0x1012;
const PR_SET_SYSCALL_USER_DISPATCH: libc::c_long = 59;
const WAIT_ATTEMPTS: usize = 2000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrepareError {
    UnsupportedPageSize,
    InvalidWineMapping,
    InvalidDispatchMapping,
    Busy,
    IncoherentClock,
    WorkerTimeout,
    System(c_int),
    Worker(c_int),
    Rollback(c_int),
}

struct Ownership(AtomicI32);

impl Ownership {
    const fn new() -> Self {
        Self(AtomicI32::new(0))
    }

    fn publish(&self, pid: libc::pid_t) {
        self.0.store(pid, Ordering::Release);
    }

    fn is_ready_for(&self, pid: libc::pid_t) -> bool {
        pid > 0 && self.0.load(Ordering::Acquire) == pid
    }

    fn reset_after_fork(&self) {
        self.0.store(0, Ordering::Release);
    }
}

static OWNER: Ownership = Ownership::new();
static PREPARING: AtomicI32 = AtomicI32::new(0);
static PREPARING_DISPATCH: AtomicI32 = AtomicI32::new(0);
// These aliases are inherited across fork. The child must never write the
// inherited private alias; it creates a new backing before starting a worker.
static WINE_SOURCE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static WRITABLE_ALIAS: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
// PID in the high bits; low bits are zero while publishing, 1=Intel, 2=AMD.
static PROFILE: AtomicU64 = AtomicU64::new(0);
static WORKER_STATUS: AtomicI32 = AtomicI32::new(0);
static STOP_WORKER: AtomicBool = AtomicBool::new(false);
// A prepared worker remains joinable until the dispatcher has been installed.
// A negative or foreign owner is never treated as this process's worker.
static STAGED_PID: AtomicI32 = AtomicI32::new(0);
static KUSER_TARGET: AtomicUsize = AtomicUsize::new(0);
static WORKER_HANDLE: AtomicUsize = AtomicUsize::new(0);
struct DispatchState {
    target: AtomicUsize,
    backup: AtomicPtr<u8>,
    protection: AtomicI32,
    slot: AtomicU64,
}

impl DispatchState {
    const fn new() -> Self {
        Self {
            target: AtomicUsize::new(0),
            backup: AtomicPtr::new(ptr::null_mut()),
            protection: AtomicI32::new(0),
            slot: AtomicU64::new(0),
        }
    }

    fn forget(&self) {
        let backup = self.backup.swap(ptr::null_mut(), Ordering::AcqRel);
        if !backup.is_null() {
            unsafe { libc::munmap(backup.cast(), PAGE_SIZE) };
        }
        self.target.store(0, Ordering::Release);
    }
}

static DISPATCH: DispatchState = DispatchState::new();

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn system_error() -> PrepareError {
    PrepareError::System(errno())
}

fn page_size_supported() -> bool {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) == PAGE_SIZE as libc::c_long }
}

// Wine's syscall-dispatch selector is per PE thread. Keep it ALLOW until the
// new native worker has disabled its inherited dispatch and CPUID traps.
struct SelectorGuard(u8);

impl SelectorGuard {
    unsafe fn enter() -> Self {
        let previous: u8;
        unsafe {
            core::arch::asm!(
                "mov {previous}, byte ptr gs:[0x340]",
                "mov byte ptr gs:[0x340], 0",
                previous = out(reg_byte) previous,
                options(nostack, preserves_flags),
            );
        }
        Self(previous)
    }
}

impl Drop for SelectorGuard {
    fn drop(&mut self) {
        unsafe {
            core::arch::asm!(
                "mov byte ptr gs:[0x340], {previous}",
                previous = in(reg_byte) self.0,
                options(nostack, preserves_flags),
            );
        }
    }
}

struct OperationGuard(&'static AtomicI32);

impl OperationGuard {
    fn acquire(owner: &'static AtomicI32, pid: libc::pid_t) -> Result<Self, PrepareError> {
        let previous = owner.load(Ordering::Acquire);
        if previous == pid
            || owner
                .compare_exchange(previous, pid, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(PrepareError::Busy);
        }
        Ok(Self(owner))
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

struct Mapping(*mut c_void);

impl Mapping {
    fn address(&self) -> *mut u8 {
        self.0.cast()
    }

    fn release(&mut self) {
        self.0 = ptr::null_mut();
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::munmap(self.0, PAGE_SIZE) };
        }
    }
}

struct FileDescriptor(c_int);

impl Drop for FileDescriptor {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn map_page(protection: c_int, flags: c_int, fd: c_int) -> Result<Mapping, PrepareError> {
    // Bypass this runtime's mmap interposer; neither alias is a PE image.
    let address = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            ptr::null_mut::<c_void>(),
            PAGE_SIZE,
            protection as libc::c_long,
            flags as libc::c_long,
            fd as libc::c_long,
            0 as libc::c_long,
        )
    };
    if address == -1 {
        Err(system_error())
    } else {
        Ok(Mapping(address as *mut c_void))
    }
}

// Linux permits old_size=0 for a shared mapping: it creates an alias of the
// same pages without disturbing the original mapping or its protections.
fn clone_shared_page(address: usize) -> Result<Mapping, PrepareError> {
    let alias = unsafe {
        libc::syscall(
            libc::SYS_mremap,
            address as *mut c_void,
            0usize,
            PAGE_SIZE,
            libc::MREMAP_MAYMOVE as libc::c_long,
            ptr::null_mut::<c_void>(),
        )
    };
    if alias == -1 {
        Err(system_error())
    } else {
        Ok(Mapping(alias as *mut c_void))
    }
}

fn move_page(mapping: &mut Mapping, destination: usize) -> Result<(), PrepareError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_mremap,
            mapping.0,
            PAGE_SIZE,
            PAGE_SIZE,
            (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as libc::c_long,
            destination as *mut c_void,
        )
    };
    if result == -1 {
        Err(system_error())
    } else {
        mapping.release();
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct MappingPermissions {
    protection: c_int,
    shared: bool,
}

fn mapping_permissions(address: usize) -> Option<MappingPermissions> {
    if !address.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    let end = (address as u64).checked_add(PAGE_SIZE as u64)?;
    let mut result = None;
    crate::maps::find_line(|line| {
        let Some(mapping) = crate::maps::parse(line) else {
            return false;
        };
        if mapping.start > address as u64 || mapping.end < end {
            return false;
        }
        let permissions = mapping.permissions;
        if permissions.len() != 4
            || !matches!(permissions[0], b'r' | b'-')
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
            || !matches!(permissions[3], b's' | b'p')
        {
            return false;
        }
        let mut protection = 0;
        if permissions[0] == b'r' {
            protection |= libc::PROT_READ;
        }
        if permissions[1] == b'w' {
            protection |= libc::PROT_WRITE;
        }
        if permissions[2] == b'x' {
            protection |= libc::PROT_EXEC;
        }
        result = Some(MappingPermissions {
            protection,
            shared: permissions[3] == b's',
        });
        true
    });
    result
}

fn is_wine_source_mapping_at(address: usize) -> bool {
    if !address.is_multiple_of(PAGE_SIZE) {
        return false;
    }
    let Some(end) = (address as u64).checked_add(PAGE_SIZE as u64) else {
        return false;
    };
    let mut resident = 0u8;
    if unsafe { libc::mincore(address as *mut c_void, PAGE_SIZE, &mut resident) } != 0 {
        return false;
    }
    crate::maps::find_line(|line| {
        crate::maps::parse(line).is_some_and(|mapping| {
            let path = mapping
                .path
                .strip_suffix(b" (deleted)")
                .unwrap_or(mapping.path);
            mapping.start <= address as u64
                && mapping.end >= end
                && matches!(mapping.permissions, b"r--s" | b"rw-s")
                && mapping.inode != b"0"
                && path == b"/memfd:wine-mapping"
        })
    })
}

unsafe fn read_time(source: *const u8, offset: usize) -> Option<(u32, u32)> {
    let word = |at| unsafe { &*source.add(at).cast::<AtomicU32>() };
    let high1 = word(offset + 4).load(Ordering::Acquire);
    let low = word(offset).load(Ordering::Relaxed);
    fence(Ordering::Acquire);
    let high2 = word(offset + 8).load(Ordering::Relaxed);
    (high1 == high2).then_some((low, high1))
}

unsafe fn write_time(destination: *mut u8, offset: usize, (low, high): (u32, u32)) {
    let word = |at| unsafe { &*destination.add(at).cast::<AtomicU32>() };
    word(offset + 8).store(high, Ordering::Relaxed);
    fence(Ordering::Release);
    word(offset).store(low, Ordering::Relaxed);
    word(offset + 4).store(high, Ordering::Release);
}

/// Attempt one coherent read from the live producer, never an immutable copy.
/// An incomplete source does not change any destination clock fields.
unsafe fn refresh_clock(source: *const u8, destination: *mut u8) -> bool {
    let source_u32 = |at| unsafe { &*source.add(at).cast::<AtomicU32>() };
    let source_u64 = |at| unsafe { &*source.add(at).cast::<AtomicU64>() };
    let sequence = source_u64(0x340).load(Ordering::Acquire);
    if sequence & 1 != 0 {
        return false;
    }
    let Some(interrupt) = (unsafe { read_time(source, 0x8) }) else {
        return false;
    };
    let Some(system) = (unsafe { read_time(source, 0x14) }) else {
        return false;
    };
    let Some(tick) = (unsafe { read_time(source, 0x320) }) else {
        return false;
    };
    let multiplier = source_u32(0x2e4).load(Ordering::Relaxed);
    let baseline_system = source_u64(0x348).load(Ordering::Relaxed);
    let baseline_interrupt = source_u64(0x350).load(Ordering::Relaxed);
    fence(Ordering::Acquire);
    if source_u64(0x340).load(Ordering::Relaxed) != sequence {
        return false;
    }
    let destination_u32 = |at| unsafe { &*destination.add(at).cast::<AtomicU32>() };
    let destination_u64 = |at| unsafe { &*destination.add(at).cast::<AtomicU64>() };
    destination_u64(0x340).store(sequence | 1, Ordering::Relaxed);
    fence(Ordering::Release);
    unsafe {
        write_time(destination, 0x8, interrupt);
        write_time(destination, 0x14, system);
        write_time(destination, 0x320, tick);
    }
    destination_u32(0x2e4).store(multiplier, Ordering::Relaxed);
    destination_u64(0x348).store(baseline_system, Ordering::Relaxed);
    destination_u64(0x350).store(baseline_interrupt, Ordering::Relaxed);
    destination_u64(0x340).store(sequence, Ordering::Release);
    true
}

fn pause_worker() {
    let pause = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    unsafe { libc::nanosleep(&pause, ptr::null_mut()) };
}

extern "C" fn clock_worker(_: *mut c_void) -> *mut c_void {
    let dispatch = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            PR_SET_SYSCALL_USER_DISPATCH,
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if dispatch == -1
        || unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, 1 as libc::c_long) } == -1
        || unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, 0 as libc::c_long) } == -1
    {
        WORKER_STATUS.store(-errno().max(1), Ordering::Release);
        return ptr::null_mut();
    }
    let source = WINE_SOURCE.load(Ordering::Acquire);
    let destination = WRITABLE_ALIAS.load(Ordering::Acquire);
    if source.is_null() || destination.is_null() {
        WORKER_STATUS.store(-libc::EINVAL, Ordering::Release);
        return ptr::null_mut();
    }
    while !STOP_WORKER.load(Ordering::Acquire) {
        if unsafe { refresh_clock(source, destination) }
            && WORKER_STATUS.load(Ordering::Relaxed) == 0
        {
            WORKER_STATUS.store(1, Ordering::Release);
        }
        pause_worker();
    }
    ptr::null_mut()
}

fn start_worker() -> Result<libc::pthread_t, PrepareError> {
    WORKER_STATUS.store(0, Ordering::Release);
    STOP_WORKER.store(false, Ordering::Release);
    let mut worker: libc::pthread_t = 0;
    let result =
        unsafe { libc::pthread_create(&mut worker, ptr::null(), clock_worker, ptr::null_mut()) };
    if result != 0 {
        return Err(PrepareError::Worker(result));
    }
    let mut status = 0;
    for _ in 0..WAIT_ATTEMPTS {
        status = WORKER_STATUS.load(Ordering::Acquire);
        if status != 0 {
            break;
        }
        pause_worker();
    }
    if status == 1 {
        return Ok(worker);
    }
    STOP_WORKER.store(true, Ordering::Release);
    unsafe { libc::pthread_join(worker, ptr::null_mut()) };
    if status < 0 {
        Err(PrepareError::Worker(-status))
    } else {
        Err(PrepareError::WorkerTimeout)
    }
}

fn prepare_backing(
    source: *mut u8,
    target: usize,
    writer: &mut Option<Mapping>,
) -> Result<libc::pthread_t, PrepareError> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"pingu-artifact-kuser".as_ptr(),
            libc::MFD_CLOEXEC as libc::c_long,
        )
    };
    if fd == -1 {
        return Err(system_error());
    }
    let fd = FileDescriptor(fd as c_int);
    if unsafe { libc::ftruncate(fd.0, PAGE_SIZE as libc::off_t) } != 0 {
        return Err(system_error());
    }
    *writer = Some(map_page(
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd.0,
    )?);
    let mut readonly = map_page(libc::PROT_READ, libc::MAP_SHARED, fd.0)?;
    let destination = writer.as_ref().unwrap().address();
    unsafe { ptr::copy_nonoverlapping(source, destination, PAGE_SIZE) };

    // A copied KSYSTEM_TIME can be permanently torn. Always retry against
    // the live Wine mapping, and never expose the page before it is coherent.
    let mut coherent = false;
    for _ in 0..WAIT_ATTEMPTS {
        if unsafe { refresh_clock(source, destination) } {
            coherent = true;
            break;
        }
        pause_worker();
    }
    if !coherent {
        return Err(PrepareError::IncoherentClock);
    }
    WRITABLE_ALIAS.store(destination, Ordering::Release);
    move_page(&mut readonly, target)?;
    start_worker()
}

/// Prepare the provider from an ordinary PE context with a valid Wine TEB.
/// Readiness is committed separately, after the dispatcher bridge is installed.
pub(crate) fn prepare() -> Result<(), PrepareError> {
    let _errno = crate::errno::Errno::save();
    let _selector = unsafe { SelectorGuard::enter() };
    unsafe { prepare_at(USER_DATA) }
}

unsafe fn prepare_at(target: usize) -> Result<(), PrepareError> {
    if !page_size_supported() {
        return Err(PrepareError::UnsupportedPageSize);
    }
    let pid = unsafe { libc::getpid() };
    if OWNER.is_ready_for(pid) {
        return if KUSER_TARGET.load(Ordering::Acquire) == target {
            Ok(())
        } else {
            Err(PrepareError::Busy)
        };
    }
    let _operation = OperationGuard::acquire(&PREPARING, pid)?;
    let staged = STAGED_PID.load(Ordering::Acquire);
    if staged != 0 {
        if staged == pid
            && WORKER_HANDLE.load(Ordering::Acquire) != 0
            && KUSER_TARGET.load(Ordering::Acquire) == target
        {
            return Ok(());
        }
        rollback()?;
    }
    // Commit marks the stage finished before releasing its rollback alias.
    // A fork in that small window inherits the already-installed private
    // dispatcher; discard bookkeeping rather than reverting it in the child.
    if STAGED_PID.load(Ordering::Acquire) == 0 {
        DISPATCH.forget();
    }
    if !OWNER.is_ready_for(pid) {
        OWNER.reset_after_fork();
        PROFILE.store(0, Ordering::Release);
        // A raw-fork child inherited a pthread handle, but not its worker.
        WORKER_HANDLE.store(0, Ordering::Release);
    }
    let inherited_source = WINE_SOURCE.load(Ordering::Acquire);
    let previous_target = KUSER_TARGET.load(Ordering::Acquire);
    let mut source = if !inherited_source.is_null()
        && previous_target == target
        && is_wine_source_mapping_at(inherited_source as usize)
    {
        Mapping(inherited_source.cast())
    } else {
        if !inherited_source.is_null() {
            return Err(PrepareError::InvalidWineMapping);
        }
        if !is_wine_source_mapping_at(target) {
            return Err(PrepareError::InvalidWineMapping);
        }
        clone_shared_page(target)?
    };
    KUSER_TARGET.store(target, Ordering::Release);
    WINE_SOURCE.store(source.address(), Ordering::Release);
    STAGED_PID.store(pid, Ordering::Release);

    // An inherited alias may share the parent's memfd. Never write through it.
    let old_alias = WRITABLE_ALIAS.swap(ptr::null_mut(), Ordering::AcqRel);
    if !old_alias.is_null() {
        unsafe { libc::munmap(old_alias.cast(), PAGE_SIZE) };
    }

    let mut writer = None;
    match prepare_backing(source.address(), target, &mut writer) {
        Ok(worker) => {
            WORKER_HANDLE.store(worker as usize, Ordering::Release);
            source.release();
            if let Some(mapping) = &mut writer {
                mapping.release();
            }
            Ok(())
        }
        Err(error) => {
            WRITABLE_ALIAS.store(ptr::null_mut(), Ordering::Release);
            drop(writer);
            if move_page(&mut source, target).is_err() {
                let failure = errno();
                source.release();
                return Err(PrepareError::Rollback(failure));
            }
            WINE_SOURCE.store(ptr::null_mut(), Ordering::Release);
            KUSER_TARGET.store(0, Ordering::Release);
            STAGED_PID.store(0, Ordering::Release);
            Err(error)
        }
    }
}

/// Signal-safe and robust even if a raw fork bypassed pthread_atfork.
pub(crate) fn ready() -> bool {
    if OWNER.0.load(Ordering::Acquire) == 0 {
        return false;
    }
    OWNER.is_ready_for(unsafe { libc::getpid() })
}

/// Publish only into this process's committed backing, without signal waits.
pub(crate) fn apply_profile(vendor: Vendor) -> bool {
    let vendor = match vendor {
        Vendor::Intel => 1,
        Vendor::Amd => 2,
        Vendor::Unknown => return false,
    };
    let pid = unsafe { libc::getpid() };
    if !OWNER.is_ready_for(pid) {
        return false;
    }
    let publishing = (pid as u64) << 2;
    let published = publishing | vendor;
    if let Err(state) = PROFILE.compare_exchange(0, publishing, Ordering::AcqRel, Ordering::Acquire)
    {
        return state == published;
    }
    let destination = WRITABLE_ALIAS.load(Ordering::Acquire);
    if destination.is_null() {
        PROFILE.store(0, Ordering::Release);
        return false;
    }
    let vendor = if vendor == 1 {
        Vendor::Intel
    } else {
        Vendor::Amd
    };
    let applied = pingu_protocol::artifact::profile::visit_writes(
        crate::artifact::config::artifact_generation(),
        vendor,
        |offset, byte| {
            unsafe { &*destination.add(offset).cast::<AtomicU8>() }.store(byte, Ordering::Relaxed);
        },
    );
    PROFILE.store(if applied { published } else { 0 }, Ordering::Release);
    applied
}

/// Write the ready marker the 0x1337-bypass Artifact build polls for. Only
/// after this process published its profile into its own backing.
pub(crate) fn publish_ready_marker() -> bool {
    if !profile_ready() {
        return false;
    }
    let destination = WRITABLE_ALIAS.load(Ordering::Acquire);
    if destination.is_null() {
        return false;
    }
    let offset = pingu_protocol::artifact::profile::READY_MARKER_OFFSET;
    for (i, byte) in pingu_protocol::artifact::profile::READY_MARKER
        .to_le_bytes()
        .into_iter()
        .enumerate()
    {
        unsafe { &*destination.add(offset + i).cast::<AtomicU8>() }.store(byte, Ordering::Release);
    }
    true
}

/// An inherited or still-publishing profile cannot satisfy ART readiness.
pub(crate) fn profile_ready() -> bool {
    let pid = unsafe { libc::getpid() };
    let profile = PROFILE.load(Ordering::Acquire);
    OWNER.is_ready_for(pid) && profile >> 2 == pid as u64 && profile & 3 != 0
}

/// Invalidate inherited liveness without writing either process's backing.
pub(crate) fn after_fork() {
    OWNER.reset_after_fork();
    PROFILE.store(0, Ordering::Release);
    PREPARING.store(0, Ordering::Release);
    PREPARING_DISPATCH.store(0, Ordering::Release);
    WORKER_HANDLE.store(0, Ordering::Release);
    WORKER_STATUS.store(0, Ordering::Release);
    STOP_WORKER.store(true, Ordering::Release);
}

unsafe fn isolate_dispatch_page(address: usize, state: &DispatchState) -> Result<(), PrepareError> {
    if !page_size_supported() {
        return Err(PrepareError::UnsupportedPageSize);
    }
    let permissions = mapping_permissions(address).ok_or(PrepareError::InvalidDispatchMapping)?;
    if permissions.protection & libc::PROT_READ == 0 {
        return Err(PrepareError::InvalidDispatchMapping);
    }
    let slot = unsafe { (address as *const u64).read_volatile() };
    if !permissions.shared {
        state
            .protection
            .store(permissions.protection, Ordering::Release);
        state.slot.store(slot, Ordering::Release);
        state.backup.store(ptr::null_mut(), Ordering::Release);
        state.target.store(address, Ordering::Release);
        return Ok(());
    }
    let mut original = clone_shared_page(address)?;
    let mut replacement = map_page(
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
    )?;
    unsafe { ptr::copy_nonoverlapping(address as *const u8, replacement.address(), PAGE_SIZE) };
    if unsafe { libc::mprotect(replacement.0, PAGE_SIZE, permissions.protection) } != 0 {
        return Err(system_error());
    }
    state
        .protection
        .store(permissions.protection, Ordering::Release);
    state.slot.store(slot, Ordering::Release);
    state.backup.store(original.address(), Ordering::Release);
    state.target.store(address, Ordering::Release);
    if let Err(error) = move_page(&mut replacement, address) {
        if move_page(&mut original, address).is_err() {
            original.release();
            return Err(PrepareError::Rollback(errno()));
        }
        state.backup.store(ptr::null_mut(), Ordering::Release);
        state.target.store(0, Ordering::Release);
        return Err(error);
    }
    original.release();
    Ok(())
}

unsafe fn prepare_dispatch_at(address: usize) -> Result<(), PrepareError> {
    let pid = unsafe { libc::getpid() };
    let _operation = OperationGuard::acquire(&PREPARING_DISPATCH, pid)?;
    if STAGED_PID.load(Ordering::Acquire) != pid || WORKER_HANDLE.load(Ordering::Acquire) == 0 {
        return Err(PrepareError::Busy);
    }
    let previous = DISPATCH.target.load(Ordering::Acquire);
    if previous != 0 {
        return if previous == address {
            Ok(())
        } else {
            Err(PrepareError::Busy)
        };
    }
    unsafe { isolate_dispatch_page(address, &DISPATCH) }
}

/// Isolate the dispatcher slot without changing unrelated bytes or protection.
pub(crate) fn prepare_dispatch_page() -> Result<(), PrepareError> {
    let _errno = crate::errno::Errno::save();
    let _selector = unsafe { SelectorGuard::enter() };
    unsafe { prepare_dispatch_at(DISPATCH_PAGE) }
}

fn restore_private_dispatch(
    address: usize,
    protection: c_int,
    slot: u64,
) -> Result<(), PrepareError> {
    let current = mapping_permissions(address).ok_or(PrepareError::InvalidDispatchMapping)?;
    if current.shared {
        return Err(PrepareError::InvalidDispatchMapping);
    }
    let readable = current.protection & libc::PROT_READ != 0;
    let same_slot = readable && unsafe { (address as *const u64).read_volatile() == slot };
    if !same_slot {
        if unsafe {
            libc::mprotect(
                address as *mut c_void,
                PAGE_SIZE,
                protection | libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            return Err(PrepareError::Rollback(errno()));
        }
        unsafe { (address as *mut u64).write_volatile(slot) };
    }
    if (!same_slot || current.protection != protection)
        && unsafe { libc::mprotect(address as *mut c_void, PAGE_SIZE, protection) } != 0
    {
        return Err(PrepareError::Rollback(errno()));
    }
    Ok(())
}

/// Stop a staged worker and restore both original mappings. A child never
/// joins its parent's pthread or writes through the inherited writable alias.
pub(crate) fn rollback() -> Result<(), PrepareError> {
    let staged = STAGED_PID.load(Ordering::Acquire);
    if staged == 0 {
        return Ok(());
    }
    let pid = unsafe { libc::getpid() };
    let worker = WORKER_HANDLE.swap(0, Ordering::AcqRel);
    STOP_WORKER.store(true, Ordering::Release);
    if staged == pid && worker != 0 {
        let result = unsafe { libc::pthread_join(worker as libc::pthread_t, ptr::null_mut()) };
        if result != 0 {
            WORKER_HANDLE.store(worker, Ordering::Release);
            return Err(PrepareError::Worker(result));
        }
    }

    let mut failure = None;
    let alias = WRITABLE_ALIAS.swap(ptr::null_mut(), Ordering::AcqRel);
    if !alias.is_null() && unsafe { libc::munmap(alias.cast(), PAGE_SIZE) } != 0 {
        WRITABLE_ALIAS.store(alias, Ordering::Release);
        failure = Some(PrepareError::Rollback(errno()));
    }

    let dispatch = DISPATCH.target.load(Ordering::Acquire);
    if dispatch != 0 {
        let backup = DISPATCH.backup.load(Ordering::Acquire);
        let restored = if backup.is_null() {
            restore_private_dispatch(
                dispatch,
                DISPATCH.protection.load(Ordering::Acquire),
                DISPATCH.slot.load(Ordering::Acquire),
            )
        } else if !mapping_permissions(backup as usize).is_some_and(|mapping| mapping.shared) {
            // A raw fork may occur after the alias was moved back but before
            // its pointer was cleared in the parent.
            if mapping_permissions(dispatch).is_some_and(|mapping| mapping.shared) {
                DISPATCH.backup.store(ptr::null_mut(), Ordering::Release);
                Ok(())
            } else {
                Err(PrepareError::InvalidDispatchMapping)
            }
        } else {
            let mut original = Mapping(backup.cast());
            match move_page(&mut original, dispatch) {
                Ok(()) => {
                    DISPATCH.backup.store(ptr::null_mut(), Ordering::Release);
                    Ok(())
                }
                Err(_) => {
                    let error = PrepareError::Rollback(errno());
                    original.release();
                    Err(error)
                }
            }
        };
        match restored {
            Ok(()) => DISPATCH.target.store(0, Ordering::Release),
            Err(error) => {
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
    }

    let target = KUSER_TARGET.load(Ordering::Acquire);
    let source = WINE_SOURCE.load(Ordering::Acquire);
    if !source.is_null() {
        if !is_wine_source_mapping_at(source as usize) {
            if target != 0 && is_wine_source_mapping_at(target) {
                WINE_SOURCE.store(ptr::null_mut(), Ordering::Release);
            } else if failure.is_none() {
                failure = Some(PrepareError::InvalidWineMapping);
            }
        } else {
            let mut original = Mapping(source.cast());
            if move_page(&mut original, target).is_ok() {
                WINE_SOURCE.store(ptr::null_mut(), Ordering::Release);
            } else {
                let error = PrepareError::Rollback(errno());
                original.release();
                if failure.is_none() {
                    failure = Some(error);
                }
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    OWNER.reset_after_fork();
    PROFILE.store(0, Ordering::Release);
    KUSER_TARGET.store(0, Ordering::Release);
    STAGED_PID.store(0, Ordering::Release);
    Ok(())
}

/// Publish only after the caller has successfully installed the bridge.
pub(crate) fn commit() {
    let pid = STAGED_PID.load(Ordering::Acquire);
    STAGED_PID.store(0, Ordering::Release);
    OWNER.publish(pid);
    DISPATCH.forget();
}

#[cfg(test)]
mod tests {
    use super::{
        DispatchState, Ownership, is_wine_source_mapping_at, isolate_dispatch_page, refresh_clock,
    };
    use core::ffi::{CStr, c_void};
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use std::ptr;

    const PAGE: usize = 4096;

    fn store_u32(page: *mut u8, offset: usize, value: u32) {
        unsafe { &*page.add(offset).cast::<AtomicU32>() }.store(value, Ordering::SeqCst);
    }

    fn load_u32(page: *const u8, offset: usize) -> u32 {
        unsafe { &*page.add(offset).cast::<AtomicU32>() }.load(Ordering::SeqCst)
    }

    fn store_u64(page: *mut u8, offset: usize, value: u64) {
        unsafe { &*page.add(offset).cast::<AtomicU64>() }.store(value, Ordering::SeqCst);
    }

    fn load_u64(page: *const u8, offset: usize) -> u64 {
        unsafe { &*page.add(offset).cast::<AtomicU64>() }.load(Ordering::SeqCst)
    }

    fn set_time(page: *mut u8, offset: usize, low: u32, high1: u32, high2: u32) {
        store_u32(page, offset, low);
        store_u32(page, offset + 4, high1);
        store_u32(page, offset + 8, high2);
    }

    fn set_complete_clock(page: *mut u8) {
        set_time(page, 0x8, 0x1111_1111, 0x22, 0x22);
        set_time(page, 0x14, 0x3333_3333, 0x44, 0x44);
        set_time(page, 0x320, 0x5555_5555, 0x66, 0x66);
        store_u32(page, 0x2e4, 0x7788_99aa);
        store_u64(page, 0x340, 8);
        store_u64(page, 0x348, 0x1234_5678_9abc_def0);
        store_u64(page, 0x350, 0x0fed_cba9_8765_4321);
    }

    #[test]
    fn torn_initial_time_is_rejected_then_refreshed_from_live_source() {
        let mut source = Box::new([0u64; PAGE / 8]);
        let mut destination = Box::new([0u64; PAGE / 8]);
        let source_ptr = source.as_mut_ptr().cast::<u8>();
        let destination_ptr = destination.as_mut_ptr().cast::<u8>();
        set_complete_clock(source_ptr);
        set_time(source_ptr, 0x8, 0, 0x10, 0x11);
        // The destination contains a frozen, torn copy, as a page snapshot can.
        unsafe { ptr::copy_nonoverlapping(source_ptr, destination_ptr, PAGE) };
        // Bound the frozen-source case even if a broken implementation spins.
        // The child touches only inherited memory and exits without using Rust
        // allocation or the test harness after the raw fork.
        let child = unsafe { libc::syscall(libc::SYS_fork) };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            let rejected = !unsafe { refresh_clock(source_ptr, destination_ptr) };
            set_time(source_ptr, 0x8, 0x1234, 0x11, 0x11);
            let refreshed = unsafe { refresh_clock(source_ptr, destination_ptr) };
            let correct = load_u32(destination_ptr, 0x8) == 0x1234
                && load_u32(destination_ptr, 0xc) == 0x11
                && load_u32(destination_ptr, 0x10) == 0x11;
            unsafe {
                libc::_exit(if rejected && refreshed && correct {
                    0
                } else {
                    1
                })
            };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(child as libc::pid_t, &mut status, libc::WNOHANG) };
            if waited == child as libc::pid_t {
                break;
            }
            assert!(waited >= 0, "waitpid: {}", std::io::Error::last_os_error());
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::kill(child as libc::pid_t, libc::SIGKILL);
                    libc::waitpid(child as libc::pid_t, &mut status, 0);
                }
                panic!("refresh spun on a frozen torn source");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn live_refresh_copies_all_clock_fields_without_changing_identity() {
        let mut source = Box::new([0u64; PAGE / 8]);
        let mut destination = Box::new([0xa5a5_a5a5_a5a5_a5a5u64; PAGE / 8]);
        let source_ptr = source.as_mut_ptr().cast::<u8>();
        let destination_ptr = destination.as_mut_ptr().cast::<u8>();
        set_complete_clock(source_ptr);
        assert!(unsafe { refresh_clock(source_ptr, destination_ptr) });
        for (offset, low, high) in [
            (0x8, 0x1111_1111, 0x22),
            (0x14, 0x3333_3333, 0x44),
            (0x320, 0x5555_5555, 0x66),
        ] {
            assert_eq!(load_u32(destination_ptr, offset), low);
            assert_eq!(load_u32(destination_ptr, offset + 4), high);
            assert_eq!(load_u32(destination_ptr, offset + 8), high);
        }
        assert_eq!(load_u32(destination_ptr, 0x2e4), 0x7788_99aa);
        assert_eq!(load_u64(destination_ptr, 0x340), 8);
        assert_eq!(load_u64(destination_ptr, 0x348), 0x1234_5678_9abc_def0);
        assert_eq!(load_u64(destination_ptr, 0x350), 0x0fed_cba9_8765_4321);
        assert_eq!(load_u64(destination_ptr, 0x100), 0xa5a5_a5a5_a5a5_a5a5);

        set_time(source_ptr, 0x8, 0x99, 0x23, 0x23);
        store_u32(source_ptr, 0x2e4, 0xabcdef01);
        store_u64(source_ptr, 0x340, 10);
        store_u64(source_ptr, 0x348, 0x123);
        store_u64(source_ptr, 0x350, 0x456);
        assert!(unsafe { refresh_clock(source_ptr, destination_ptr) });
        assert_eq!(load_u32(destination_ptr, 0x8), 0x99);
        assert_eq!(load_u32(destination_ptr, 0xc), 0x23);
        assert_eq!(load_u32(destination_ptr, 0x10), 0x23);
        assert_eq!(load_u32(destination_ptr, 0x2e4), 0xabcdef01);
        assert_eq!(load_u64(destination_ptr, 0x340), 10);
        assert_eq!(load_u64(destination_ptr, 0x348), 0x123);
        assert_eq!(load_u64(destination_ptr, 0x350), 0x456);
        assert_eq!(load_u64(destination_ptr, 0x100), 0xa5a5_a5a5_a5a5_a5a5);
    }

    #[test]
    fn updating_qpc_block_does_not_publish_an_incoherent_refresh() {
        let mut source = Box::new([0u64; PAGE / 8]);
        let mut destination = Box::new([0xa5a5_a5a5_a5a5_a5a5u64; PAGE / 8]);
        let source_ptr = source.as_mut_ptr().cast::<u8>();
        let destination_ptr = destination.as_mut_ptr().cast::<u8>();
        set_complete_clock(source_ptr);
        store_u64(source_ptr, 0x340, 9);
        assert!(!unsafe { refresh_clock(source_ptr, destination_ptr) });
        assert!(
            destination
                .iter()
                .all(|&word| word == 0xa5a5_a5a5_a5a5_a5a5)
        );
        store_u64(source_ptr, 0x340, 10);
        assert!(unsafe { refresh_clock(source_ptr, destination_ptr) });
        assert_eq!(load_u64(destination_ptr, 0x340), 10);
        assert_eq!(load_u64(destination_ptr, 0x348), 0x1234_5678_9abc_def0);
        assert_eq!(load_u64(destination_ptr, 0x350), 0x0fed_cba9_8765_4321);
    }

    #[test]
    fn concurrent_refresh_keeps_times_and_qpc_under_the_same_sequence() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::{Arc, Barrier};

        let mut source = Box::new([0u64; PAGE / 8]);
        let mut destination = Box::new([0u64; PAGE / 8]);
        let source_ptr = source.as_mut_ptr().cast::<u8>();
        let destination_ptr = destination.as_mut_ptr().cast::<u8>();
        for offset in [0x8, 0x14, 0x320] {
            set_time(source_ptr, offset, 1, 0, 0);
        }
        store_u32(source_ptr, 0x2e4, 1);
        store_u64(source_ptr, 0x340, 2);
        store_u64(source_ptr, 0x348, 1);
        store_u64(source_ptr, 0x350, 1);
        assert!(unsafe { refresh_clock(source_ptr, destination_ptr) });

        let start = Arc::new(Barrier::new(3));
        let done = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let bad = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let source_address = source_ptr as usize;
        let writer_start = Arc::clone(&start);
        let writer_done = Arc::clone(&done);
        let writer = std::thread::spawn(move || {
            let source = source_address as *mut u8;
            writer_start.wait();
            for generation in 2u32..=40_000 {
                store_u64(source, 0x340, u64::from(generation) * 2 - 1);
                for offset in [0x8, 0x14, 0x320] {
                    set_time(source, offset, generation, 0, 0);
                }
                store_u32(source, 0x2e4, generation);
                store_u64(source, 0x348, u64::from(generation));
                store_u64(source, 0x350, u64::from(generation));
                store_u64(source, 0x340, u64::from(generation) * 2);
                if generation % 32 == 0 {
                    std::thread::yield_now();
                }
            }
            writer_done.store(true, Ordering::Release);
        });
        let destination_address = destination_ptr as usize;
        let reader_start = Arc::clone(&start);
        let reader_stop = Arc::clone(&stop);
        let reader_bad = Arc::clone(&bad);
        let reader_reads = Arc::clone(&reads);
        let reader = std::thread::spawn(move || {
            let page = destination_address as *const u8;
            reader_start.wait();
            while !reader_stop.load(Ordering::Acquire) {
                let first = load_u64(page, 0x340);
                if first & 1 != 0 {
                    continue;
                }
                let interrupt = load_u32(page, 0x8);
                let system = load_u32(page, 0x14);
                let tick = load_u32(page, 0x320);
                let multiplier = load_u32(page, 0x2e4);
                let baseline_system = load_u64(page, 0x348);
                let baseline_interrupt = load_u64(page, 0x350);
                let last = load_u64(page, 0x340);
                if first == last && last & 1 == 0 {
                    reader_reads.fetch_add(1, Ordering::Relaxed);
                    if u64::from(interrupt) * 2 != last
                        || system != interrupt
                        || tick != interrupt
                        || multiplier != interrupt
                        || baseline_system != u64::from(interrupt)
                        || baseline_interrupt != u64::from(interrupt)
                    {
                        reader_bad.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        });
        start.wait();
        while !done.load(Ordering::Acquire) {
            unsafe { refresh_clock(source_ptr, destination_ptr) };
        }
        writer.join().unwrap();
        for _ in 0..100 {
            unsafe { refresh_clock(source_ptr, destination_ptr) };
        }
        stop.store(true, Ordering::Release);
        reader.join().unwrap();
        assert!(reads.load(Ordering::Acquire) > 0);
        assert!(
            !bad.load(Ordering::Acquire),
            "a stable time sequence exposed mixed generations"
        );
    }

    #[test]
    fn inherited_owner_is_not_live_in_a_raw_fork_child() {
        let owner = Ownership::new();
        let parent_pid = unsafe { libc::getpid() };
        owner.publish(parent_pid);
        assert!(owner.is_ready_for(parent_pid));
        // A raw fork deliberately bypasses pthread_atfork: the PID check itself
        // must reject inherited liveness even before normal child recovery.
        let child = unsafe { libc::syscall(libc::SYS_fork) };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            let child_pid = unsafe { libc::getpid() };
            let rejected = !owner.is_ready_for(child_pid);
            owner.reset_after_fork();
            let cleared = !owner.is_ready_for(child_pid);
            unsafe { libc::_exit(if rejected && cleared { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child as libc::pid_t, &mut status, 0) },
            child as libc::pid_t
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert!(owner.is_ready_for(parent_pid));
    }

    struct Mappings {
        fd: libc::c_int,
        first: *mut u8,
        second: *mut u8,
    }

    impl Mappings {
        fn new(name: &CStr, first_flags: libc::c_int) -> Self {
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
            assert_eq!(unsafe { libc::ftruncate(fd, PAGE as libc::off_t) }, 0);
            let second = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            assert_ne!(second, libc::MAP_FAILED);
            for i in 0..PAGE {
                unsafe {
                    second
                        .cast::<u8>()
                        .add(i)
                        .write((i.wrapping_mul(37) & 0xff) as u8)
                };
            }
            let first = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    first_flags,
                    fd,
                    0,
                )
            };
            assert_ne!(first, libc::MAP_FAILED);
            Self {
                fd,
                first: first.cast(),
                second: second.cast(),
            }
        }
    }

    impl Drop for Mappings {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.first.cast::<c_void>(), PAGE);
                libc::munmap(self.second.cast::<c_void>(), PAGE);
                libc::close(self.fd);
            }
        }
    }

    fn mapping_line(address: *const u8) -> String {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        maps.lines()
            .find(|line| {
                crate::maps::parse(line.as_bytes()).is_some_and(|mapping| {
                    mapping.start <= address as u64 && mapping.end >= address as u64 + PAGE as u64
                })
            })
            .expect("mapped page")
            .to_owned()
    }

    #[test]
    fn source_validation_requires_a_shared_wine_memfd_mapping() {
        let wine = Mappings::new(c"wine-mapping", libc::MAP_SHARED);
        let other = Mappings::new(c"not-wine-mapping", libc::MAP_SHARED);
        let private_wine = Mappings::new(c"wine-mapping", libc::MAP_PRIVATE);
        assert!(is_wine_source_mapping_at(wine.first as usize));
        assert!(!is_wine_source_mapping_at(other.first as usize));
        assert!(!is_wine_source_mapping_at(private_wine.first as usize));
    }

    #[test]
    fn dispatcher_page_copy_is_private_preserves_bytes_and_protection() {
        let mapping = Mappings::new(c"artifact-dispatch-test", libc::MAP_SHARED);
        assert_eq!(
            unsafe { libc::mprotect(mapping.first.cast(), PAGE, libc::PROT_READ) },
            0
        );
        let before = unsafe { std::slice::from_raw_parts(mapping.first, PAGE) }.to_vec();
        assert_eq!(
            crate::maps::parse(mapping_line(mapping.first).as_bytes())
                .unwrap()
                .permissions,
            b"r--s"
        );
        let state = DispatchState::new();
        unsafe { isolate_dispatch_page(mapping.first as usize, &state) }.unwrap();
        assert_eq!(
            crate::maps::parse(mapping_line(mapping.first).as_bytes())
                .unwrap()
                .permissions,
            b"r--p"
        );
        assert_eq!(
            unsafe { std::slice::from_raw_parts(mapping.first, PAGE) },
            before
        );
        unsafe { mapping.second.add(0x138).write(0xe1) };
        assert_eq!(unsafe { mapping.first.add(0x138).read() }, before[0x138]);
        assert_eq!(
            unsafe {
                libc::mprotect(
                    mapping.first.cast(),
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            0
        );
        unsafe { mapping.first.add(0x140).write(0x7b) };
        assert_eq!(unsafe { mapping.second.add(0x140).read() }, before[0x140]);
        state.forget();
    }

    #[test]
    fn already_private_dispatcher_mapping_is_not_copied() {
        let mapping = Mappings::new(c"artifact-dispatch-private", libc::MAP_PRIVATE);
        let before = mapping_line(mapping.first);
        let state = DispatchState::new();
        unsafe { isolate_dispatch_page(mapping.first as usize, &state) }.unwrap();
        assert_eq!(mapping_line(mapping.first), before);
        unsafe { mapping.second.add(0x138).write(0xa9) };
        assert_eq!(unsafe { mapping.first.add(0x138).read() }, 0xa9);
        state.forget();
    }

    struct RollbackOnDrop;

    impl Drop for RollbackOnDrop {
        fn drop(&mut self) {
            let _ = super::rollback();
        }
    }

    #[test]
    fn late_dispatch_failure_and_abort_restore_real_mappings_without_readiness() {
        let wine = Mappings::new(c"wine-mapping", libc::MAP_SHARED);
        let dispatch = Mappings::new(c"artifact-dispatch-transaction", libc::MAP_SHARED);
        set_complete_clock(wine.second);
        assert_eq!(
            unsafe { libc::mprotect(dispatch.first.cast(), PAGE, libc::PROT_READ) },
            0
        );
        let _cleanup = RollbackOnDrop;

        const ARCH_GET_CPUID: libc::c_long = 0x1011;
        let previous_cpuid_mode =
            unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_CPUID, 0 as libc::c_ulong) };
        let cpuid_faulting_supported = previous_cpuid_mode >= 0
            && unsafe {
                libc::syscall(
                    libc::SYS_arch_prctl,
                    super::ARCH_SET_CPUID,
                    previous_cpuid_mode as libc::c_ulong,
                )
            } != -1;
        if !cpuid_faulting_supported {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODEV)
            );
            assert_eq!(
                unsafe { super::prepare_at(wine.first as usize) },
                Err(super::PrepareError::Worker(libc::ENODEV))
            );
            assert!(!super::ready());
            assert!(is_wine_source_mapping_at(wine.first as usize));
            assert_eq!(
                crate::maps::parse(mapping_line(wine.first).as_bytes())
                    .unwrap()
                    .permissions,
                b"rw-s"
            );
            return;
        }

        unsafe { super::prepare_at(wine.first as usize) }.unwrap();
        assert!(
            !super::ready(),
            "the worker alone must not publish readiness"
        );
        assert!(unsafe { super::prepare_dispatch_at(0) }.is_err());
        assert!(!super::ready());
        super::rollback().unwrap();
        assert!(is_wine_source_mapping_at(wine.first as usize));
        assert_eq!(
            crate::maps::parse(mapping_line(wine.first).as_bytes())
                .unwrap()
                .permissions,
            b"rw-s"
        );

        unsafe { super::prepare_at(wine.first as usize) }.unwrap();
        unsafe { super::prepare_dispatch_at(dispatch.first as usize) }.unwrap();
        assert!(
            !super::ready(),
            "dispatch preparation is not a successful bridge install"
        );
        assert_eq!(
            crate::maps::parse(mapping_line(dispatch.first).as_bytes())
                .unwrap()
                .permissions,
            b"r--p"
        );
        let saved = unsafe { dispatch.first.add(0x138).read() };
        unsafe { dispatch.second.add(0x138).write(saved ^ 0xff) };
        assert_eq!(unsafe { dispatch.first.add(0x138).read() }, saved);

        super::rollback().unwrap();
        assert!(!super::ready());
        assert!(is_wine_source_mapping_at(wine.first as usize));
        assert_eq!(
            crate::maps::parse(mapping_line(dispatch.first).as_bytes())
                .unwrap()
                .permissions,
            b"r--s"
        );
        assert_eq!(unsafe { dispatch.first.add(0x138).read() }, saved ^ 0xff);

        use pingu_protocol::cpuid::Vendor;
        store_u32(wine.second, 0x3c0, 12);
        unsafe { super::prepare_at(wine.first as usize) }.unwrap();
        assert!(!super::apply_profile(Vendor::Amd));
        assert_eq!(load_u32(wine.first, 0x3c0), 12);
        super::commit();
        // Keep the ordinary rollback guard responsible for this test's worker.
        super::STAGED_PID.store(unsafe { libc::getpid() }, Ordering::Release);
        assert!(!super::profile_ready());
        assert!(super::apply_profile(Vendor::Amd));
        assert!(super::profile_ready());
        assert_eq!(load_u32(wine.first, 0x3c0), 16);
        assert_eq!(load_u32(wine.second, 0x3c0), 12);
        assert_eq!(
            crate::maps::parse(mapping_line(wine.first).as_bytes())
                .unwrap()
                .permissions,
            b"r--s"
        );
        assert!(
            !super::apply_profile(Vendor::Intel),
            "a published profile is immutable"
        );

        set_time(wine.second, 0x14, 0x1234_5678, 0x44, 0x44);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while load_u32(wine.first, 0x14) != 0x1234_5678 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(load_u32(wine.first, 0x14), 0x1234_5678);
        assert_eq!(load_u32(wine.first, 0x3c0), 16);

        let child = unsafe { libc::syscall(libc::SYS_fork) };
        assert!(child >= 0);
        if child == 0 {
            unsafe { libc::alarm(3) };
            let rejected = !super::profile_ready() && !super::apply_profile(Vendor::Intel);
            unsafe { libc::_exit(if rejected { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child as libc::pid_t, &mut status, 0) },
            child as libc::pid_t
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        // The profile clears this feature byte for both vendors, so the byte
        // no longer tells them apart; the rejected re-apply above is the check.
        assert_eq!(unsafe { wine.first.add(0x297).read() }, 0);
        assert!(super::profile_ready());

        super::rollback().unwrap();
        assert!(!super::profile_ready());
        assert_eq!(load_u32(wine.first, 0x3c0), 12);
        unsafe { super::prepare_at(wine.first as usize) }.unwrap();
        super::commit();
        super::STAGED_PID.store(unsafe { libc::getpid() }, Ordering::Release);
        assert!(
            !super::profile_ready(),
            "a replacement backing needs a fresh profile"
        );
        assert!(super::apply_profile(Vendor::Intel));
        assert_eq!(unsafe { wine.first.add(0x297).read() }, 0);
        super::rollback().unwrap();
    }
}
