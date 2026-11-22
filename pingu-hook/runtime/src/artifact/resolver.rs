//! Resolver re-entry compatibility bridge (enabled by default;
//! `PINGU_RESOLVER_BRIDGE=0` disables it for diagnosis).
#![cfg_attr(test, allow(dead_code))]
use crate::errno::Errno;
#[cfg(test)]
use core::sync::atomic::AtomicU64;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

static BUSY: AtomicBool = AtomicBool::new(false);
static SITE: AtomicUsize = AtomicUsize::new(0);
static UNWIND_REGISTERED: AtomicBool = AtomicBool::new(false);
static DIAGNOSTIC_STAGE: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "debug")]
unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
}

fn log_info(message: &'static core::ffi::CStr) {
    #[cfg(feature = "debug")]
    {
        let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
        unsafe { debug_log(message.as_ptr()) };
    }
    #[cfg(not(feature = "debug"))]
    let _ = message;
}

#[unsafe(no_mangle)]
static PINGU_RESOLVER_GATEWAY: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static PINGU_RESOLVER_HOOK_POINTER: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
#[unsafe(no_mangle)]
static PINGU_RESOLVER_STATS: Stats = Stats::new();

#[cfg(test)]
#[repr(C)]
struct Stats {
    installed: AtomicU64,
    outer: AtomicU64,
    nested: AtomicU64,
}
#[cfg(test)]
impl Stats {
    const fn new() -> Self {
        Self {
            installed: AtomicU64::new(0),
            outer: AtomicU64::new(0),
            nested: AtomicU64::new(0),
        }
    }
}
#[cfg(not(test))]
core::arch::global_asm!(
    ".set PINGU_RESOLVER_STATS_ENABLED, 0\n",
    include_str!("resolver.S")
);
#[cfg(test)]
core::arch::global_asm!(
    ".set PINGU_RESOLVER_STATS_ENABLED, 1\n",
    include_str!("resolver.S")
);
unsafe extern "C" {
    fn pingu_resolver_entry();
    fn pingu_resolver_entry_end();
    fn pingu_resolver_clear_depth();
}

struct Observer {
    kernel: [usize; 4],
    ntdll: [usize; 4],
    export: usize,
    pristine: [u8; 5],
    // Up to two RUNTIME_FUNCTIONs sorted by address: this gateway and, in an
    // Artifact process, the loader's entry thunk (see include_unwind_function).
    function: [u32; 6],
    // Version 1/UHANDLER, 25-byte prologue, four unwind-code slots, RBP=RSP+160.
    unwind: [u32; 4],
}
struct Storage(UnsafeCell<Observer>);
// SAFETY: BUSY grants exclusive access; published function/unwind fields become immutable before RtlAddFunctionTable registers their process-lifetime storage.
unsafe impl Sync for Storage {}
static OBSERVER: Storage = Storage(UnsafeCell::new(Observer {
    kernel: [0; 4],
    ntdll: [0; 4],
    export: 0,
    pristine: [0; 5],
    function: [0; 6],
    unwind: [
        u32::from_le_bytes([0x11, 25, 4, 0xa5]),
        u32::from_le_bytes([17, 3, 9, 1]),
        u32::from_le_bytes([20, 0, 1, 0x50]),
        0,
    ],
}));
#[cfg(test)]
const _: () = assert!(
    core::mem::offset_of!(Stats, installed) == 0
        && core::mem::offset_of!(Stats, outer) == 8
        && core::mem::offset_of!(Stats, nested) == 16
);

pub(crate) fn after_fork() {
    BUSY.store(false, Ordering::Release);
    // The forking thread retains its active resolver frames. Their normal
    // returns/unwind callbacks still own the inherited TLS depth.
}

pub(crate) unsafe extern "C" fn signal_bridge(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut c_void,
) {
    let _errno = Errno::save();
    // SAFETY: Wine/kernel supplies unchanged live signal buffers.
    if signal != libc::SIGILL || !unsafe { handle(info, context) } {
        // SAFETY: preserve every unrelated signal's saved Wine disposition.
        unsafe { crate::hooks::forward_signal(signal, info, context) };
    }
}

pub(super) unsafe fn handle(info: *mut libc::siginfo_t, context: *mut c_void) -> bool {
    let site = SITE.load(Ordering::Acquire);
    if site == 0 || info.is_null() || context.is_null() {
        return false;
    }
    // SAFETY: the caller owns live signal frames; edit only the resumed RIP.
    let (code, frame) = unsafe { ((*info).si_code, &mut *context.cast::<libc::ucontext_t>()) };
    // Linux x86 UAPI ILL_ILLOPN (UD2); libc does not export this constant.
    if code != 2 || frame.uc_mcontext.gregs[libc::REG_RIP as usize] as usize != site {
        return false;
    }
    frame.uc_mcontext.gregs[libc::REG_RIP as usize] =
        pingu_resolver_entry as *const () as libc::greg_t;
    true
}

pub(crate) fn read_slice(at: usize, bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let Some(end) = at.checked_add(bytes.len()) else {
        return false;
    };
    if at == 0 || end >= 1_usize << 47 {
        return false;
    }
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: at as *mut c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: a bounded owned output; process_vm_readv checks source readability without dereferencing an untrusted PE pointer in this process.
    unsafe {
        libc::process_vm_readv(libc::gettid(), &local, 1, &remote, 1, 0) == bytes.len() as isize
    }
}

pub(crate) fn read<const N: usize>(at: usize) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    read_slice(at, &mut bytes).then_some(bytes)
}
fn word(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?) as usize)
}
/// Address of the bound import slot for `dll!name` in a mapped PE image.
pub(crate) fn import_slot(base: usize, dll: &[u8], name: &[u8]) -> Option<usize> {
    let dos = read::<64>(base)?;
    if &dos[..2] != b"MZ" {
        return None;
    }
    let pe = word(&dos, 60)?;
    if pe > 4096 {
        return None;
    }
    let nt = read::<152>(base.checked_add(pe)?)?;
    if &nt[..6] != b"PE\0\0\x64\x86" || &nt[24..26] != b"\x0b\x02" {
        return None;
    }
    let size = word(&nt, 80)?;
    let directory = word(&nt, 144)?;
    if !(4096..=0x1000_0000).contains(&size)
        || directory == 0
        || directory >= size
        || name.len() > 63
    {
        return None;
    }
    for index in 0..256 {
        let descriptor = read::<20>(base.checked_add(directory + index * 20)?)?;
        let (lookup, dll_at, first) = (
            word(&descriptor, 0)?,
            word(&descriptor, 12)?,
            word(&descriptor, 16)?,
        );
        if dll_at == 0 {
            return None;
        }
        if dll_at.checked_add(32)? > size || dll.len() >= 32 {
            return None;
        }
        let actual = read::<32>(base.checked_add(dll_at)?)?;
        if !actual[..dll.len()].eq_ignore_ascii_case(dll) || actual[dll.len()] != 0 {
            continue;
        }
        let table = if lookup != 0 { lookup } else { first };
        for slot in 0..4096 {
            let entry = u64::from_le_bytes(read::<8>(base.checked_add(table + slot * 8)?)?);
            if entry == 0 {
                break;
            }
            if entry >> 63 != 0 {
                continue;
            }
            let by_name = (entry as usize).checked_add(2)?;
            if by_name.checked_add(64)? > size {
                continue;
            }
            if read::<64>(base.checked_add(by_name)?)?[..name.len()] == *name {
                return base.checked_add(first + slot * 8);
            }
        }
    }
    None
}
pub(crate) fn export(base: usize, dll: &[u8], name: &[u8]) -> Option<usize> {
    let dos = read::<64>(base)?;
    if &dos[..2] != b"MZ" {
        return None;
    }
    let pe = word(&dos, 60)?;
    if pe > 4096 {
        return None;
    }
    let nt = read::<152>(base.checked_add(pe)?)?;
    if &nt[..6] != b"PE\0\0\x64\x86" || &nt[24..26] != b"\x0b\x02" {
        return None;
    }
    let size = word(&nt, 80)?;
    let directory = word(&nt, 136)?;
    let directory_size = word(&nt, 140)?;
    if !(4096..=0x1000_0000).contains(&size)
        || directory == 0
        || directory_size < 40
        || directory.checked_add(directory_size)? > size
    {
        return None;
    }
    let dir = read::<40>(base.checked_add(directory)?)?;
    let dll_at = word(&dir, 12)?;
    if dll_at.checked_add(32)? > size || dll.len() > 32 {
        return None;
    }
    let actual = read::<32>(base.checked_add(dll_at)?)?;
    if !actual[..dll.len()].eq_ignore_ascii_case(dll) {
        return None;
    }
    let functions = word(&dir, 20)?;
    let names = word(&dir, 24)?;
    let ft = word(&dir, 28)?;
    let nt = word(&dir, 32)?;
    let ot = word(&dir, 36)?;
    if functions == 0
        || names == 0
        || ft == 0
        || nt == 0
        || ot == 0
        || functions > 16384
        || names > 16384
        || ft.checked_add(functions * 4)? > size
        || nt.checked_add(names * 4)? > size
        || ot.checked_add(names * 2)? > size
        || name.len() > 64
    {
        return None;
    }
    for index in 0..names {
        let rva = u32::from_le_bytes(read::<4>(base.checked_add(nt + index * 4)?)?) as usize;
        if rva.checked_add(64)? > size {
            return None;
        }
        if &read::<64>(base.checked_add(rva)?)?[..name.len()] != name {
            continue;
        }
        let ordinal = u16::from_le_bytes(read::<2>(base.checked_add(ot + index * 2)?)?) as usize;
        if ordinal >= functions {
            return None;
        }
        let address = u32::from_le_bytes(read::<4>(base.checked_add(ft + ordinal * 4)?)?) as usize;
        if address == 0
            || address.checked_add(5)? > size
            || (directory..directory + directory_size).contains(&address)
        {
            return None;
        }
        return base.checked_add(address);
    }
    None
}

fn protection(address: usize, size: usize, anonymous: bool) -> Option<i32> {
    let end = address.checked_add(size)?;
    let mut found = None;
    crate::maps::find_line(|line| {
        let Some(mapping) = crate::maps::parse(line) else {
            return false;
        };
        if mapping.start <= address as u64
            && end as u64 <= mapping.end
            && matches!(mapping.permissions, b"r-xp" | b"rwxp")
            && (!anonymous || (mapping.inode == b"0" && mapping.path.is_empty()))
        {
            found = Some(
                libc::PROT_READ
                    | libc::PROT_EXEC
                    | if mapping.permissions[1] == b'w' {
                        libc::PROT_WRITE
                    } else {
                        0
                    },
            );
            true
        } else {
            false
        }
    });
    found
}

fn executable(address: usize, size: usize, anonymous: bool) -> bool {
    protection(address, size, anonymous).is_some()
}

unsafe extern "win64" fn unwind_cleanup(
    _: *mut c_void,
    frame: usize,
    _: *mut c_void,
    _: *mut c_void,
) -> i32 {
    // SAFETY: Wine supplies this registered frame; offset 96 marks an outer invocation.
    if unsafe { ptr::read_unaligned((frame + 96) as *const u32) } != 0 {
        // SAFETY: assembly modifies only this thread's dedicated TLS word.
        unsafe { pingu_resolver_clear_depth() };
    }
    1
}
fn register_unwind(observer: &mut Observer) -> bool {
    if UNWIND_REGISTERED.load(Ordering::Acquire) {
        return true;
    }
    let Some(add) = observer
        .ntdll
        .iter()
        .find_map(|base| export(*base, b"ntdll.dll\0", b"RtlAddFunctionTable\0"))
    else {
        diagnostic(5, c"resolver: unwind NTDLL export unavailable");
        return false;
    };
    // SAFETY: writable POD output for dladdr and an address in this ELF image.
    let mut info: libc::Dl_info = unsafe { core::mem::zeroed() };
    // SAFETY: exact libc query with initialized output.
    if unsafe {
        libc::dladdr(
            pingu_resolver_entry as *const () as *const c_void,
            &mut info,
        )
    } == 0
    {
        diagnostic(6, c"resolver: unwind ELF base unavailable");
        return false;
    }
    let base = info.dli_fbase as usize;
    let relative = |at: usize| at.checked_sub(base).and_then(|v| u32::try_from(v).ok());
    let (Some(begin), Some(end), Some(unwind), Some(cleanup)) = (
        relative(pingu_resolver_entry as *const () as usize),
        relative(pingu_resolver_entry_end as *const () as usize),
        relative(observer.unwind.as_ptr() as usize),
        relative(unwind_cleanup as *const () as usize),
    ) else {
        diagnostic(7, c"resolver: unwind metadata RVA outside u32");
        return false;
    };
    observer.unwind[3] = cleanup;
    let own = [begin, end, unwind];
    let mut count = 1;
    observer.function[..3].copy_from_slice(&own);
    if let Some(extra) = extra_unwind_function() {
        let (low, high) = if extra[0] < begin {
            (extra, own)
        } else {
            (own, extra)
        };
        observer.function[..3].copy_from_slice(&low);
        observer.function[3..].copy_from_slice(&high);
        count = 2;
    }
    // SAFETY: the validated PE export has the documented Windows ABI; the function and unwind arrays remain mapped and immutable until process exit.
    let add: unsafe extern "win64" fn(*const u32, u32, u64) -> u8 =
        unsafe { core::mem::transmute(add) };
    // SAFETY: complete three-word RUNTIME_FUNCTION and image-relative metadata.
    let registered = unsafe { add(observer.function.as_ptr(), count, base as u64) != 0 };
    if !registered {
        diagnostic(8, c"resolver: RtlAddFunctionTable returned false");
    } else {
        UNWIND_REGISTERED.store(true, Ordering::Release);
    }
    registered
}

/// Register the native resolver frame from the ordinary PE preparation
/// boundary. Mapping observation can run while Wine owns `virtual_mutex`;
/// RtlAddFunctionTable allocates from the process heap and therefore cannot be
/// called from that observer without a recursive virtual-memory lock hazard.
pub(crate) fn register_unwind_from_prepare() -> bool {
    if !crate::artifact::config::resolver_bridge_enabled()
        || UNWIND_REGISTERED.load(Ordering::Acquire)
    {
        return true;
    }
    if BUSY
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    let _errno = Errno::save();
    let registered = if let Some(_dispatch) = unsafe { crate::artifact::wine_dispatch_guard() } {
        // SAFETY: BUSY serializes mutable Observer access. This ordinary Wine
        // PE thread is outside mapping observation and Wine's virtual mutex.
        register_unwind(unsafe { &mut *OBSERVER.0.get() })
    } else {
        false
    };
    BUSY.store(false, Ordering::Release);
    registered
}

struct ExtraFunction(UnsafeCell<[u32; 3]>);
unsafe impl Sync for ExtraFunction {}
static EXTRA_FUNCTION: ExtraFunction = ExtraFunction(UnsafeCell::new([0; 3]));
static EXTRA_SET: AtomicBool = AtomicBool::new(false);

/// Wine selects the first dynamic function table whose [base, base + end)
/// range contains a PC. Another RUNTIME_FUNCTION in this image must
/// therefore join the gateway's table instead of being registered on its
/// own. Call before `register_unwind_from_prepare`.
pub(crate) fn include_unwind_function(function: [u32; 3]) {
    if UNWIND_REGISTERED.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: written once on the loader boundary thread before registration.
    unsafe { *EXTRA_FUNCTION.0.get() = function };
    EXTRA_SET.store(true, Ordering::Release);
}

fn extra_unwind_function() -> Option<[u32; 3]> {
    // SAFETY: immutable after EXTRA_SET is published.
    EXTRA_SET
        .load(Ordering::Acquire)
        .then(|| unsafe { *EXTRA_FUNCTION.0.get() })
}

/// True once the combined table (gateway plus any included function) is
/// registered.
pub(crate) fn unwind_registered() -> bool {
    UNWIND_REGISTERED.load(Ordering::Acquire) && extra_unwind_function().is_some()
}

/// With the resolver bridge disabled the gateway table is never registered,
/// so the included function is registered alone.
pub(crate) fn register_unwind_function_alone(ntdll: usize, function: [u32; 3]) -> bool {
    if crate::artifact::config::resolver_bridge_enabled() {
        return false;
    }
    let observer = unsafe { &*OBSERVER.0.get() };
    let Some(add) = [ntdll]
        .into_iter()
        .chain(observer.ntdll.iter().copied())
        .filter(|&base| base != 0)
        .find_map(|base| export(base, b"ntdll.dll\0", b"RtlAddFunctionTable\0"))
    else {
        return false;
    };
    let mut info: libc::Dl_info = unsafe { core::mem::zeroed() };
    if unsafe {
        libc::dladdr(
            pingu_resolver_entry as *const () as *const c_void,
            &mut info,
        )
    } == 0
    {
        return false;
    }
    // SAFETY: written once before registration; process-lifetime storage.
    let table = unsafe { &mut *EXTRA_FUNCTION.0.get() };
    *table = function;
    let add: unsafe extern "win64" fn(*const u32, u32, u64) -> u8 =
        unsafe { core::mem::transmute(add) };
    unsafe { add(table.as_ptr(), 1, info.dli_fbase as u64) != 0 }
}

fn prepare(observer: &mut Observer) {
    if observer.export == 0 {
        for base in observer.kernel {
            let Some(entry) = export(base, b"kernel32.dll\0", b"GetProcAddress\0") else {
                continue;
            };
            let Some(bytes) = read::<5>(entry) else {
                continue;
            };
            if matches!(bytes[0], 0xe9 | 0xff)
                || bytes[..2] == [0x0f, 0x0b]
                || !executable(entry, 5, false)
            {
                continue;
            }
            observer.export = entry;
            observer.pristine = bytes;
            log_info(c"resolver: export observed");
            break;
        }
    }
    if observer.export == 0 {
        return;
    }
    let Some(jump) = read::<5>(observer.export) else {
        return;
    };
    if jump[0] != 0xe9 {
        return;
    }
    diagnostic(1, c"resolver: export detour observed");
    let displacement = i32::from_le_bytes([jump[1], jump[2], jump[3], jump[4]]);
    let Some(site) = observer
        .export
        .checked_add(5)
        .and_then(|v| v.checked_add_signed(displacement as isize))
    else {
        return;
    };
    if site < 19 || site & 63 > 62 || unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != 4096 {
        return;
    }
    let Some(original_protection) = protection(site - 19, 33, true) else {
        return;
    };
    diagnostic(2, c"resolver: private executable pair observed");
    let Some(pair) = read::<33>(site - 19) else {
        return;
    };
    let Some(target) = validate_pair(observer.export, &observer.pristine, &pair) else {
        return;
    };
    diagnostic(3, c"resolver: gateway pair matched");
    if (site - 19..site + 14).contains(&target) || !executable(target, 1, false) {
        return;
    }
    if !UNWIND_REGISTERED.load(Ordering::Acquire) {
        diagnostic(
            4,
            c"resolver: unwind metadata was not registered at PE preparation; gate declined",
        );
        return;
    }
    PINGU_RESOLVER_GATEWAY.store(site - 19, Ordering::Release);
    PINGU_RESOLVER_HOOK_POINTER.store(site + 6, Ordering::Release);
    SITE.store(site, Ordering::Release);
    let page = site & !4095;
    // SAFETY: the complete private anonymous RX pair and page were validated.
    if unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page,
            4096,
            (original_protection | libc::PROT_WRITE) as libc::c_long,
        )
    } != 0
    {
        fail(b"pingu_protocol: resolver trampoline write access failed\n");
    }
    let mut previous = 0x25ff_u16;
    // SAFETY: validated two-byte word lies within one cache line and page. x86 locked compare-exchange handles unaligned instruction storage without constructing an unaligned Rust atomic reference.
    unsafe {
        core::arch::asm!("lock cmpxchg word ptr [{site}], {new:x}",site=in(reg)site,new=in(reg)0x0b0f_u16,inout("ax")previous,options(nostack));
    }
    // SAFETY: restore this same page's validated original RX or RWX protection.
    if unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page,
            4096,
            original_protection as libc::c_long,
        )
    } != 0
        || previous != 0x25ff
    {
        fail(b"pingu_protocol: resolver trampoline publication failed\n");
    }
    #[cfg(test)]
    PINGU_RESOLVER_STATS.installed.store(1, Ordering::Release);
    log_info(c"resolver: pair gate ready");
}
fn diagnostic(stage: usize, message: &'static core::ffi::CStr) {
    if DIAGNOSTIC_STAGE.fetch_max(stage, Ordering::Relaxed) < stage {
        log_info(message);
    }
}
fn validate_pair(export: usize, pristine: &[u8; 5], pair: &[u8; 33]) -> Option<usize> {
    let continuation = u64::from_le_bytes(pair[11..19].try_into().ok()?) as usize;
    let target = u64::from_le_bytes(pair[25..33].try_into().ok()?) as usize;
    (pair[..5] == *pristine
        && pair[5..11] == [0xff, 0x25, 0, 0, 0, 0]
        && pair[19..25] == [0xff, 0x25, 0, 0, 0, 0]
        && continuation == export.checked_add(5)?
        && target != 0)
        .then_some(target)
}

fn mapping_basename(fd: i32, offset: libc::off_t, protection: i32) -> Option<([u8; 64], usize)> {
    if fd < 0 || offset != 0 || protection & libc::PROT_READ == 0 {
        return None;
    }
    let mut link = [0_u8; 64];
    let prefix = b"/proc/self/fd/";
    link[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0_u8; 10];
    let mut value = fd as u32;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for i in 0..count {
        link[prefix.len() + i] = digits[count - i - 1];
    }
    let mut path = [0_u8; 4096];
    // SAFETY: complete NUL-terminated path and bounded writable output.
    let used =
        unsafe { libc::readlink(link.as_ptr().cast(), path.as_mut_ptr().cast(), path.len()) };
    if used <= 0 || used >= path.len() as isize {
        return None;
    }
    let name = path[..used as usize].rsplit(|b| *b == b'/').next()?;
    if name.len() > 63 {
        return None;
    }
    let mut out = [0_u8; 64];
    out[..name.len()].copy_from_slice(name);
    Some((out, name.len()))
}

pub(crate) fn observe(address: usize, protection: i32, fd: i32, offset: libc::off_t) {
    // SAFETY: this native thread owns errno; restored on every return.
    let _errno = Errno::save();
    let image = mapping_basename(fd, offset, protection);
    if let Some((name, len)) = &image {
        crate::artifact::loader::observe_image(&name[..*len], address);
    }
    if !crate::artifact::config::resolver_bridge_enabled()
        || SITE.load(Ordering::Acquire) != 0
        || BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
    // SAFETY: BUSY serializes all mutable observer access; published arrays are never modified after SITE becomes nonzero.
    let observer = unsafe { &mut *OBSERVER.0.get() };
    if let Some((name, len)) = image {
        let name = &name[..len];
        let list = if name.eq_ignore_ascii_case(b"kernel32.dll") {
            Some(&mut observer.kernel)
        } else if name.eq_ignore_ascii_case(b"ntdll.dll") {
            Some(&mut observer.ntdll)
        } else {
            None
        };
        if let Some(list) = list
            && let Some(slot) = list.iter_mut().find(|v| **v == 0 || **v == address)
        {
            *slot = address;
        }
    }
    // Wine maps NTDLL before installing its signal handlers. Remember header
    // mappings immediately, but never publish a trap before owning its chain.
    if protection & libc::PROT_EXEC != 0 && crate::hooks::resolver_signal_ready() {
        prepare(observer);
    }
    BUSY.store(false, Ordering::Release);
}

/// Native mprotect interposition is included only in Artifact builds. The
/// observer never changes the requested operation's return value or errno.
#[cfg(not(test))]
pub(crate) unsafe extern "C" fn mprotect(
    address: *mut c_void,
    length: usize,
    protection: i32,
) -> i32 {
    crate::artifact::loader::before_mprotect(address as usize, length, protection);
    // SAFETY: unchanged libc ABI, full-width variadic syscall arguments.
    let result = unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            address,
            length,
            protection as libc::c_long,
        )
    } as i32;
    if result == 0 {
        observe(address as usize, protection, -1, 0);
    }
    result
}

fn fail(message: &[u8]) -> ! {
    // SAFETY: only a validated gate's failed protection/publication reaches this.
    let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
    unsafe {
        libc::write(2, message.as_ptr().cast(), message.len());
        libc::_exit(70);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_char;
    use std::sync::Mutex;

    static SERIAL: Mutex<()> = Mutex::new(());
    static HOOK: AtomicUsize = AtomicUsize::new(0);
    static HOOK_DEPTH: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn resolver_fork_reset_retains_live_frame_depth() {
        unsafe fn set(value: u32) {
            unsafe {
                core::arch::asm!(
                "mov rax, qword ptr [rip+pingu_resolver_depth@gottpoff]",
                "mov dword ptr fs:[rax], {value:e}",
                value=in(reg)value, out("rax") _, options(nostack));
            }
        }
        unsafe fn get() -> u32 {
            let value: u32;
            unsafe {
                core::arch::asm!(
                "mov rax, qword ptr [rip+pingu_resolver_depth@gottpoff]",
                "mov {value:e}, dword ptr fs:[rax]",
                value=out(reg)value, out("rax") _, options(nostack));
            }
            value
        }
        unsafe {
            set(1);
        }
        after_fork();
        let inherited = unsafe { get() };
        unsafe {
            set(0);
        }
        assert_eq!(inherited, 1);
    }

    #[test]
    fn resolver_observer_retains_ntdll_header_before_wine_claims_sigill() {
        if std::env::var_os("PINGU_OWNED_RESOLVER_EARLY_MAP_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .env("PINGU_OWNED_RESOLVER_EARLY_MAP_CHILD", "1")
                .env("PINGU_HOOK_PATH", "artifact").env("PINGU_RESOLVER_BRIDGE", "1")
                .args(["--exact", "artifact::resolver::tests::resolver_observer_retains_ntdll_header_before_wine_claims_sigill", "--test-threads=1"])
                .status().unwrap();
            assert!(status.success());
            return;
        }
        use std::os::fd::AsRawFd;
        assert!(crate::artifact::config::resolver_bridge_enabled());
        assert!(!crate::hooks::resolver_signal_ready());
        let directory =
            std::env::temp_dir().join(format!("pingu-resolver-early-map-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("ntdll.dll");
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(4096).unwrap();
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        observe(mapping as usize, libc::PROT_READ, file.as_raw_fd(), 0);
        let remembered = unsafe { &*OBSERVER.0.get() }
            .ntdll
            .contains(&(mapping as usize));
        unsafe { libc::munmap(mapping, 4096) };
        drop(file);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
        assert!(
            remembered,
            "NTDLL header predates Wine's SIGILL handler and must still be cached"
        );
        assert_eq!(
            SITE.load(Ordering::Acquire),
            0,
            "early observation cannot publish a gate"
        );
    }

    type Resolve = unsafe extern "win64" fn(*mut c_void, *const c_char) -> *mut c_void;

    unsafe extern "win64" fn original(module: *mut c_void, name: *const c_char) -> *mut c_void {
        // SAFETY: the fixture passes a valid dlopen handle and terminated name.
        unsafe { libc::dlsym(module, name) }
    }

    unsafe extern "win64" fn recursive_hook(
        module: *mut c_void,
        name: *const c_char,
    ) -> *mut c_void {
        if HOOK_DEPTH.fetch_add(1, Ordering::Relaxed) != 0 {
            HOOK_DEPTH.fetch_sub(1, Ordering::Relaxed);
            return ptr::null_mut(); // Bound a broken recursion guard to one retry.
        }
        // SAFETY: assembly uses Win64 arguments and forwards the same request.
        let resolve: Resolve = unsafe { core::mem::transmute(pingu_resolver_entry as *const ()) };
        let result = unsafe { resolve(module, name) };
        HOOK_DEPTH.fetch_sub(1, Ordering::Relaxed);
        result
    }

    // If nested calls re-enter the hook, the authored hook returns NULL.
    // The bridge must instead return the real loader's symbol address.
    #[test]
    fn resolver_recursion_reaches_original_and_retains_actual_loader_answers() {
        let _lock = SERIAL.lock().unwrap();
        HOOK.store(recursive_hook as *const () as usize, Ordering::Release);
        PINGU_RESOLVER_HOOK_POINTER.store(&HOOK as *const _ as usize, Ordering::Release);
        PINGU_RESOLVER_GATEWAY.store(original as *const () as usize, Ordering::Release);
        PINGU_RESOLVER_STATS.outer.store(0, Ordering::Relaxed);
        PINGU_RESOLVER_STATS.nested.store(0, Ordering::Relaxed);
        let resolve: Resolve = unsafe { core::mem::transmute(pingu_resolver_entry as *const ()) };
        let actual = unsafe { resolve(libc::RTLD_DEFAULT, c"getpid".as_ptr()) };
        let expected = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"getpid".as_ptr()) };
        assert!(!expected.is_null());
        assert_eq!(actual, expected);
        assert!(
            unsafe {
                resolve(
                    libc::RTLD_DEFAULT,
                    c"owned_fixture_absent_symbol_49e3".as_ptr(),
                )
            }
            .is_null()
        );
        assert_eq!(HOOK_DEPTH.load(Ordering::Relaxed), 0);
        assert_eq!(PINGU_RESOLVER_STATS.outer.load(Ordering::Relaxed), 2);
        assert_eq!(PINGU_RESOLVER_STATS.nested.load(Ordering::Relaxed), 2);
        PINGU_RESOLVER_HOOK_POINTER.store(0, Ordering::Release);
        PINGU_RESOLVER_GATEWAY.store(0, Ordering::Release);
    }

    #[test]
    fn resolver_pe_lookup_refuses_forwarded_and_out_of_image_exports() {
        let lookup = |image: &[u8]| {
            // The native syscall reader observes memory through an integer
            // address. Keep every fixture mutation visible to that reader.
            std::hint::black_box(image);
            export(
                image.as_ptr() as usize,
                b"kernel32.dll\0",
                b"GetProcAddress\0",
            )
        };
        let mut image = [0u8; 4096];
        image[..2].copy_from_slice(b"MZ");
        image[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x86].copy_from_slice(b"PE\0\0\x64\x86");
        image[0x98..0x9a].copy_from_slice(b"\x0b\x02");
        for (at, value) in [
            (0xd0, 4096u32),
            (0x108, 0x200),
            (0x10c, 40),
            (0x20c, 0x300),
            (0x214, 1),
            (0x218, 1),
            (0x21c, 0x340),
            (0x220, 0x350),
            (0x224, 0x360),
            (0x340, 0x600),
            (0x350, 0x400),
        ] {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        image[0x300..0x30d].copy_from_slice(b"kernel32.dll\0");
        image[0x400..0x40f].copy_from_slice(b"GetProcAddress\0");
        let base = image.as_ptr() as usize;
        assert_eq!(lookup(&image), Some(base + 0x600));
        image[0x340..0x344].copy_from_slice(&0x210u32.to_le_bytes());
        assert_eq!(lookup(&image), None);
        image[0x340..0x344].copy_from_slice(&4095u32.to_le_bytes());
        assert_eq!(lookup(&image), None);
        image[0x80] = 0;
        assert_eq!(lookup(&image), None);
    }

    #[test]
    fn resolver_sigill_declines_unfamiliar_sites_and_retains_full_xstate_pointer() {
        let _lock = SERIAL.lock().unwrap();
        SITE.store(0x1234, Ordering::Release);
        let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
        info.si_code = 2;
        let mut frame: libc::ucontext_t = unsafe { core::mem::zeroed() };
        frame.uc_mcontext.gregs[libc::REG_RIP as usize] = 0x4321;
        frame.uc_mcontext.fpregs = ptr::dangling_mut();
        assert!(!unsafe { handle(&mut info, (&mut frame as *mut libc::ucontext_t).cast()) });
        assert_eq!(frame.uc_mcontext.gregs[libc::REG_RIP as usize], 0x4321);
        frame.uc_mcontext.gregs[libc::REG_RIP as usize] = 0x1234;
        assert!(unsafe { handle(&mut info, (&mut frame as *mut libc::ucontext_t).cast()) });
        assert_eq!(
            frame.uc_mcontext.gregs[libc::REG_RIP as usize] as usize,
            pingu_resolver_entry as *const () as usize
        );
        assert_eq!(frame.uc_mcontext.fpregs, ptr::dangling_mut());
        SITE.store(0, Ordering::Release);
    }

    // A wrong continuation, altered instruction, or null handler must never
    // authorize editing an unfamiliar private executable mapping.
    #[test]
    fn resolver_pair_requires_the_original_gateway_and_nonzero_handler() {
        let pristine = [0x48, 0x89, 0x5c, 0x24, 0x08];
        let mut pair = [0; 33];
        pair[..5].copy_from_slice(&pristine);
        pair[5..11].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
        pair[11..19].copy_from_slice(&0x1005u64.to_le_bytes());
        pair[19..25].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
        pair[25..33].copy_from_slice(&0x3000u64.to_le_bytes());
        assert_eq!(validate_pair(0x1000, &pristine, &pair), Some(0x3000));
        for at in [0, 5, 11, 19] {
            let mut unfamiliar = pair;
            unfamiliar[at] ^= 1;
            assert_eq!(validate_pair(0x1000, &pristine, &unfamiliar), None);
        }
        pair[25..33].fill(0);
        assert_eq!(validate_pair(0x1000, &pristine, &pair), None);
        assert_eq!(validate_pair(usize::MAX, &pristine, &pair), None);
    }

    #[test]
    fn bridge_disabled_unwind_fallback_registers_single_function_in_fresh_process() {
        const CHILD: &str = "PINGU_OWNED_BRIDGE_DISABLED_UNWIND_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .env(CHILD, "1")
                .env("PINGU_HOOK_PATH", "artifact").env("PINGU_RESOLVER_BRIDGE", "0")
                .args([
                    "--exact",
                    "artifact::resolver::tests::bridge_disabled_unwind_fallback_registers_single_function_in_fresh_process",
                    "--test-threads=1",
                ])
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        assert!(!crate::artifact::config::resolver_bridge_enabled());
        assert!(unsafe { &*OBSERVER.0.get() }.ntdll.iter().all(|&b| b == 0));

        static RECORDED_COUNT: core::sync::atomic::AtomicU32 =
            core::sync::atomic::AtomicU32::new(0);
        static RECORDED_ENTRY: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
        static RECORDED_BASE: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "win64" fn fake_rtl_add(table: *const u32, count: u32, base: u64) -> u8 {
            RECORDED_COUNT.store(count, Ordering::Release);
            RECORDED_BASE.store(base as usize, Ordering::Release);
            if !table.is_null() && count >= 1 {
                for (i, slot) in RECORDED_ENTRY.iter().enumerate() {
                    slot.store(unsafe { *table.add(i) } as usize, Ordering::Release);
                }
            }
            1
        }

        const ALIGN: usize = 0x1_0000;
        let block_len = ALIGN * 2;
        let block = unsafe {
            libc::mmap(
                ptr::null_mut(),
                block_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(block, libc::MAP_FAILED);
        let base = ((block as usize) + ALIGN - 1) & !(ALIGN - 1);
        let image = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, ALIGN) };
        image[..2].copy_from_slice(b"MZ");
        image[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x86].copy_from_slice(b"PE\0\0\x64\x86");
        image[0x98..0x9a].copy_from_slice(b"\x0b\x02");
        for (at, value) in [
            (0xd0, ALIGN as u32),
            (0x108, 0x200),
            (0x10c, 40),
            (0x20c, 0x300),
            (0x214, 1),
            (0x218, 1),
            (0x21c, 0x340),
            (0x220, 0x350),
            (0x224, 0x360),
            (0x340, 0x600),
            (0x350, 0x400),
        ] {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        image[0x300..0x30a].copy_from_slice(b"ntdll.dll\0");
        image[0x400..0x414].copy_from_slice(b"RtlAddFunctionTable\0");
        // Trampoline: movabs rax, fake_rtl_add; jmp rax
        image[0x600..0x602].copy_from_slice(&[0x48, 0xb8]);
        image[0x602..0x60a].copy_from_slice(&(fake_rtl_add as *const () as usize).to_le_bytes());
        image[0x60a..0x60c].copy_from_slice(&[0xff, 0xe0]);
        assert_eq!(
            unsafe {
                libc::mprotect(
                    base as *mut c_void,
                    ALIGN,
                    libc::PROT_READ | libc::PROT_EXEC,
                )
            },
            0
        );

        let func = [0x100, 0x120, 0x200];
        let ok = register_unwind_function_alone(base, func);
        unsafe { libc::munmap(block, block_len) };

        assert!(ok);
        assert_eq!(RECORDED_COUNT.load(Ordering::Acquire), 1);
        assert_ne!(RECORDED_BASE.load(Ordering::Acquire), 0);
        assert_eq!(
            [
                RECORDED_ENTRY[0].load(Ordering::Acquire) as u32,
                RECORDED_ENTRY[1].load(Ordering::Acquire) as u32,
                RECORDED_ENTRY[2].load(Ordering::Acquire) as u32,
            ],
            func
        );
    }
}
