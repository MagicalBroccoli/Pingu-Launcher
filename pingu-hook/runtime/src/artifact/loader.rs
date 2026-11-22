//! Stock-Wine loader support for Artifact, with only `LD_PRELOAD`.
//!
//! Artifact's DllMain replaces `PEB->Ldr` with byte-shallow copies of the
//! three list heads. Stock Wine reads every loader list through
//! `Peb->LdrData` (its static `ldr` is touched only at initialization), so the
//! copy's stale back-links make Wine's walks loop forever. This module:
//!
//! 1. gets one early PE-context boundary: `kernel32!DllMain` ends with a call
//!    through its `RtlReleasePebLock` import slot. That slot is pointed at
//!    `release_peb_lock` just before Wine makes the import page read-only.
//!    The call runs on the initial thread, under the loader lock, after the
//!    executable's imports are bound and before any of their TLS callbacks
//!    or DllMain run;
//! 2. at that boundary, in an Artifact process only: prepares ART, makes
//!    `PEB.ProcessHeaps` live (`peb_heaps`) and wraps Artifact's entry;
//! 3. when Artifact's DllMain returns (still under the loader lock), adopts
//!    the public copy by relinking the neighbours' back-links, all or nothing,
//!    and tags Artifact's public-only entries so Wine never delivers DllMain
//!    or TLS lifecycle calls to them.
//!    If Artifact also copied the PEB, Wine's original process PEB must point
//!    at the adopted loader data: process-information queries still return it.
//!
//! Any failure terminates the process with a message before Wine can walk an
//! incoherent list.
#![cfg_attr(test, allow(dead_code))]
use crate::errno::Errno;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

static NTDLL_BASE: AtomicUsize = AtomicUsize::new(0);
static KERNEL32_BASE: AtomicUsize = AtomicUsize::new(0);
/// `kernel32` import slot for `RtlReleasePebLock`; `usize::MAX` if unusable.
static SLOT: AtomicUsize = AtomicUsize::new(0);
static SLOT_PATCHED: AtomicBool = AtomicBool::new(false);
static REAL_RELEASE: AtomicUsize = AtomicUsize::new(0);
static BOUNDARY_RAN: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);

static CANONICAL_LDR: AtomicUsize = AtomicUsize::new(0);
static CANONICAL_PEB: AtomicUsize = AtomicUsize::new(0);
static ARTIFACT_ENTRY: AtomicUsize = AtomicUsize::new(0);
static REAL_ENTRY: AtomicUsize = AtomicUsize::new(0);

struct EntryUnwind(core::cell::UnsafeCell<[u32; 3]>);
unsafe impl Sync for EntryUnwind {}
/// UNWIND_INFO for `pingu_artifact_entry_thunk`: version 1 with exception
/// and unwind handlers, a 4-byte prologue (`sub rsp, 40`), one
/// UWOP_ALLOC_SMALL, then the handler RVA (filled at the boundary).
static ENTRY_UNWIND: EntryUnwind = EntryUnwind(core::cell::UnsafeCell::new([
    u32::from_le_bytes([0x19, 4, 1, 0]),
    u32::from_le_bytes([4, 0x42, 0, 0]),
    0,
]));

const MAX_LIST_NODES: usize = 4096;
const MIN_USER_ADDRESS: usize = 0x10000;
const LDR_DONT_CALL_DLLMAIN: u32 = 0x2000_0000;
const STATUS_DLL_INIT_FAILED: u32 = 0xC000_0142;

// LDR_DATA_TABLE_ENTRY (x64) offsets.
const ENTRY_DLL_BASE: usize = 0x30;
const ENTRY_ENTRY_POINT: usize = 0x38;
const ENTRY_SIZE_OF_IMAGE: usize = 0x40;
const ENTRY_BASE_NAME: usize = 0x58;
const ENTRY_FLAGS: usize = 0x68;
const ENTRY_LOAD_COUNT: usize = 0x6c;
// PEB_LDR_DATA list heads: load, memory and initialization order.
const HEADS: [usize; 3] = [0x10, 0x20, 0x30];

/// Record image bases from the mmap observer (Unix side: memory only).
pub(crate) fn observe_image(name: &[u8], address: usize) {
    let base = if name.eq_ignore_ascii_case(b"ntdll.dll") {
        &NTDLL_BASE
    } else if name.eq_ignore_ascii_case(b"kernel32.dll") {
        &KERNEL32_BASE
    } else {
        return;
    };
    let _ = base.compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire);
}

/// Called by the `mprotect` interposer before the real call. When Wine makes
/// kernel32's bound ntdll import page read-only again, point its
/// `RtlReleasePebLock` slot at `release_peb_lock`. Unix side, under Wine's
/// virtual lock: memory reads and one checked self-write only.
pub(crate) fn before_mprotect(address: usize, length: usize, protection: i32) {
    if protection & libc::PROT_WRITE != 0 || SLOT_PATCHED.load(Ordering::Acquire) {
        return;
    }
    let (kernel32, ntdll) = (
        KERNEL32_BASE.load(Ordering::Acquire),
        NTDLL_BASE.load(Ordering::Acquire),
    );
    if kernel32 == 0 || ntdll == 0 {
        return;
    }
    let _errno = Errno::save();
    let slot = match SLOT.load(Ordering::Acquire) {
        0 => {
            let found = crate::artifact::resolver::import_slot(
                kernel32,
                b"ntdll.dll",
                b"RtlReleasePebLock\0",
            )
            .unwrap_or(usize::MAX);
            SLOT.store(found, Ordering::Release);
            found
        }
        known => known,
    };
    if slot == usize::MAX || slot < address || slot - address >= length {
        return;
    }
    let Some(real) =
        crate::artifact::resolver::export(ntdll, b"ntdll.dll\0", b"RtlReleasePebLock\0")
    else {
        return;
    };
    // Only a bound slot: Wine restores protection after binding each DLL.
    if crate::artifact::resolver::read::<8>(slot).map(usize::from_le_bytes) != Some(real) {
        return;
    }
    REAL_RELEASE.store(real, Ordering::Release);
    let stub = (release_peb_lock as *const () as usize).to_le_bytes();
    if self_write(slot, &stub) {
        SLOT_PATCHED.store(true, Ordering::Release);
    }
}

/// Write through process_vm_writev, which fails instead of faulting if the
/// page is not writable.
fn self_write(address: usize, bytes: &[u8]) -> bool {
    let local = libc::iovec {
        iov_base: bytes.as_ptr() as *mut c_void,
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: bytes.len(),
    };
    let written = unsafe { libc::process_vm_writev(libc::getpid(), &local, 1, &remote, 1, 0) };
    written == bytes.len() as isize
}

/// Replaces kernel32's `RtlReleasePebLock` import. Releases the PEB lock
/// first, so the boundary never runs while holding it.
unsafe extern "win64" fn release_peb_lock() {
    let real: unsafe extern "win64" fn() =
        unsafe { core::mem::transmute(REAL_RELEASE.load(Ordering::Acquire)) };
    unsafe { real() };
    // The first call is the end of kernel32's PROCESS_ATTACH: kernel32 holds
    // the PEB lock from its RtlAcquirePebLock until this release. Artifact
    // processes that miss this boundary are stopped by `require_armed`.
    if !BOUNDARY_RAN.swap(true, Ordering::AcqRel) {
        early_boundary();
    }
}

/// Artifact's protocol CPUID leaves call this before any protocol effect. If
/// the loader boundary did not arm (a missed hook, an Artifact load Wine did
/// not report through its load list, or a dynamic load after the boundary),
/// stop: Artifact's later `PEB->Ldr` swap would make Wine's walks endless.
/// Signal context: async-signal-safe calls only.
pub(crate) fn require_armed() {
    if !ARMED.load(Ordering::Acquire) {
        let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
        let message = b"pingu_protocol: Artifact started without the loader boundary; stopping\n";
        unsafe {
            libc::write(2, message.as_ptr().cast(), message.len());
            libc::_exit(70);
        }
    }
}

#[cfg(test)]
pub(crate) fn arm_for_test() {
    ARMED.store(true, Ordering::Release);
}

struct CanonicalSnapshot(core::cell::UnsafeCell<SnapshotData>);
unsafe impl Sync for CanonicalSnapshot {}
struct SnapshotData {
    nodes: [[usize; MAX_LIST_NODES]; 3],
    lens: [usize; 3],
}
static CANONICAL_SNAPSHOT: CanonicalSnapshot =
    CanonicalSnapshot(core::cell::UnsafeCell::new(SnapshotData {
        nodes: [[0; MAX_LIST_NODES]; 3],
        lens: [0; 3],
    }));
static SNAPSHOT_VALID: AtomicBool = AtomicBool::new(false);

fn early_boundary() {
    let _errno = Errno::save();
    let peb = current_peb();
    let canonical = peek(peb + 0x18).unwrap_or(0);
    if !plausible_ldr(canonical) {
        fatal(b"pingu_protocol: Wine loader data is not readable at the kernel32 boundary\n");
    }
    let entry = match find_entry(canonical, b"artifact.dll") {
        Ok(Some(entry)) => entry,
        Ok(None) => return,
        Err(()) => {
            fatal(b"pingu_protocol: Wine loader list is not readable at the kernel32 boundary\n")
        }
    };
    CANONICAL_LDR.store(canonical, Ordering::Release);
    CANONICAL_PEB.store(peb, Ordering::Release);
    crate::artifact::config::set_artifact_vbs20_marker(image_has_vbs20_marker(entry));
    // The resolver and the entry thunk share this image base, and Wine picks
    // the first registered table whose range [base, base + end) contains a
    // PC. Both functions are therefore registered as one sorted table.
    let Some(function) = entry_unwind_function() else {
        fatal(b"pingu_protocol: Artifact entry thunk unwind data is invalid\n");
    };
    crate::artifact::resolver::include_unwind_function(function);
    if unsafe { crate::artifact::entry::pingu_artifact_prepare() } != 1 {
        fatal(b"pingu_protocol: ART preparation failed at the loader boundary\n");
    }
    let ntdll = find_entry(canonical, b"ntdll.dll")
        .ok()
        .flatten()
        .and_then(|e| peek(e + ENTRY_DLL_BASE))
        .filter(|&b| b != 0)
        .unwrap_or_else(|| NTDLL_BASE.load(Ordering::Acquire));
    if !crate::artifact::resolver::unwind_registered()
        && !crate::artifact::resolver::register_unwind_function_alone(ntdll, function)
    {
        fatal(b"pingu_protocol: could not register unwind data for the Artifact entry thunk\n");
    }
    let modules = [
        find_entry(canonical, b"kernel32.dll")
            .ok()
            .flatten()
            .and_then(|e| peek(e + ENTRY_DLL_BASE))
            .unwrap_or(0),
        find_entry(canonical, b"kernelbase.dll")
            .ok()
            .flatten()
            .and_then(|e| peek(e + ENTRY_DLL_BASE))
            .unwrap_or(0),
    ];
    if modules.contains(&0) || !crate::artifact::peb_heaps::install(ntdll, &modules) {
        fatal(b"pingu_protocol: PEB.ProcessHeaps could not be made live\n");
    }
    let real = peek(entry + ENTRY_ENTRY_POINT).unwrap_or(0);
    if real == 0 {
        fatal(b"pingu_protocol: Artifact has no entry point\n");
    }
    REAL_ENTRY.store(real, Ordering::Release);
    ARTIFACT_ENTRY.store(entry, Ordering::Release);
    let thunk = pingu_artifact_entry_thunk as *const () as usize;
    if !self_write(entry + ENTRY_ENTRY_POINT, &thunk.to_le_bytes()) {
        fatal(b"pingu_protocol: Artifact entry point could not be wrapped\n");
    }
    ARMED.store(true, Ordering::Release);
    note(c"Artifact loader boundary armed");
}

unsafe extern "C" {
    fn pingu_artifact_entry_thunk();
    fn pingu_artifact_entry_thunk_end();
}

// Wine calls Artifact's entry through this thunk. It restores the real
// EntryPoint, calls it, then adopts the loader data. Its registered unwind
// data names `entry_exception_handler`, so an exception that escapes
// Artifact's DllMain stops the process here instead of reaching Wine's
// DLL-init failure path with unrepaired lists.
core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".globl pingu_artifact_entry_thunk",
    ".hidden pingu_artifact_entry_thunk",
    "pingu_artifact_entry_thunk:",
    "    sub rsp, 40",
    "    mov [rsp + 48], rcx",
    "    mov [rsp + 56], rdx",
    "    mov [rsp + 64], r8",
    "    call {before}",
    "    mov rcx, [rsp + 48]",
    "    mov rdx, [rsp + 56]",
    "    mov r8, [rsp + 64]",
    "    call qword ptr [rip + {real}]",
    "    mov [rsp + 32], eax",
    "    call {after}",
    "    mov eax, [rsp + 32]",
    "    add rsp, 40",
    "    ret",
    ".globl pingu_artifact_entry_thunk_end",
    ".hidden pingu_artifact_entry_thunk_end",
    "pingu_artifact_entry_thunk_end:",
    before = sym before_entry,
    after = sym after_entry,
    real = sym REAL_ENTRY,
);

/// Scan the mapped `artifact.dll` (still before its DllMain) for the VBS 2.0
/// dialog text, one page at a time so the buffer stays small on the Windows
/// stack and an unreadable page only hides itself. A missing or implausible
/// image counts as VBS 1.9. Kept out of line: the boundary hook that calls
/// it runs on every `RtlReleasePebLock` from kernel32.
#[inline(never)]
fn image_has_vbs20_marker(entry: usize) -> bool {
    const PAGE: usize = 0x1000;
    const MAX_IMAGE: usize = 256 * 1024 * 1024;
    const CARRY: usize = 64;
    const _: () = assert!(pingu_protocol::artifact::profile::VBS20_MARKER.len() <= CARRY);
    let keep = pingu_protocol::artifact::profile::VBS20_MARKER.len() - 1;
    let (Some(base), Some(size)) = (
        peek(entry + ENTRY_DLL_BASE),
        peek_bytes::<4>(entry + ENTRY_SIZE_OF_IMAGE).map(u32::from_le_bytes),
    ) else {
        return false;
    };
    if base < MIN_USER_ADDRESS || base % PAGE != 0 {
        return false;
    }
    let Some(end) = base.checked_add((size as usize).min(MAX_IMAGE)) else {
        return false;
    };
    let mut buffer = [0u8; CARRY + PAGE];
    let mut carried = 0;
    let mut page = base;
    while page < end {
        let length = PAGE.min(end - page);
        let total = carried + length;
        if crate::artifact::resolver::read_slice(page, &mut buffer[carried..total]) {
            if pingu_protocol::artifact::profile::contains_vbs20_marker(&buffer[..total]) {
                return true;
            }
            // Carry the tail so a marker across a page boundary is found.
            let tail = keep.min(total);
            buffer.copy_within(total - tail..total, 0);
            carried = tail;
        } else {
            carried = 0;
        }
        let Some(next) = page.checked_add(PAGE) else {
            break;
        };
        page = next;
    }
    false
}

/// The entry thunk's RUNTIME_FUNCTION (begin, end, unwind RVAs relative to
/// this image), with its UNWIND_INFO completed. None if the prologue is not
/// the one the unwind data describes, or an RVA does not fit.
fn entry_unwind_function() -> Option<[u32; 3]> {
    let thunk = pingu_artifact_entry_thunk as *const () as usize;
    if crate::artifact::resolver::read::<4>(thunk)? != [0x48, 0x83, 0xec, 0x28] {
        return None;
    }
    let mut info: libc::Dl_info = unsafe { core::mem::zeroed() };
    if unsafe { libc::dladdr(thunk as *const c_void, &mut info) } == 0 {
        return None;
    }
    let base = info.dli_fbase as usize;
    let relative = |at: usize| at.checked_sub(base).and_then(|v| u32::try_from(v).ok());
    let words = unsafe { &mut *ENTRY_UNWIND.0.get() };
    words[2] = relative(entry_exception_handler as *const () as usize)?;
    Some([
        relative(thunk)?,
        relative(pingu_artifact_entry_thunk_end as *const () as usize)?,
        relative(words.as_ptr() as usize)?,
    ])
}

unsafe extern "win64" fn entry_exception_handler(
    _record: *mut c_void,
    _frame: usize,
    _context: *mut c_void,
    _dispatch: *mut c_void,
) -> i32 {
    fatal(b"pingu_protocol: an exception escaped Artifact's entry point\n");
}

fn snapshot_head(head: usize, out: &mut [usize; MAX_LIST_NODES]) -> Option<usize> {
    if !valid_node(head) {
        return None;
    }
    let first = peek(head)?;
    let last = peek(head + 8)?;
    if !valid_node(first) || !valid_node(last) {
        return None;
    }
    if first == head && last == head {
        return Some(0);
    }
    if first == head || last == head {
        return None;
    }
    let mut prev = head;
    let mut cur = first;
    let mut len = 0usize;
    for _ in 0..MAX_LIST_NODES {
        if !valid_node(cur) || cur == head {
            return None;
        }
        if peek(cur + 8)? != prev {
            return None;
        }
        out[len] = cur;
        len += 1;
        let next = peek(cur)?;
        if next == head {
            return (cur == last).then_some(len);
        }
        prev = cur;
        cur = next;
    }
    None
}

/// Wine reads `EntryPoint` once before TLS callbacks and the call, so the
/// real value is restored before Artifact's DllMain runs, and Wine's
/// canonical loader lists are snapshotted for interior-node verification.
unsafe extern "win64" fn before_entry() {
    let _errno = Errno::save();
    let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
    SNAPSHOT_VALID.store(false, Ordering::Release);
    let real = REAL_ENTRY.load(Ordering::Acquire);
    if !self_write(
        ARTIFACT_ENTRY.load(Ordering::Acquire) + ENTRY_ENTRY_POINT,
        &real.to_le_bytes(),
    ) {
        fatal(b"pingu_protocol: Artifact entry point could not be restored\n");
    }
    let canonical = CANONICAL_LDR.load(Ordering::Acquire);
    if !plausible_ldr(canonical) {
        fatal(b"pingu_protocol: Wine loader data is not readable before Artifact entry\n");
    }
    // SAFETY: runs once on the loader-lock thread before Artifact's DllMain and `after_entry`.
    let data = unsafe { &mut *CANONICAL_SNAPSHOT.0.get() };
    for (idx, head) in HEADS.iter().enumerate() {
        let Some(len) = snapshot_head(canonical + head, &mut data.nodes[idx]) else {
            fatal(b"pingu_protocol: Wine loader list could not be snapshotted before Artifact entry\n");
        };
        data.lens[idx] = len;
    }
    SNAPSHOT_VALID.store(true, Ordering::Release);
}

/// Runs when Artifact's DllMain returns, still under Wine's loader lock;
/// Artifact's `PEB->Ldr` swap happens inside DllMain, so adoption here
/// precedes every later lock-respecting walk.
unsafe extern "win64" fn after_entry() {
    let _errno = Errno::save();
    let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
    let canonical = CANONICAL_LDR.load(Ordering::Acquire);
    let public = current_ldr();
    if !SNAPSHOT_VALID.load(Ordering::Acquire) {
        fatal(b"pingu_protocol: Wine loader snapshot is missing after Artifact entry\n");
    }
    // SAFETY: `SNAPSHOT_VALID` was published by `before_entry` on this thread and never mutated afterward.
    let data = unsafe { &*CANONICAL_SNAPSHOT.0.get() };
    let expected = [
        &data.nodes[0][..data.lens[0]],
        &data.nodes[1][..data.lens[1]],
        &data.nodes[2][..data.lens[2]],
    ];
    if !plausible_ldr(public) {
        fatal(b"pingu_protocol: Artifact loader data is not plausible after entry\n");
    }
    if public == canonical {
        // Some Artifact builds (seen in Anno 117) keep Wine's PEB_LDR_DATA.
        note(c"Artifact kept Wine loader data");
        if !unsafe { relink_in_place(public, &expected) } {
            fatal(b"pingu_protocol: Artifact in-place loader links could not be repaired\n");
        }
    } else if !unsafe { adopt_heads(canonical, public, &expected) } {
        fatal(b"pingu_protocol: Artifact loader data could not be adopted\n");
    }
    tag_public_only_entries(public, &expected);
    // NtQueryInformationProcess returns Wine's original PEB even when
    // Artifact replaced TEB.Peb. Toolhelp walks must use the adopted head
    // too, rather than loop through a list that never reaches the old head.
    if !publish_process_ldr(CANONICAL_PEB.load(Ordering::Acquire), canonical, public) {
        fatal(b"pingu_protocol: original process PEB loader data could not be updated\n");
    }
    note(c"Artifact loader data adopted");
}

fn tag_head_entries(
    head: usize,
    link: usize,
    expected: &[usize],
    owned: impl Fn(usize, usize) -> bool,
    tagged: &mut usize,
) -> Result<(), &'static [u8]> {
    if !valid_node(head) {
        return Err(b"pingu_protocol: Artifact loader head is invalid\n");
    }
    let mut prev = head;
    let mut cur =
        peek(head).ok_or(&b"pingu_protocol: Artifact loader head is not readable\n"[..])?;
    let mut matched = 0usize;
    for _ in 0..MAX_LIST_NODES {
        if cur == head {
            if peek(head + 8) != Some(prev) {
                return Err(b"pingu_protocol: Artifact loader head back-link is broken\n");
            }
            if matched != expected.len() {
                return Err(b"pingu_protocol: Wine loader entry missing during tagging\n");
            }
            return Ok(());
        }
        if !valid_node(cur) || cur < link {
            return Err(b"pingu_protocol: Artifact loader node is invalid\n");
        }
        if peek(cur + 8) != Some(prev) {
            return Err(b"pingu_protocol: Artifact loader list back-link is broken\n");
        }
        if expected.get(matched) == Some(&cur) {
            matched += 1;
        }
        let entry = cur - link;
        let (Some(dll_base), Some(count), Some(flags)) = (
            peek(entry + ENTRY_DLL_BASE),
            peek_bytes::<2>(entry + ENTRY_LOAD_COUNT).map(u16::from_le_bytes),
            peek_bytes::<4>(entry + ENTRY_FLAGS).map(u32::from_le_bytes),
        ) else {
            return Err(b"pingu_protocol: Artifact loader entry is not readable\n");
        };
        if !owned(entry, dll_base) {
            if count == 0 {
                // MODULE_FlushModrefs would free it as a WINE_MODREF.
                return Err(b"pingu_protocol: Artifact loader entry with zero load count\n");
            }
            if flags & LDR_DONT_CALL_DLLMAIN == 0 {
                let tagged_flags = flags | LDR_DONT_CALL_DLLMAIN;
                if !self_write(entry + ENTRY_FLAGS, &tagged_flags.to_le_bytes()) {
                    return Err(b"pingu_protocol: Artifact loader entry is not writable\n");
                }
                *tagged += 1;
            }
        }
        let Some(next) = peek(cur) else {
            return Err(b"pingu_protocol: Artifact loader list is not readable\n");
        };
        prev = cur;
        cur = next;
    }
    Err(b"pingu_protocol: Artifact loader list exceeded node limit\n")
}

/// Wine's address index is authoritative: an entry is Wine-owned only when
/// `LdrFindEntryForAddress(entry.DllBase)` returns that exact entry. Every
/// other entry is Artifact metadata and gets `LDR_DONT_CALL_DLLMAIN`, which
/// stock `MODULE_InitDLL` checks before TLS callbacks and the entry point.
fn tag_public_only_entries(public: usize, expected: &[&[usize]; 3]) {
    let ntdll = NTDLL_BASE.load(Ordering::Acquire);
    let Some(find) =
        crate::artifact::resolver::export(ntdll, b"ntdll.dll\0", b"LdrFindEntryForAddress\0")
    else {
        fatal(b"pingu_protocol: LdrFindEntryForAddress unavailable\n");
    };
    type Find = unsafe extern "win64" fn(usize, *mut usize) -> i32;
    let find: Find = unsafe { core::mem::transmute(find) };
    let owned = |entry: usize, dll_base: usize| {
        let mut owner = 0usize;
        let status = unsafe { find(dll_base, &mut owner) };
        status == 0 && owner == entry
    };
    let mut tagged = 0usize;
    for ((head, link), expected_nodes) in
        HEADS.iter().zip([0usize, 0x10, 0x20]).zip(expected.iter())
    {
        if let Err(message) =
            tag_head_entries(public + head, link, expected_nodes, owned, &mut tagged)
        {
            fatal(message);
        }
    }
    note_count(c"Artifact public-only loader entries tagged: ", tagged);
    // Artifact places private copies of system DLLs (kernelbase, kernel32,
    // user32, ...) ahead of Wine's modules on purpose, and Wine's full-name
    // and apiset lookups then bind later imports to them. Moving them behind
    // Wine's modules breaks Artifact initialization, so the order is left as is.
    // Known limit: a full-path GetModuleHandle/LoadLibrary of one of those
    // DLLs can return Artifact's copy, which Wine may refuse to unload.
}

#[cfg(feature = "debug")]
unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_dec(prefix: *const core::ffi::c_char, value: u64);
}

pub(crate) fn fatal(message: &[u8]) -> ! {
    {
        let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
        unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
    }
    let ntdll = NTDLL_BASE.load(Ordering::Acquire);
    if let Some(terminate) =
        crate::artifact::resolver::export(ntdll, b"ntdll.dll\0", b"NtTerminateProcess\0")
    {
        let terminate: unsafe extern "win64" fn(isize, u32) -> i32 =
            unsafe { core::mem::transmute(terminate) };
        unsafe { terminate(-1, STATUS_DLL_INIT_FAILED) };
    }
    unsafe { libc::_exit(70) }
}

/// Gate informational loader diagnostics behind `PINGU_DEBUG` (keeping the
/// syscall-dispatch selector cleared across the log write in PE context).
fn note(message: &'static core::ffi::CStr) {
    #[cfg(feature = "debug")]
    {
        let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
        unsafe { debug_log(message.as_ptr()) };
    }
    #[cfg(not(feature = "debug"))]
    let _ = message;
}

fn note_count(prefix: &'static core::ffi::CStr, value: usize) {
    #[cfg(feature = "debug")]
    {
        let _dispatch = unsafe { crate::artifact::wine_dispatch_guard() };
        unsafe { debug_log_dec(prefix.as_ptr(), value as u64) };
    }
    #[cfg(not(feature = "debug"))]
    let _ = (prefix, value);
}

fn current_peb() -> usize {
    let mut peb: usize;
    unsafe { core::arch::asm!("mov {p}, qword ptr gs:[0x60]", p = out(reg) peb) };
    peb
}

fn current_ldr() -> usize {
    let peb = current_peb();
    if peb == 0 {
        return 0;
    }
    peek(peb + 0x18).unwrap_or(0)
}

fn publish_process_ldr(peb: usize, canonical: usize, public: usize) -> bool {
    let Some(slot) = peb.checked_add(0x18) else {
        return false;
    };
    match peek(slot) {
        Some(current) if current == public => true,
        Some(current) if current == canonical => self_write(slot, &public.to_le_bytes()),
        _ => false,
    }
}

fn plausible_ldr(ldr: usize) -> bool {
    valid_node(ldr)
        && peek_bytes::<5>(ldr)
            .is_some_and(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) == 0x58 && b[4] == 1)
}

/// Load-order entry with this base name (ASCII, case-insensitive).
/// Validates reciprocal `Blink` links across the entire ring and full name
/// readability. Returns `Err(())` on corrupt or unreadable loader data, and
/// `Ok(None)` only after a complete clean walk.
fn find_entry(ldr: usize, name: &[u8]) -> Result<Option<usize>, ()> {
    let head = ldr + HEADS[0];
    if !valid_node(head) {
        return Err(());
    }
    let mut prev = head;
    let mut cur = peek(head).ok_or(())?;
    let mut matched = None;
    for _ in 0..MAX_LIST_NODES {
        if cur == head {
            if peek(head + 8) != Some(prev) {
                return Err(());
            }
            return Ok(matched);
        }
        if !valid_node(cur) || peek(cur + 8) != Some(prev) {
            return Err(());
        }
        match unicode_eq_ascii(cur + ENTRY_BASE_NAME, name) {
            Some(true) if matched.is_none() => matched = Some(cur),
            Some(_) => {}
            None => return Err(()),
        }
        prev = cur;
        cur = peek(cur).ok_or(())?;
    }
    Err(())
}

fn range_readable(address: usize, length: usize) -> bool {
    let mut buf = [0u8; 64];
    let mut offset = 0usize;
    while offset < length {
        let chunk = (length - offset).min(buf.len());
        let Some(at) = address.checked_add(offset) else {
            return false;
        };
        if !crate::artifact::resolver::read_slice(at, &mut buf[..chunk]) {
            return false;
        }
        offset += chunk;
    }
    true
}

/// Compare a UNICODE_STRING with an ASCII name of at most 32 characters,
/// ignoring ASCII case. Returns `None` on empty, odd, truncated, or unreadable
/// strings.
fn unicode_eq_ascii(us: usize, ascii: &[u8]) -> Option<bool> {
    if ascii.len() > 32 {
        return None;
    }
    let length = peek_bytes::<2>(us).map(u16::from_le_bytes)? as usize;
    let maximum = peek_bytes::<2>(us + 2).map(u16::from_le_bytes)? as usize;
    if length == 0 || length & 1 != 0 || length > maximum {
        return None;
    }
    // BaseDllName points inside FullDllName: only WCHAR (2-byte) aligned.
    let buffer = peek(us + 8).filter(|b| *b >= MIN_USER_ADDRESS && b & 1 == 0)?;
    if length != ascii.len() * 2 {
        return range_readable(buffer, length).then_some(false);
    }
    let mut text = [0u8; 64];
    let needed = ascii.len() * 2;
    if !crate::artifact::resolver::read_slice(buffer, &mut text[..needed]) {
        return None;
    }
    Some(ascii.iter().enumerate().all(|(index, byte)| {
        let value = u16::from_le_bytes([text[index * 2], text[index * 2 + 1]]);
        value < 0x80 && (value as u8).eq_ignore_ascii_case(byte)
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Repair {
    Noop,
    Empty,
    Insert { first: usize, tail: usize },
    FixFirst { first: usize },
}

fn valid_node(address: usize) -> bool {
    address >= MIN_USER_ADDRESS && address & 7 == 0
}

#[cfg(test)]
unsafe fn read_word(address: usize) -> usize {
    unsafe { core::ptr::read_volatile(address as *const usize) }
}

/// Read one word without faulting: an unmapped pointer reads as `None`.
fn peek(address: usize) -> Option<usize> {
    peek_bytes::<8>(address).map(usize::from_le_bytes)
}

fn peek_bytes<const N: usize>(address: usize) -> Option<[u8; N]> {
    crate::artifact::resolver::read::<N>(address)
}

/// Plan one list repair without writing. `old` is Wine's head, `copy` is
/// Artifact's shallow public head, and `wine_nodes` is the pre-Artifact
/// canonical sequence. Any inconsistency, dropped Wine entry, or unmapped
/// node returns `None`; the caller commits nothing unless all three pass.
fn plan_head(old: usize, copy: usize, wine_nodes: &[usize]) -> Option<Repair> {
    if !valid_node(old) || !valid_node(copy) {
        return None;
    }
    let (of, ob, cf, cb) = (peek(old)?, peek(old + 8)?, peek(copy)?, peek(copy + 8)?);
    if !valid_node(of) || !valid_node(ob) || !valid_node(cf) || !valid_node(cb) {
        return None;
    }
    let canonical_empty = of == old && ob == old;
    if canonical_empty != wine_nodes.is_empty() {
        return None;
    }
    if cf == copy && cb == copy {
        // An empty public list may only stand for an empty Wine list.
        return canonical_empty.then_some(Repair::Noop);
    }
    if cf == old && cb == old {
        // Byte-copied empty head: initialize the copy, never the old sentinel.
        return canonical_empty.then_some(Repair::Empty);
    }
    if canonical_empty || cf == copy || cb == copy || of != cf {
        // Head insertion, a partial head, or an unrelated replacement.
        return None;
    }
    // Walk first..tail, requiring reciprocal links throughout, Wine's current
    // tail `ob`, and every snapshotted canonical Wine entry in order.
    let mut cur = cf;
    let mut found = false;
    let mut saw_wine_tail = false;
    let mut matched = 0usize;
    for _ in 0..MAX_LIST_NODES {
        if cur == old || cur == copy {
            return None;
        }
        saw_wine_tail |= cur == ob;
        if wine_nodes.get(matched) == Some(&cur) {
            matched += 1;
        }
        if cur == cb {
            found = true;
            break;
        }
        let next = peek(cur)?;
        if !valid_node(next) || peek(next + 8)? != cur {
            return None;
        }
        cur = next;
    }
    if !found || matched != wine_nodes.len() {
        return None;
    }
    let first_blink = peek(cf + 8)?;
    let tail_next = peek(cb)?;
    if tail_next == copy {
        if !saw_wine_tail {
            return None;
        }
        if first_blink == copy {
            return Some(Repair::Noop);
        }
        // The public tail was extended after the copy; only the first
        // back-link still points at Wine's head.
        return (first_blink == old).then_some(Repair::FixFirst { first: cf });
    }
    if tail_next == old && first_blink == old && ob == cb {
        return Some(Repair::Insert {
            first: cf,
            tail: cb,
        });
    }
    None
}

/// Artifact builds that keep Wine's PEB_LDR_DATA splice their private
/// entries into Wine's lists through Flink only: an inserted node's Blink
/// points at its successor, and the successor's Blink still skips it. Keep
/// Artifact's forward order and make every Blink reciprocal. All three lists
/// are validated, and every target test-written, before the first real write.
unsafe fn relink_in_place(ldr: usize, expected: &[&[usize]; 3]) -> bool {
    for (head, wine_nodes) in HEADS.iter().zip(expected.iter()) {
        if !relink_pass(ldr + head, wine_nodes, false) {
            note_count(c"Artifact in-place loader head rejected at offset ", *head);
            return false;
        }
    }
    HEADS
        .iter()
        .zip(expected.iter())
        .all(|(head, wine_nodes)| relink_pass(ldr + head, wine_nodes, true))
}

/// Walk one list by Flink. It must return to `head` and contain every
/// snapshotted Wine node in order. Without `commit`, each Blink that needs a
/// change is only test-written with its current value.
fn relink_pass(head: usize, wine_nodes: &[usize], commit: bool) -> bool {
    if !valid_node(head) {
        return false;
    }
    let mut prev = head;
    let Some(mut cur) = peek(head) else {
        return false;
    };
    let mut matched = 0usize;
    for _ in 0..MAX_LIST_NODES {
        if cur == head {
            return matched == wine_nodes.len() && fix_blink(head, prev, commit);
        }
        if !valid_node(cur) {
            return false;
        }
        if wine_nodes.get(matched) == Some(&cur) {
            matched += 1;
        }
        if !fix_blink(cur, prev, commit) {
            return false;
        }
        prev = cur;
        let Some(next) = peek(cur) else {
            return false;
        };
        cur = next;
    }
    false
}

fn fix_blink(node: usize, prev: usize, commit: bool) -> bool {
    let Some(current) = peek(node + 8) else {
        return false;
    };
    if current == prev {
        return true;
    }
    let value = if commit { prev } else { current };
    self_write(node + 8, &value.to_le_bytes())
}

/// The (address, value) writes one repair needs.
fn repair_writes(copy: usize, repair: Repair) -> ([(usize, usize); 2], usize) {
    match repair {
        Repair::Noop => ([(0, 0); 2], 0),
        Repair::Empty => ([(copy, copy), (copy + 8, copy)], 2),
        Repair::Insert { first, tail } => ([(first + 8, copy), (tail, copy)], 2),
        Repair::FixFirst { first } => ([(first + 8, copy), (0, 0)], 1),
    }
}

/// Validate all three heads, then test-write every target with its current
/// value, before the first real write. Rejection or an unwritable target
/// leaves everything unchanged.
unsafe fn adopt_heads(canonical: usize, public: usize, expected: &[&[usize]; 3]) -> bool {
    let mut writes = [(0usize, 0usize); 6];
    let mut count = 0;
    for (head, wine_nodes) in HEADS.iter().zip(expected.iter()) {
        let Some(repair) = plan_head(canonical + head, public + head, wine_nodes) else {
            note_count(c"Artifact loader head rejected at offset ", *head);
            return false;
        };
        let (pairs, used) = repair_writes(public + head, repair);
        writes[count..count + used].copy_from_slice(&pairs[..used]);
        count += used;
    }
    let writes = &writes[..count];
    for &(address, _) in writes {
        let Some(current) = peek(address) else {
            return false;
        };
        if !self_write(address, &current.to_le_bytes()) {
            return false;
        }
    }
    writes
        .iter()
        .all(|&(address, value)| self_write(address, &value.to_le_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem {
        words: Box<[usize; 512]>,
    }

    fn apply(copy: usize, repair: Repair) {
        let (pairs, used) = repair_writes(copy, repair);
        for &(address, value) in &pairs[..used] {
            assert!(self_write(address, &value.to_le_bytes()));
        }
    }

    impl Mem {
        fn new() -> Self {
            Self {
                words: Box::new([0; 512]),
            }
        }
        fn addr(&self, word: usize) -> usize {
            self.words.as_ptr() as usize + word * 8
        }
        fn set(&mut self, word: usize, flink: usize, blink: usize) {
            self.words[word] = flink;
            self.words[word + 1] = blink;
        }
        fn set_addr(&mut self, address: usize, flink: usize, blink: usize) {
            let word = (address - self.words.as_ptr() as usize) / 8;
            self.set(word, flink, blink);
        }
    }

    #[test]
    fn original_process_peb_module_walk_terminates_after_copy_adoption() {
        let mut m = Mem::new();
        let (peb, copied_peb, canonical, public) = (m.addr(0), m.addr(32), m.addr(64), m.addr(96));
        m.words[3] = canonical;
        m.words[35] = public;
        let (a, b) = (m.addr(128), m.addr(160));
        let (old_head, copy_head) = (canonical + 0x10, public + 0x10);
        m.set_addr(old_head, a, b);
        m.set_addr(a, b, old_head);
        m.set_addr(b, old_head, a);
        m.set_addr(copy_head, a, b);
        for offset in [0x20, 0x30] {
            m.set_addr(canonical + offset, canonical + offset, canonical + offset);
            m.set_addr(public + offset, canonical + offset, canonical + offset);
        }
        assert!(unsafe { adopt_heads(canonical, public, &[&[a, b], &[], &[]]) });
        let mut nodes = [0; MAX_LIST_NODES];
        assert_eq!(
            snapshot_head(peek(copied_peb + 0x18).unwrap() + 0x10, &mut nodes),
            Some(2)
        );
        // The original sentinel is stranded after its neighbours adopt the copy.
        assert_eq!(
            snapshot_head(peek(peb + 0x18).unwrap() + 0x10, &mut nodes),
            None
        );
        assert!(publish_process_ldr(peb, canonical, public));
        assert_eq!(
            snapshot_head(peek(peb + 0x18).unwrap() + 0x10, &mut nodes),
            Some(2)
        );
        assert_eq!(peek(copied_peb + 0x18), Some(public));
    }

    #[test]
    fn process_loader_publication_preserves_an_unexpected_replacement() {
        let mut m = Mem::new();
        let (peb, canonical, public, other) = (m.addr(0), m.addr(32), m.addr(64), m.addr(96));
        m.words[3] = other;
        assert!(!publish_process_ldr(peb, canonical, public));
        assert_eq!(m.words[3], other);
    }

    #[test]
    fn process_loader_publication_is_idempotent_and_rejects_unreadable_pebs() {
        let mut m = Mem::new();
        let (peb, canonical, public) = (m.addr(0), m.addr(32), m.addr(64));
        m.words[3] = public;
        assert!(publish_process_ldr(peb, canonical, public));
        assert_eq!(m.words[3], public);
        assert!(!publish_process_ldr(0, canonical, public));
        assert!(!publish_process_ldr(usize::MAX - 8, canonical, public));
    }

    #[test]
    fn empty_copy_initializes_copy_only() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        m.set(0, old, old);
        m.set(2, old, old);
        assert_eq!(plan_head(old, copy, &[]), Some(Repair::Empty));
        apply(copy, Repair::Empty);
        assert_eq!(m.words[0], old);
        assert_eq!(m.words[1], old);
        assert_eq!(m.words[2], copy);
        assert_eq!(m.words[3], copy);
    }

    #[test]
    fn self_linked_copy_of_nonempty_list_is_rejected() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let a = m.addr(4);
        m.set(0, a, a);
        m.set(4, old, old);
        m.set(2, copy, copy);
        assert_eq!(plan_head(old, copy, &[a]), None);
    }

    #[test]
    fn shallow_copy_inserts_head_once() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let a = m.addr(4);
        let b = m.addr(6);
        m.set(0, a, b);
        m.set(4, b, old);
        m.set(6, old, a);
        m.set(2, a, b);
        assert_eq!(
            plan_head(old, copy, &[a, b]),
            Some(Repair::Insert { first: a, tail: b })
        );
        apply(copy, Repair::Insert { first: a, tail: b });
        assert_eq!(m.words[4 + 1], copy);
        assert_eq!(m.words[6], copy);
    }

    #[test]
    fn broken_interior_backlink_is_rejected() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let a = m.addr(4);
        let b = m.addr(6);
        let c = m.addr(8);
        m.set(0, a, c);
        m.set(4, b, old);
        m.set(6, c, old); // b.Blink should be a
        m.set(8, old, b);
        m.set(2, a, c);
        assert_eq!(plan_head(old, copy, &[a, b, c]), None);
    }

    #[test]
    fn extended_tail_fixes_first_backlink() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let a = m.addr(4);
        let b = m.addr(6);
        let c = m.addr(8);
        m.set(0, a, b);
        m.set(4, b, old);
        m.set(6, c, a);
        m.set(8, copy, b);
        m.set(2, a, c);
        assert_eq!(
            plan_head(old, copy, &[a, b]),
            Some(Repair::FixFirst { first: a })
        );
        apply(copy, Repair::FixFirst { first: a });
        assert_eq!(m.words[4 + 1], copy);
    }

    #[test]
    fn old_sentinel_is_rejected_as_module_node() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let a = m.addr(4);
        m.set(0, a, old);
        m.set(4, old, a);
        m.set(2, a, old);
        assert_eq!(plan_head(old, copy, &[a]), None);
    }

    #[test]
    fn head_insertion_is_rejected_without_writes() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let a = m.addr(4);
        let b = m.addr(6);
        let inserted = m.addr(8);
        m.set(0, a, b);
        m.set(4, b, inserted);
        m.set(6, old, a);
        m.set(8, a, copy);
        m.set(2, inserted, b);
        assert_eq!(plan_head(old, copy, &[a, b]), None);
        assert_eq!(m.words[4 + 1], inserted);
        assert_eq!(m.words[6], old);
    }

    #[test]
    fn extended_tail_that_drops_wine_tail_is_rejected() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let (a, b, c) = (m.addr(4), m.addr(6), m.addr(8));
        // Wine: old -> a -> b -> old. Public: copy -> a -> c -> copy; b lost.
        m.set(0, a, b);
        m.set(4, c, old);
        m.set(6, old, a);
        m.set(8, copy, a);
        m.set(2, a, c);
        assert_eq!(plan_head(old, copy, &[a, b]), None);
    }

    #[test]
    fn dropped_interior_wine_entry_is_rejected() {
        let mut m = Mem::new();
        let old = m.addr(0);
        let copy = m.addr(2);
        let (a, b, c) = (m.addr(4), m.addr(6), m.addr(8));
        // Snapshot canonical: old -> a -> b -> c -> old.
        m.set(0, a, c);
        m.set(4, b, old);
        m.set(6, c, a);
        m.set(8, old, b);
        let mut snap = [0usize; MAX_LIST_NODES];
        let snap_len = snapshot_head(old, &mut snap).unwrap();
        assert_eq!(&snap[..snap_len], &[a, b, c]);

        // Public drops interior node `b`: copy -> a -> c -> copy.
        m.set(4, c, old);
        m.set(8, copy, a);
        m.set(2, a, c);
        assert_eq!(plan_head(old, copy, &snap[..snap_len]), None);
    }

    #[test]
    fn unicode_eq_ascii_succeeds_at_page_boundary_before_unreadable_page() {
        let pages = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                0x2000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pages, libc::MAP_FAILED);
        let first_page = pages as usize;
        let second_page = first_page + 0x1000;
        let name = b"artifact.dll";
        let needed = name.len() * 2;
        let buffer = second_page - needed;
        let utf16: Vec<u16> = name.iter().map(|&b| u16::from(b)).collect();
        for (i, &ch) in utf16.iter().enumerate() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    ch.to_le_bytes().as_ptr(),
                    (buffer + i * 2) as *mut u8,
                    2,
                );
            }
        }
        assert_eq!(
            unsafe { libc::mprotect(second_page as *mut c_void, 0x1000, libc::PROT_NONE) },
            0
        );

        let mut us = [0usize; 2];
        us[0] = needed | (needed << 16);
        us[1] = buffer;
        let us_addr = us.as_ptr() as usize;
        assert_eq!(unicode_eq_ascii(us_addr, name), Some(true));
        assert_eq!(unicode_eq_ascii(us_addr, b"other.dll"), Some(false));

        unsafe { libc::munmap(pages, 0x2000) };
    }

    #[test]
    fn tag_head_entries_rejects_unreadable_or_corrupt_lists() {
        // 1. Unreadable head.
        let bad_page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                0x1000,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(bad_page, libc::MAP_FAILED);
        let mut tagged = 0usize;
        assert!(tag_head_entries(bad_page as usize, 0, &[], |_, _| true, &mut tagged).is_err());
        unsafe { libc::munmap(bad_page, 0x1000) };

        // Backing memory for head + two LDR_DATA_TABLE_ENTRY fixtures.
        let mut m = Mem::new();
        let head = m.addr(0);
        let a = m.addr(16);
        let b = m.addr(64);
        let init_entry = |m: &mut Mem, entry: usize, dll_base: usize, count: u16, flags: u32| {
            let base_word = (entry - m.words.as_ptr() as usize) / 8;
            m.words[base_word + ENTRY_DLL_BASE / 8] = dll_base;
            let flags_count = (u64::from(flags)) | (u64::from(count) << 32);
            m.words[base_word + ENTRY_FLAGS / 8] = flags_count as usize;
        };
        init_entry(&mut m, a, 0x1000_0000, 1, 0);
        init_entry(&mut m, b, 0x2000_0000, 1, 0);

        // 2. Invalid interior node.
        m.set_addr(head, a + 4, a + 4);
        assert!(tag_head_entries(head, 0, &[a], |_, _| true, &mut tagged).is_err());

        // 3. Broken Blink.
        m.set_addr(head, a, b);
        m.set_addr(a, b, head);
        m.set_addr(b, head, head); // should be a
        assert!(tag_head_entries(head, 0, &[a, b], |_, _| true, &mut tagged).is_err());

        // 4. Missing expected Wine node.
        m.set_addr(head, a, a);
        m.set_addr(a, head, head);
        assert!(tag_head_entries(head, 0, &[a, b], |_, _| true, &mut tagged).is_err());

        // 5. Zero load count on unowned entry.
        init_entry(&mut m, b, 0x2000_0000, 0, 0);
        m.set_addr(head, a, b);
        m.set_addr(a, b, head);
        m.set_addr(b, head, a);
        assert!(tag_head_entries(head, 0, &[a], |entry, _| entry == a, &mut tagged).is_err());

        // Valid case tags the unowned entry once count > 0.
        init_entry(&mut m, b, 0x2000_0000, 1, 0);
        tagged = 0;
        assert!(tag_head_entries(head, 0, &[a], |entry, _| entry == a, &mut tagged).is_ok());
        assert_eq!(tagged, 1);
    }

    #[test]
    fn rejection_of_one_head_prevents_all_writes() {
        let mut m = Mem::new();
        let canonical = m.addr(0);
        let public = m.addr(64);
        let (old_load, old_memory, old_init) =
            (canonical + 0x10, canonical + 0x20, canonical + 0x30);
        let (copy_load, copy_memory, copy_init) = (public + 0x10, public + 0x20, public + 0x30);
        let (a, b, c, d, e, f) = (
            m.addr(16),
            m.addr(18),
            m.addr(20),
            m.addr(22),
            m.addr(24),
            m.addr(26),
        );
        m.set_addr(old_load, a, b);
        m.set_addr(a, b, old_load);
        m.set_addr(b, old_load, a);
        m.set_addr(copy_load, a, b);
        // Memory-order copy does not start at the canonical first node.
        m.set_addr(old_memory, old_memory, old_memory);
        m.set_addr(copy_memory, c, d);
        m.set_addr(old_init, e, f);
        m.set_addr(e, f, old_init);
        m.set_addr(f, old_init, e);
        m.set_addr(copy_init, e, f);
        assert!(!unsafe { adopt_heads(canonical, public, &[&[a, b], &[], &[e, f]]) });
        assert_eq!(unsafe { read_word(a + 8) }, old_load);
        assert_eq!(unsafe { read_word(b) }, old_load);
        assert_eq!(unsafe { read_word(e + 8) }, old_init);
        assert_eq!(unsafe { read_word(f) }, old_init);
    }

    #[test]
    fn unchanged_ldr_pointer_validates_snapshot_and_rejects_corrupted_links() {
        let mut m = Mem::new();
        let canonical = m.addr(0);
        let (old_load, old_memory, old_init) =
            (canonical + 0x10, canonical + 0x20, canonical + 0x30);
        let (a, b, c) = (m.addr(16), m.addr(18), m.addr(20));
        m.set_addr(old_load, a, c);
        m.set_addr(a, b, old_load);
        m.set_addr(b, c, a);
        m.set_addr(c, old_load, b);
        m.set_addr(old_memory, old_memory, old_memory);
        m.set_addr(old_init, old_init, old_init);
        assert!(unsafe { adopt_heads(canonical, canonical, &[&[a, b, c], &[], &[]]) });

        // Dropped interior node while PEB->Ldr == canonical.
        m.set_addr(a, c, old_load);
        m.set_addr(c, old_load, a);
        assert!(!unsafe { adopt_heads(canonical, canonical, &[&[a, b, c], &[], &[]]) });

        // First node's Blink left pointing at a temporary copy head.
        let temp_copy = m.addr(64);
        m.set_addr(a, b, temp_copy);
        m.set_addr(b, c, a);
        m.set_addr(c, old_load, b);
        assert!(!unsafe { adopt_heads(canonical, canonical, &[&[a, b, c], &[], &[]]) });
    }

    #[test]
    fn find_entry_rejects_broken_head_or_interior_backlinks() {
        let mut m = Mem::new();
        let ldr = m.addr(0);
        let head = ldr + HEADS[0];
        let bogus = m.addr(32);
        // Empty-looking Flink with mismatched head.Blink.
        m.set_addr(head, head, bogus);
        assert_eq!(find_entry(ldr, b"artifact.dll"), Err(()));

        // Interior node with broken Blink.
        let a = m.addr(16);
        let b = m.addr(64);
        let name = b"kernel32.dll";
        let utf16: Vec<u16> = name.iter().map(|&ch| u16::from(ch)).collect();
        let name_bytes: Vec<u8> = utf16.iter().flat_map(|ch| ch.to_le_bytes()).collect();
        let str_buf = m.addr(128);
        unsafe {
            core::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                str_buf as *mut u8,
                name_bytes.len(),
            );
        }
        let init_name = |m: &mut Mem, entry: usize| {
            let word = (entry - m.words.as_ptr() as usize) / 8;
            let len = name_bytes.len();
            m.words[word + ENTRY_BASE_NAME / 8] = len | (len << 16);
            m.words[word + (ENTRY_BASE_NAME + 8) / 8] = str_buf;
        };
        init_name(&mut m, a);
        init_name(&mut m, b);
        m.set_addr(head, a, b);
        m.set_addr(a, b, head);
        m.set_addr(b, head, head); // should be a
        assert_eq!(find_entry(ldr, b"artifact.dll"), Err(()));

        // Clean ring completes with Ok(None).
        m.set_addr(b, head, a);
        assert_eq!(find_entry(ldr, b"artifact.dll"), Ok(None));
    }

    #[test]
    fn unicode_eq_ascii_rejects_different_length_name_with_unreadable_tail() {
        let pages = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                0x2000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pages, libc::MAP_FAILED);
        let second_page = (pages as usize) + 0x1000;
        let total = 36usize;
        let buffer = second_page - 24;
        unsafe {
            core::ptr::write_bytes(buffer as *mut u8, b'a', 24);
        }
        assert_eq!(
            unsafe { libc::mprotect(second_page as *mut c_void, 0x1000, libc::PROT_NONE) },
            0
        );
        let mut us = [0usize; 2];
        us[0] = total | (total << 16);
        us[1] = buffer;
        assert_eq!(
            unicode_eq_ascii(us.as_ptr() as usize, b"artifact.dll"),
            None
        );
        unsafe { libc::munmap(pages, 0x2000) };
    }

    #[test]
    fn in_place_flink_only_splice_gets_reciprocal_blinks() {
        let mut m = Mem::new();
        let (head, exe, a1, ntdll, a2, k32) = (
            m.addr(0),
            m.addr(2),
            m.addr(4),
            m.addr(6),
            m.addr(8),
            m.addr(10),
        );
        // Layout seen with Anno 117's Artifact: inserted nodes point Blink
        // forward, and Wine's nodes keep Blinks that skip them.
        m.set(0, exe, k32);
        m.set(2, a1, head);
        m.set(4, ntdll, ntdll);
        m.set(6, a2, exe);
        m.set(8, k32, k32);
        m.set(10, head, ntdll);
        let before = m.words.clone();
        let missing = m.addr(12);
        assert!(!relink_pass(head, &[exe, ntdll, missing], false));
        assert!(!relink_pass(head, &[ntdll, exe], false));
        assert!(relink_pass(head, &[exe, ntdll, k32], false));
        assert_eq!(m.words, before);
        assert!(relink_pass(head, &[exe, ntdll, k32], true));
        let order = [head, exe, a1, ntdll, a2, k32];
        for (i, node) in order.iter().enumerate() {
            let next = order[(i + 1) % order.len()];
            let prev = order[(i + order.len() - 1) % order.len()];
            assert_eq!(unsafe { read_word(*node) }, next);
            assert_eq!(unsafe { read_word(node + 8) }, prev);
        }
    }

    #[test]
    fn in_place_relink_rejects_a_list_that_never_returns_to_its_head() {
        let mut m = Mem::new();
        let (head, a, b) = (m.addr(0), m.addr(2), m.addr(4));
        m.set(0, a, b);
        m.set(2, b, head);
        m.set(4, a, a);
        assert!(!relink_pass(head, &[a], false));
    }
}
