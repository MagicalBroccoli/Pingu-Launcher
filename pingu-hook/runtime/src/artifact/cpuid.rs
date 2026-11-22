//! The SIGSEGV handler for CPUID traps (Linux `ARCH_SET_CPUID` faulting):
//! Artifact CPUID handshake & profile replies, Wine-view caching, native
//! pass-through, and host vendor detection.
use core::arch::x86_64::__cpuid_count;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering, fence};

use crate::maps;
use crate::procmem::read_memory;
use libc::{greg_t, siginfo_t, ucontext_t};
use pingu_protocol::cpuid::{ActiveVendor, Registers, Vendor};

const ARCH_SET_CPUID: c_int = 0x1012;
static ACTIVE_VENDOR: ActiveVendor = ActiveVendor::new();
#[cfg(feature = "debug")]
static FORWARDED_GAME_FAULTS_LOGGED: AtomicU64 = AtomicU64::new(0);

const CALLER_CACHE_CAP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum CallerKind {
    Ordinary = 0,
    Artifact = 1,
}

impl CallerKind {
    fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Artifact,
            _ => Self::Ordinary,
        }
    }
}

/// Mapping ranges already classified, so a repeat caller skips the
/// `/proc/self/maps` scan.
struct CallerCache {
    lock: AtomicBool,
    next: AtomicU32,
    sequences: [AtomicU32; CALLER_CACHE_CAP],
    starts: [AtomicU64; CALLER_CACHE_CAP],
    ends: [AtomicU64; CALLER_CACHE_CAP],
    kinds: [AtomicU32; CALLER_CACHE_CAP],
}

impl CallerCache {
    const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            next: AtomicU32::new(0),
            sequences: [const { AtomicU32::new(0) }; CALLER_CACHE_CAP],
            starts: [const { AtomicU64::new(0) }; CALLER_CACHE_CAP],
            ends: [const { AtomicU64::new(0) }; CALLER_CACHE_CAP],
            kinds: [const { AtomicU32::new(CallerKind::Ordinary as u32) }; CALLER_CACHE_CAP],
        }
    }

    fn lookup(&self, address: u64) -> Option<CallerKind> {
        for index in 0..CALLER_CACHE_CAP {
            let before = self.sequences[index].load(Ordering::Acquire);
            if before & 1 != 0 {
                continue;
            }
            let start = self.starts[index].load(Ordering::Relaxed);
            let end = self.ends[index].load(Ordering::Relaxed);
            let kind = self.kinds[index].load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if self.sequences[index].load(Ordering::Relaxed) == before
                && (start..end).contains(&address)
            {
                return Some(CallerKind::from_raw(kind));
            }
        }
        None
    }

    fn insert(&self, start: u64, end: u64, kind: CallerKind) {
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let index = self.next.load(Ordering::Relaxed) as usize % CALLER_CACHE_CAP;
        self.next.store((index + 1) as u32, Ordering::Relaxed);
        let sequence = self.sequences[index].load(Ordering::Relaxed);
        self.sequences[index].store(sequence.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.starts[index].store(start, Ordering::Relaxed);
        self.ends[index].store(end, Ordering::Relaxed);
        self.kinds[index].store(kind as u32, Ordering::Relaxed);
        self.sequences[index].store(sequence.wrapping_add(2), Ordering::Release);
        self.lock.store(false, Ordering::Release);
    }

    fn reset_after_fork(&self) {
        for index in 0..CALLER_CACHE_CAP {
            let sequence = self.sequences[index].load(Ordering::Relaxed);
            if sequence & 1 != 0 {
                self.starts[index].store(0, Ordering::Relaxed);
                self.ends[index].store(0, Ordering::Relaxed);
                self.sequences[index].store(sequence.wrapping_add(1), Ordering::Release);
            }
        }
        self.lock.store(false, Ordering::Release);
    }
}

static CALLER_CACHE: CallerCache = CallerCache::new();

unsafe extern "C" {
    fn debug_log(message: *const c_char);
    #[cfg(feature = "debug")]
    fn debug_log_hex(prefix: *const c_char, value: u64);
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
}

fn little_endian_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

fn little_endian_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn pe_export_name(base: u64, expected: &[u8]) -> bool {
    if expected.len() >= 32 {
        return false;
    }
    let mut dos = [0u8; 64];
    if !read_memory(base, &mut dos) || dos.get(..2) != Some(b"MZ") {
        return false;
    }
    let Some(header_offset) = little_endian_u32(&dos[0x3c..]) else {
        return false;
    };
    let Some(header_address) = base.checked_add(u64::from(header_offset)) else {
        return false;
    };
    let mut header = [0u8; 160];
    if !read_memory(header_address, &mut header)
        || header.get(..4) != Some(b"PE\0\0")
        || little_endian_u16(&header[24..]) != Some(0x20b)
    {
        return false;
    }
    let Some(export_rva) = little_endian_u32(&header[136..]) else {
        return false;
    };
    let Some(export_address) = base.checked_add(u64::from(export_rva)) else {
        return false;
    };
    let mut export = [0u8; 16];
    if !read_memory(export_address, &mut export) {
        return false;
    }
    let Some(name_rva) = little_endian_u32(&export[12..]) else {
        return false;
    };
    let Some(name_address) = base.checked_add(u64::from(name_rva)) else {
        return false;
    };
    let mut name = [0u8; 32];
    let length = expected.len() + 1;
    read_memory(name_address, &mut name[..length])
        && name[..expected.len()] == *expected
        && name[expected.len()] == 0
}

fn pe_image_named(address: u64, expected: &[u8]) -> bool {
    const ALLOCATION_GRANULARITY: u64 = 0x1_0000;
    const SEARCH_DISTANCE: u64 = 0x10_00000;
    let aligned = address & !(ALLOCATION_GRANULARITY - 1);
    for offset in (0..=SEARCH_DISTANCE).step_by(ALLOCATION_GRANULARITY as usize) {
        let Some(base) = aligned.checked_sub(offset) else {
            break;
        };
        if pe_export_name(base, expected) {
            return true;
        }
    }
    false
}

fn caller_mapping(line: &[u8], address: u64) -> Option<(u64, u64, CallerKind)> {
    let mapping = maps::parse(line)?;
    (mapping.start..mapping.end)
        .contains(&address)
        .then(|| (mapping.start, mapping.end, path_kind(mapping.path)))
}

#[cfg(test)]
fn mapping_path_kind(line: &[u8]) -> CallerKind {
    maps::parse(line).map_or(CallerKind::Ordinary, |mapping| path_kind(mapping.path))
}

fn path_kind(pathname: &[u8]) -> CallerKind {
    let pathname = pathname.strip_suffix(b" (deleted)").unwrap_or(pathname);
    let filename = pathname
        .rsplit(|&byte| byte == b'/')
        .next()
        .unwrap_or_default();
    if matches!(filename, b"artifact.dll" | b"artifact.dll.so") {
        CallerKind::Artifact
    } else {
        CallerKind::Ordinary
    }
}

fn classify_caller(address: u64) -> Option<CallerKind> {
    if let Some(kind) = CALLER_CACHE.lookup(address) {
        return Some(kind);
    }
    let mut result = None;
    maps::find_line(|line| {
        result = caller_mapping(line, address);
        result.is_some()
    });
    let (start, end, mapped_kind) = result?;
    let kind = match mapped_kind {
        CallerKind::Ordinary if pe_image_named(address, b"artifact.dll") => CallerKind::Artifact,
        kind => kind,
    };
    CALLER_CACHE.insert(start, end, kind);
    Some(kind)
}

fn native_cpuid(leaf: u32, subleaf: u32) -> Registers {
    let result = __cpuid_count(leaf, subleaf);
    Registers {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

pub(crate) fn after_fork() {
    {
        CALLER_CACHE.reset_after_fork();
        WINE_VIEW_CACHE.reset_after_fork();
    }
}

pub(crate) unsafe extern "C" fn detect_cpu_vendor() {
    let vendor = Vendor::from_leaf0(native_cpuid(0, 0));
    unsafe {
        debug_log(
            match vendor {
                Vendor::Intel => c"cpuid host vendor=intel",
                Vendor::Amd => c"cpuid host vendor=amd",
                Vendor::Unknown => c"cpuid host vendor=unknown",
            }
            .as_ptr(),
        );
    }
    ACTIVE_VENDOR.store(vendor);
}

fn is_cpuid_instruction_at(address: usize) -> bool {
    let mut instruction = [0u8; 2];
    read_memory(address as u64, &mut instruction) && instruction == [0x0f, 0xa2]
}

#[cfg(feature = "debug")]
fn trace_forwarded_game_fault(info: *const siginfo_t, gregs: *const greg_t) {
    if !crate::artifact::active()
        || FORWARDED_GAME_FAULTS_LOGGED.fetch_add(1, Ordering::Relaxed) >= 8
    {
        return;
    }
    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() as u64 };
    let mut opcode = [0; 2];
    let opcode = if read_memory(rip, &mut opcode) {
        u16::from_le_bytes(opcode)
    } else {
        u16::MAX
    };
    let (trap, code, address) = unsafe {
        (
            gregs.add(libc::REG_TRAPNO as usize).read() as u64,
            (*info).si_code as u64,
            (*info).si_addr() as u64,
        )
    };
    unsafe {
        debug_log(c"game SIGSEGV forwarded to Wine".as_ptr());
        debug_log_hex(c"game fault RIP=".as_ptr(), rip);
        debug_log_hex(c"game fault trap=".as_ptr(), trap);
        debug_log_hex(c"game fault si_code=".as_ptr(), code);
        debug_log_hex(c"game fault address=".as_ptr(), address);
        debug_log_hex(c"game fault opcode=".as_ptr(), u64::from(opcode));
    }
}

fn native_reply_uncached(leaf: u32, subleaf: u32) -> Option<Registers> {
    if unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_SET_CPUID as libc::c_long,
            1 as libc::c_ulong,
        )
    } == -1
    {
        return None;
    }

    let result = native_cpuid(leaf, subleaf);
    if unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_SET_CPUID as libc::c_long,
            0 as libc::c_ulong,
        )
    } == -1
    {
        unsafe {
            debug_log(c"CPUID faulting re-arm failed; terminating".as_ptr());
            libc::syscall(libc::SYS_exit_group, 127 as libc::c_long);
            libc::_exit(127);
        }
    }
    Some(result)
}

fn artifact_native_reply(leaf: u32, subleaf: u32) -> Registers {
    let Some(reply) = native_reply_uncached(leaf, subleaf) else {
        unsafe {
            debug_log(c"ART native CPUID access failed; terminating".as_ptr());
            libc::_exit(170);
        }
    };
    reply
}

enum CpuidOutput {
    Full(Registers),
    ArtifactQuery([u64; 4]),
    ArtifactReady,
}

const WINE_VIEW_CACHE_CAP: usize = 64;

/// Address ranges whose Wine-view answer is already known, so a repeat CPUID
/// from the same code skips the `/proc/self/maps` scan. Without this, every
/// Artifact-game CPUID costs a full scan, which widens game-side
/// set-flag-then-fill races (Stellar Blade's SIMD table setup) into crashes.
/// Each entry records the file-mapping generation it was computed under and
/// is ignored once a new file mapping appears. Entries use the same seqlock
/// and skip-if-busy insert as [`CallerCache`].
struct WineViewCache {
    lock: AtomicBool,
    next: AtomicU32,
    sequences: [AtomicU32; WINE_VIEW_CACHE_CAP],
    starts: [AtomicU64; WINE_VIEW_CACHE_CAP],
    ends: [AtomicU64; WINE_VIEW_CACHE_CAP],
    /// Start of everything the answer depends on: the PE header of the image
    /// that decided an anonymous range, otherwise the range start.
    depends: [AtomicU64; WINE_VIEW_CACHE_CAP],
    /// `generation << 1 | native`.
    values: [AtomicU64; WINE_VIEW_CACHE_CAP],
}

impl WineViewCache {
    const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            next: AtomicU32::new(0),
            sequences: [const { AtomicU32::new(0) }; WINE_VIEW_CACHE_CAP],
            starts: [const { AtomicU64::new(0) }; WINE_VIEW_CACHE_CAP],
            ends: [const { AtomicU64::new(0) }; WINE_VIEW_CACHE_CAP],
            depends: [const { AtomicU64::new(0) }; WINE_VIEW_CACHE_CAP],
            values: [const { AtomicU64::new(0) }; WINE_VIEW_CACHE_CAP],
        }
    }

    fn lookup(&self, address: u64, generation: u64) -> Option<bool> {
        for index in 0..WINE_VIEW_CACHE_CAP {
            let before = self.sequences[index].load(Ordering::Acquire);
            if before & 1 != 0 {
                continue;
            }
            let start = self.starts[index].load(Ordering::Relaxed);
            let end = self.ends[index].load(Ordering::Relaxed);
            let value = self.values[index].load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if self.sequences[index].load(Ordering::Relaxed) == before
                && (start..end).contains(&address)
                && value >> 1 == generation
            {
                return Some(value & 1 != 0);
            }
        }
        None
    }

    /// Skips caching rather than spinning if another insert is in progress:
    /// this runs inside the SIGSEGV handler, possibly on top of that insert.
    fn insert(&self, start: u64, depend: u64, end: u64, generation: u64, native: bool) {
        if generation >> 63 != 0
            || self
                .lock
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        // Several threads can miss on the same cold range at once.
        if self.lookup(start, generation).is_some() && self.lookup(end - 1, generation).is_some() {
            self.lock.store(false, Ordering::Release);
            return;
        }
        let index = self.next.load(Ordering::Relaxed) as usize % WINE_VIEW_CACHE_CAP;
        self.next.store((index + 1) as u32, Ordering::Relaxed);
        let sequence = self.sequences[index].load(Ordering::Relaxed);
        self.sequences[index].store(sequence.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.starts[index].store(start, Ordering::Relaxed);
        self.ends[index].store(end, Ordering::Relaxed);
        self.depends[index].store(depend.min(start), Ordering::Relaxed);
        self.values[index].store(generation << 1 | u64::from(native), Ordering::Relaxed);
        self.sequences[index].store(sequence.wrapping_add(2), Ordering::Release);
        self.lock.store(false, Ordering::Release);
    }
}

impl WineViewCache {
    /// Whether `[start, end)` overlaps anything a cached answer depends on.
    fn overlaps(&self, start: u64, end: u64) -> bool {
        (0..WINE_VIEW_CACHE_CAP).any(|index| {
            let cached_end = self.ends[index].load(Ordering::Relaxed);
            let depend = self.depends[index].load(Ordering::Relaxed);
            // An entry being written is treated as overlapping: invalidating
            // too often only costs a rescan.
            self.sequences[index].load(Ordering::Acquire) & 1 != 0
                || (depend < cached_end && depend < end && start < cached_end)
        })
    }

    /// After `fork`, only this thread exists, so the cache can start empty.
    fn reset_after_fork(&self) {
        for index in 0..WINE_VIEW_CACHE_CAP {
            self.starts[index].store(0, Ordering::Relaxed);
            self.ends[index].store(0, Ordering::Relaxed);
            self.depends[index].store(0, Ordering::Relaxed);
            self.sequences[index].store(0, Ordering::Release);
        }
        self.next.store(0, Ordering::Relaxed);
        self.lock.store(false, Ordering::Release);
    }
}

static WINE_VIEW_CACHE: WineViewCache = WineViewCache::new();

/// Mappings placed over memory a cached answer depends on. Unmapped code
/// cannot run CPUID until something is mapped there again, and every such
/// mapping made through this library's `mmap` reaches [`note_mapping`].
/// Mappings made with raw syscalls (the dynamic loader) or `mremap` are not
/// seen; they rarely land on CPUID-executing game or Wine code.
static WINE_VIEW_INVALIDATIONS: AtomicU64 = AtomicU64::new(0);

fn wine_view_generation() -> u64 {
    maps::file_mapping_generation().wrapping_add(WINE_VIEW_INVALIDATIONS.load(Ordering::Acquire))
}

/// Called by the `mmap` interposer after every successful mapping.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn note_mapping(start: u64, length: u64) {
    if WINE_VIEW_CACHE.overlaps(start, start.saturating_add(length)) {
        WINE_VIEW_INVALIDATIONS.fetch_add(1, Ordering::Release);
    }
}

fn artifact_wine_system_rip(address: u64) -> bool {
    // Read before the scan: a mapping added during it makes this entry stale.
    let generation = wine_view_generation();
    if let Some(native) = WINE_VIEW_CACHE.lookup(address, generation) {
        return native;
    }
    let (native, range) = classify_wine_view(address);
    if let Some((start, depend, end)) = range {
        WINE_VIEW_CACHE.insert(start, depend, end, generation, native);
    }
    native
}

/// Whether `address` runs Wine system code, plus the surrounding range that
/// gets the same answer (see `constant_wine_view_range`) and the start of the
/// memory that answer depends on.
fn classify_wine_view(address: u64) -> (bool, Option<(u64, u64, u64)>) {
    let mut native = pingu_protocol::artifact::profile::native_wine_view(address, None);
    // (start, end, view) of the closest preceding PE image containing `address`.
    let mut image: Option<(u64, u64, bool)> = None;
    let mut closer_image_end = 0;
    let mut containing = None;
    maps::find_line(|line| {
        let Some(mapping) = maps::parse(line) else {
            return false;
        };
        if mapping.start > address {
            return true;
        }
        let path = mapping
            .path
            .strip_suffix(b" (deleted)")
            .unwrap_or(mapping.path);
        let extension = path.get(path.len().saturating_sub(4)..).unwrap_or_default();
        if mapping.start & 0xffff == 0
            && mapping.inode != b"0"
            && (extension.eq_ignore_ascii_case(b".exe") || extension.eq_ignore_ascii_case(b".dll"))
        {
            let mut dos = [0u8; 64];
            if read_memory(mapping.start, &mut dos) && &dos[..2] == b"MZ" {
                let offset = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]);
                if (64..=0x1000).contains(&offset)
                    && let Some(header) = mapping.start.checked_add(u64::from(offset))
                {
                    let mut pe = [0u8; 84];
                    if read_memory(header, &mut pe)
                        && let Some(end) = pingu_protocol::artifact::profile::pe_image_end(
                            mapping.start,
                            &dos,
                            &pe,
                        )
                    {
                        if address < end {
                            // Maps are ordered; the closest containing PE header wins.
                            image = Some((
                                mapping.start,
                                end,
                                pingu_protocol::artifact::profile::native_wine_view(
                                    address,
                                    Some(path),
                                ),
                            ));
                            closer_image_end = 0;
                        } else {
                            closer_image_end = closer_image_end.max(end);
                        }
                    }
                }
            }
        }
        if !(mapping.start..mapping.end).contains(&address) {
            return false;
        }
        let anonymous = mapping.inode == b"0";
        native = if anonymous {
            image.map_or(native, |(_, _, view)| view)
        } else {
            pingu_protocol::artifact::profile::native_wine_view(address, Some(mapping.path))
        };
        containing = Some((mapping.start, mapping.end, anonymous));
        true
    });
    let range = containing.and_then(|(start, end, anonymous)| {
        let (range_start, range_end) = pingu_protocol::artifact::profile::constant_wine_view_range(
            address,
            (start, end),
            anonymous,
            image.map(|(_, end, _)| end),
            closer_image_end,
        )?;
        let depend = match image {
            Some((image_start, _, _)) if anonymous => image_start,
            _ => range_start,
        };
        Some((range_start, depend, range_end))
    });
    (native, range)
}

fn apply_cpuid_output(registers: &mut [greg_t; 23], output: CpuidOutput) {
    match output {
        CpuidOutput::Full(reply) => {
            registers[libc::REG_RAX as usize] = i64::from(reply.eax);
            registers[libc::REG_RBX as usize] = i64::from(reply.ebx);
            registers[libc::REG_RCX as usize] = i64::from(reply.ecx);
            registers[libc::REG_RDX as usize] = i64::from(reply.edx);
        }
        CpuidOutput::ArtifactQuery(reply) => {
            registers[libc::REG_RAX as usize] = reply[0] as greg_t;
            registers[libc::REG_RBX as usize] = reply[1] as greg_t;
            registers[libc::REG_RCX as usize] = reply[2] as greg_t;
            registers[libc::REG_RDX as usize] = reply[3] as greg_t;
        }
        CpuidOutput::ArtifactReady => registers[libc::REG_RAX as usize] = 1,
    }
    registers[libc::REG_RIP as usize] = registers[libc::REG_RIP as usize].wrapping_add(2);
}

pub(crate) unsafe extern "C" fn cpuid_sigsegv_handler(
    sig: c_int,
    info: *mut siginfo_t,
    context: *mut c_void,
) {
    let _errno = crate::errno::Errno::save();
    let context_ptr = context.cast::<ucontext_t>();
    if context_ptr.is_null() || info.is_null() {
        unsafe { forward_signal(sig, info, context) };
        return;
    }
    let mut dispatch_guard = unsafe { crate::artifact::wine_dispatch_guard() };

    let gregs = unsafe { ptr::addr_of_mut!((*context_ptr).uc_mcontext.gregs).cast::<greg_t>() };
    // `int 2e` is identifiable from its faulting opcode and #GP trap number.
    if unsafe { crate::int2e::skip_int2e_fault(context_ptr) } {
        return;
    }
    let is_cpuid_fault = unsafe {
        gregs.add(libc::REG_TRAPNO as usize).read() == 13 && (*info).si_code == libc::SI_KERNEL
    };
    if !is_cpuid_fault {
        #[cfg(feature = "debug")]
        trace_forwarded_game_fault(info, gregs);
        drop(dispatch_guard);
        unsafe { forward_signal(sig, info, context) };
        return;
    }

    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() };
    if !is_cpuid_instruction_at(rip as usize) {
        #[cfg(feature = "debug")]
        trace_forwarded_game_fault(info, gregs);
        drop(dispatch_guard);
        unsafe { forward_signal(sig, info, context) };
        return;
    }

    let (leaf, control, payload) = unsafe {
        (
            gregs.add(libc::REG_RAX as usize).read() as u32,
            gregs.add(libc::REG_RCX as usize).read() as u64,
            gregs.add(libc::REG_RDX as usize).read() as u64,
        )
    };
    {
        if !crate::artifact::detected() && classify_caller(rip as u64) == Some(CallerKind::Artifact)
        {
            crate::artifact::mark_detected();
            dispatch_guard = unsafe { crate::artifact::wine_dispatch_guard() };
        }
        if crate::artifact::detected() {
            let early_handler_allowed = leaf == 0x336933 && !crate::artifact::active();
            let action = crate::artifact::cpuid(
                leaf,
                control,
                payload,
                ACTIVE_VENDOR.load(),
                early_handler_allowed,
            );
            let output = match action {
                pingu_protocol::artifact::CpuidAction::Ready => CpuidOutput::ArtifactReady,
                pingu_protocol::artifact::CpuidAction::Zero => {
                    CpuidOutput::Full(Registers::default())
                }
                pingu_protocol::artifact::CpuidAction::Query
                    if !artifact_wine_system_rip(rip as u64) =>
                {
                    CpuidOutput::ArtifactQuery(pingu_protocol::artifact::profile::reply(
                        crate::artifact::config::artifact_generation(),
                        ACTIVE_VENDOR.load(),
                        crate::artifact::intel_identity(),
                        leaf,
                        control as u32,
                        || artifact_native_reply(leaf, control as u32),
                    ))
                }
                pingu_protocol::artifact::CpuidAction::Native
                    if dispatch_guard.is_some() && !artifact_wine_system_rip(rip as u64) =>
                {
                    CpuidOutput::ArtifactQuery(pingu_protocol::artifact::cpu::native_words(
                        ACTIVE_VENDOR.load(),
                        artifact_native_reply(leaf, control as u32),
                    ))
                }
                pingu_protocol::artifact::CpuidAction::Query
                | pingu_protocol::artifact::CpuidAction::Native => {
                    CpuidOutput::Full(artifact_native_reply(leaf, control as u32))
                }
            };
            apply_cpuid_output(unsafe { &mut (*context_ptr).uc_mcontext.gregs }, output);
            drop(dispatch_guard);
            return;
        }
    }
    let _ = payload;
    let reply = native_reply_uncached(leaf, control as u32).unwrap_or_default();
    apply_cpuid_output(
        unsafe { &mut (*context_ptr).uc_mcontext.gregs },
        CpuidOutput::Full(reply),
    );
}

#[cfg(test)]
mod caller_image_tests {
    use super::{CallerKind, caller_mapping, mapping_path_kind};

    #[test]
    fn maps_artifact_image_even_when_the_library_path_has_spaces() {
        let artifact =
            b"7f100000-7f101000 r-xp 00000000 08:01 456 /home/user/Steam Library/artifact.dll";
        assert_eq!(
            caller_mapping(artifact, 0x7f10_0100),
            Some((0x7f10_0000, 0x7f10_1000, CallerKind::Artifact))
        );
        assert_eq!(mapping_path_kind(artifact), CallerKind::Artifact);
    }
}

#[cfg(all(test, not(miri)))]
mod int2e_signal_tests {
    use super::cpuid_sigsegv_handler;
    use core::mem::MaybeUninit;
    use libc::{siginfo_t, ucontext_t};

    // Reaches `int2e.rs`'s `skip_int2e_fault`, whose `read_memory` calls
    // `process_vm_readv` — not in Miri's foreign-function shim list at all
    // (confirmed: "can't call foreign function `process_vm_readv`").
    #[test]
    fn handles_int2e_even_when_signal_code_is_not_si_kernel() {
        let page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let code = [0x0f, 0x05, 0xc3, 0xcd, 0x2e];
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast::<u8>(), code.len()) };
        // No `mprotect(PROT_EXEC)`: this RIP lands on the rewind path
        // (`preceding_direct_syscall`), which only reads these bytes back via
        // `process_vm_readv` — it never executes them and never reaches
        // `patch_to_syscall`'s `/proc/self/maps` executable-mapping check, so
        // the page never actually needs to be executable. Miri doesn't
        // support mmap/mprotect protections beyond PROT_READ|PROT_WRITE, so
        // this also keeps the test runnable there.
        let mut context = unsafe { MaybeUninit::<ucontext_t>::zeroed().assume_init() };
        let mut info = unsafe { MaybeUninit::<siginfo_t>::zeroed().assume_init() };
        let direct = page as u64;
        context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = 13;
        context.uc_mcontext.gregs[libc::REG_RIP as usize] = (direct + 3) as libc::greg_t;
        info.si_code = 1; // Deliberately differs from SI_KERNEL.

        unsafe {
            cpuid_sigsegv_handler(
                libc::SIGSEGV,
                &mut info,
                (&mut context as *mut ucontext_t).cast(),
            );
        }

        assert_eq!(
            context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            direct
        );
        assert_eq!(unsafe { libc::munmap(page, 0x1000) }, 0);
    }
}

// Not a correctness test: measures `classify_caller`'s actual wall-clock cost
// under two workloads, to check a hypothesis about a reported fps regression
// (Monster Hunter Wilds, 160->90fps) rather than reason about it further from
// first principles. `#[ignore]` since it's a manual diagnostic, not part of
// the normal suite; run with `cargo test -p pingu-hook-runtime --lib
// classify_caller_bench -- --ignored --nocapture`.
#[cfg(test)]
mod artifact_cpuid_output_tests {
    use super::{CpuidOutput, apply_cpuid_output};

    #[test]
    fn artifact_ready_preserves_every_incoming_register_except_rax_and_next_rip() {
        let mut registers =
            core::array::from_fn(|index| (0x1234_0000_0000_0000u64 | index as u64) as libc::greg_t);
        registers[libc::REG_RIP as usize] = 0x140001000;
        let before = registers;
        apply_cpuid_output(&mut registers, CpuidOutput::ArtifactReady);
        assert_eq!(registers[libc::REG_RAX as usize], 1);
        assert_eq!(registers[libc::REG_RIP as usize], 0x140001002);
        for index in 0..registers.len() {
            if index != libc::REG_RAX as usize && index != libc::REG_RIP as usize {
                assert_eq!(registers[index], before[index], "register {index}");
            }
        }
    }

    #[test]
    fn artifact_query_keeps_signed_source_words_without_clobbering_other_state() {
        let mut registers =
            core::array::from_fn(|index| (0x1234_0000_0000_0000u64 | index as u64) as libc::greg_t);
        registers[libc::REG_RIP as usize] = 0x140001000;
        let before = registers;
        let reply = [0, 0x0180_0020, 0xffff_ffff_8040_0200, 0xffff_ffff_8000_4000];
        apply_cpuid_output(&mut registers, CpuidOutput::ArtifactQuery(reply));
        for (index, value) in [
            (libc::REG_RAX, reply[0]),
            (libc::REG_RBX, reply[1]),
            (libc::REG_RCX, reply[2]),
            (libc::REG_RDX, reply[3]),
        ] {
            assert_eq!(registers[index as usize] as u64, value);
        }
        assert_eq!(registers[libc::REG_RIP as usize], 0x140001002);
        for index in 0..registers.len() {
            if ![
                libc::REG_RAX,
                libc::REG_RBX,
                libc::REG_RCX,
                libc::REG_RDX,
                libc::REG_RIP,
            ]
            .contains(&(index as i32))
            {
                assert_eq!(registers[index], before[index], "register {index}");
            }
        }
    }

    #[test]
    fn native_gs_zero_thread_keeps_architectural_cpuid_words_after_art_detection() {
        const ARCH_GET_CPUID: libc::c_long = 0x1011;
        let previous_cpuid_mode =
            unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_CPUID, 0 as libc::c_ulong) };
        let cpuid_faulting_supported = previous_cpuid_mode >= 0
            && unsafe {
                libc::syscall(
                    libc::SYS_arch_prctl,
                    super::ARCH_SET_CPUID as libc::c_long,
                    previous_cpuid_mode as libc::c_ulong,
                )
            } != -1;
        if !cpuid_faulting_supported {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENODEV)
            );
        }
        let child = unsafe { libc::syscall(libc::SYS_fork) };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                crate::artifact::mark_detected();
                if crate::artifact::wine_dispatch_guard().is_some() {
                    libc::_exit(70);
                }
                let native = if cpuid_faulting_supported {
                    let Some(native) = super::native_reply_uncached(0x8000_0000, 0) else {
                        libc::_exit(71);
                    };
                    Some(native)
                } else {
                    if super::native_reply_uncached(0x8000_0000, 0).is_some() {
                        libc::_exit(73);
                    }
                    None
                };
                super::ACTIVE_VENDOR.store(pingu_protocol::cpuid::Vendor::Intel);
                static OPCODE: [u8; 2] = [0x0f, 0xa2];
                let mut context: libc::ucontext_t = core::mem::zeroed();
                let mut info: libc::siginfo_t = core::mem::zeroed();
                info.si_code = libc::SI_KERNEL;
                context.uc_mcontext.gregs[libc::REG_RAX as usize] = 0x8000_0000;
                context.uc_mcontext.gregs[libc::REG_RIP as usize] = OPCODE.as_ptr() as libc::greg_t;
                context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = 13;
                super::cpuid_sigsegv_handler(
                    libc::SIGSEGV,
                    &mut info,
                    (&mut context as *mut libc::ucontext_t).cast(),
                );
                let Some(native) = native else {
                    // `artifact_native_reply` must terminate with 170 before reaching here.
                    libc::_exit(74);
                };
                let expected = [native.eax, native.ebx, native.ecx, native.edx];
                let indices = [libc::REG_RAX, libc::REG_RBX, libc::REG_RCX, libc::REG_RDX];
                let unchanged = indices.into_iter().zip(expected).all(|(index, word)| {
                    context.uc_mcontext.gregs[index as usize] as u64 == u64::from(word)
                });
                libc::_exit(if unchanged { 0 } else { 72 });
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(child as libc::pid_t, &mut status, libc::WNOHANG) };
            if result == child as libc::pid_t {
                break;
            }
            if result < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR)
                );
                continue;
            }
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::kill(child as libc::pid_t, libc::SIGKILL);
                    libc::waitpid(child as libc::pid_t, &mut status, 0);
                }
                panic!("native CPUID child timed out");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(libc::WIFEXITED(status), "child status {status}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            if cpuid_faulting_supported { 0 } else { 170 }
        );
    }
}

#[cfg(test)]
mod wine_view_cache_tests {
    use super::{CallerCache, CallerKind, WineViewCache, classify_wine_view};
    use core::sync::atomic::Ordering;

    #[test]
    fn hits_only_inside_the_range_and_for_the_same_generation() {
        let cache = WineViewCache::new();
        assert_eq!(cache.lookup(0x2000, 7), None);
        cache.insert(0x1000, 0x1000, 0x3000, 7, true);
        cache.insert(0x5000, 0x5000, 0x6000, 7, false);
        assert_eq!(cache.lookup(0x1000, 7), Some(true));
        assert_eq!(cache.lookup(0x2fff, 7), Some(true));
        assert_eq!(cache.lookup(0x3000, 7), None);
        assert_eq!(cache.lookup(0x5800, 7), Some(false));
        // A new file mapping since the scan makes every entry stale.
        assert_eq!(cache.lookup(0x2000, 8), None);
        // Generations too large to pack are never cached.
        cache.insert(0x8000, 0x8000, 0x9000, 1 << 63, true);
        assert_eq!(cache.lookup(0x8800, 1 << 63), None);
    }

    #[test]
    fn replaces_entries_round_robin_once_full_and_skips_duplicates() {
        let cache = WineViewCache::new();
        cache.insert(0x1000, 0x1000, 0x2000, 1, true);
        cache.insert(0x1000, 0x1000, 0x2000, 1, true);
        assert_eq!(cache.next.load(Ordering::Relaxed), 1);
        for i in 1..super::WINE_VIEW_CACHE_CAP as u64 + 1 {
            let start = (i + 1) * 0x1000;
            cache.insert(start, start, start + 0x1000, 1, i % 2 == 0);
        }
        // The first entry was overwritten by the last one.
        assert_eq!(cache.lookup(0x1010, 1), None);
        let last = (super::WINE_VIEW_CACHE_CAP as u64 + 1) * 0x1000;
        assert_eq!(cache.lookup(last + 0x10, 1), Some(true));
    }

    #[test]
    fn overlap_covers_the_range_and_the_image_it_depends_on() {
        let cache = WineViewCache::new();
        // Anonymous code at 0x5000..0x7000 decided by an image whose header is at 0x1000.
        cache.insert(0x5000, 0x1000, 0x7000, 1, false);
        assert!(cache.overlaps(0x6000, 0x6001));
        assert!(cache.overlaps(0x1000, 0x2000));
        assert!(cache.overlaps(0x0, 0x1001));
        assert!(!cache.overlaps(0x0, 0x1000));
        assert!(!cache.overlaps(0x7000, 0x9000));
    }

    #[test]
    fn fork_resets_the_wine_view_cache_and_repairs_half_written_caller_entries() {
        let cache = WineViewCache::new();
        cache.insert(0x1000, 0x1000, 0x2000, 1, true);
        cache.lock.store(true, Ordering::Relaxed);
        cache.sequences[1].store(5, Ordering::Relaxed);
        cache.reset_after_fork();
        assert_eq!(cache.lookup(0x1800, 1), None);
        cache.insert(0x3000, 0x3000, 0x4000, 1, false);
        assert_eq!(cache.lookup(0x3800, 1), Some(false));

        let callers = CallerCache::new();
        callers.insert(0x1000, 0x2000, CallerKind::Artifact);
        callers.sequences[0].store(3, Ordering::Relaxed);
        callers.lock.store(true, Ordering::Relaxed);
        callers.reset_after_fork();
        assert_eq!(callers.sequences[0].load(Ordering::Relaxed) & 1, 0);
        assert_eq!(callers.lookup(0x1800), None);
        callers.insert(0x5000, 0x6000, CallerKind::Artifact);
        assert_eq!(callers.lookup(0x5800), Some(CallerKind::Artifact));
    }

    #[test]
    fn every_address_in_a_cached_range_classifies_the_same() {
        // Real `/proc/self/maps` of this test process: this function's own code.
        let here = every_address_in_a_cached_range_classifies_the_same as *const () as usize as u64;
        let (native, range) = classify_wine_view(here);
        let (start, depend, end) = range.expect("a code mapping has a cacheable range");
        assert!((start..end).contains(&here));
        assert!(depend <= start);
        for probe in [start, start + (end - start) / 2, end - 1, here] {
            assert_eq!(classify_wine_view(probe).0, native, "address {probe:#x}");
        }
    }
}
