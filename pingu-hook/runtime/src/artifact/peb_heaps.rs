//! Live `PEB.ProcessHeaps` publication for stock Wine.
//!
//! Wine keeps its heap list private and leaves the PEB triple
//! (`NumberOfHeaps` +0xe8, `MaximumNumberOfHeaps` +0xec, `ProcessHeaps` +0xf0)
//! empty. Artifact copies the table during its initialization, so it must be
//! valid then and stay valid while heaps are created and destroyed.
//!
//! Only `kernel32` and `kernelbase` call `RtlCreateHeap`/`RtlDestroyHeap` in
//! Wine (ntdll has no internal caller after its own process heap), so their
//! import slots are the whole interposition surface. The hooks run in PE
//! context: they make no Linux syscalls, only calls into ntdll.
//!
//! Every update runs under `RtlLockHeap(process heap)`, held across the real
//! create or destroy, and fills the inactive one of two fixed buffers before
//! publishing pointer, then count. Readers that lock the process heap always
//! see a consistent table. A lock-free reader is not synchronized: it can see
//! the new pointer with the old count, a buffer reused two updates later, or
//! a handle destroyed after it was read. More than 4096 heaps stops the
//! process rather than publishing an incomplete table.
//!
//! Limit: a caller that resolves `ntdll!RtlCreateHeap` or `RtlDestroyHeap`
//! directly, bypassing kernel32/kernelbase, is not seen. No such caller has
//! been observed in Artifact or the game.
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

const SLOTS: usize = 4096;

struct Tables(UnsafeCell<[[usize; SLOTS]; 2]>);
unsafe impl Sync for Tables {}
static TABLES: Tables = Tables(UnsafeCell::new([[0; SLOTS]; 2]));
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

static REAL_CREATE: AtomicUsize = AtomicUsize::new(0);
static REAL_DESTROY: AtomicUsize = AtomicUsize::new(0);
static GET_HEAPS: AtomicUsize = AtomicUsize::new(0);
static LOCK_HEAP: AtomicUsize = AtomicUsize::new(0);
static UNLOCK_HEAP: AtomicUsize = AtomicUsize::new(0);

type Create =
    unsafe extern "win64" fn(u32, *mut c_void, usize, usize, *mut c_void, *mut c_void) -> usize;
type Destroy = unsafe extern "win64" fn(usize) -> usize;
type GetHeaps = unsafe extern "win64" fn(u32, *mut usize) -> u32;
type LockHeap = unsafe extern "win64" fn(usize) -> u8;
type Protect = unsafe extern "win64" fn(isize, *mut usize, *mut usize, u32, *mut u32) -> i32;

const PAGE_READWRITE: u32 = 4;

fn peb() -> usize {
    let mut peb: usize;
    unsafe { core::arch::asm!("mov {p}, qword ptr gs:[0x60]", p = out(reg) peb) };
    peb
}

fn process_heap() -> usize {
    unsafe { core::ptr::read_volatile((peb() + 0x30) as *const usize) }
}

/// Fill the inactive buffer from Wine's list, then publish it. The caller
/// holds the process-heap lock. A table that does not fit is never
/// published incomplete: the process stops instead.
unsafe fn republish() {
    let get: GetHeaps = unsafe { core::mem::transmute(GET_HEAPS.load(Ordering::Acquire)) };
    let active = ACTIVE.load(Ordering::Relaxed);
    let next = unsafe { &mut (*TABLES.0.get())[active ^ 1] };
    let count = unsafe { get(SLOTS as u32, next.as_mut_ptr()) } as usize;
    if count == 0 || count > SLOTS {
        crate::artifact::loader::fatal(
            b"pingu_protocol: process heap count exceeds the PEB.ProcessHeaps table\n",
        );
    }
    for slot in &mut next[count..] {
        *slot = 0;
    }
    let peb = peb();
    unsafe {
        core::ptr::write_volatile((peb + 0xec) as *mut u32, SLOTS as u32);
        core::ptr::write_volatile((peb + 0xf0) as *mut usize, next.as_ptr() as usize);
        core::ptr::write_volatile((peb + 0xe8) as *mut u32, count as u32);
    }
    ACTIVE.store(active ^ 1, Ordering::Relaxed);
}

unsafe fn locked<R>(body: impl FnOnce() -> R) -> R {
    let heap = process_heap();
    let lock: LockHeap = unsafe { core::mem::transmute(LOCK_HEAP.load(Ordering::Acquire)) };
    let unlock: LockHeap = unsafe { core::mem::transmute(UNLOCK_HEAP.load(Ordering::Acquire)) };
    unsafe { lock(heap) };
    let result = body();
    unsafe { unlock(heap) };
    result
}

// Both hooks hold the process-heap lock across the real call, so a reader
// that locks the process heap never sees Wine's list and the table disagree.
// Wine's own create/destroy take that lock too, so the order matches Wine's.
unsafe extern "win64" fn create_hook(
    flags: u32,
    addr: *mut c_void,
    total: usize,
    commit: usize,
    lock: *mut c_void,
    params: *mut c_void,
) -> usize {
    let real: Create = unsafe { core::mem::transmute(REAL_CREATE.load(Ordering::Acquire)) };
    unsafe {
        locked(|| {
            let heap = real(flags, addr, total, commit, lock, params);
            if heap != 0 {
                republish();
            }
            heap
        })
    }
}

unsafe extern "win64" fn destroy_hook(heap: usize) -> usize {
    let real: Destroy = unsafe { core::mem::transmute(REAL_DESTROY.load(Ordering::Acquire)) };
    unsafe {
        locked(|| {
            let result = real(heap);
            republish();
            result
        })
    }
}

/// Write one 8-byte import slot through `NtProtectVirtualMemory`. Fails,
/// without leaving the page writable, unless the protection is restored.
unsafe fn write_slot(protect: Protect, slot: usize, value: usize) -> bool {
    let (mut address, mut size, mut old) = (slot, 8usize, 0u32);
    if unsafe { protect(-1, &mut address, &mut size, PAGE_READWRITE, &mut old) } != 0 {
        return false;
    }
    unsafe { core::ptr::write_volatile(slot as *mut usize, value) };
    let (mut address, mut size, mut ignored) = (slot, 8usize, 0u32);
    unsafe { protect(-1, &mut address, &mut size, old, &mut ignored) == 0 }
}

/// Install once, from PE context under the loader lock, before Artifact's
/// TLS callbacks and DllMain. Does nothing if Wine already publishes a
/// consistent table (a patched NTDLL). On any failure the original import
/// slots are restored and false is returned.
pub(crate) fn install(ntdll: usize, modules: &[usize; 2]) -> bool {
    if INSTALLED.load(Ordering::Acquire) {
        return true;
    }
    let peb = peb();
    if peb == 0 {
        return false;
    }
    let published = unsafe { core::ptr::read_volatile((peb + 0xf0) as *const usize) };
    if published != 0 {
        let number = unsafe { core::ptr::read_volatile((peb + 0xe8) as *const u32) };
        let maximum = unsafe { core::ptr::read_volatile((peb + 0xec) as *const u32) };
        let consistent = number != 0
            && number <= maximum
            && crate::artifact::resolver::read::<8>(published + (number as usize - 1) * 8)
                .is_some();
        INSTALLED.store(consistent, Ordering::Release);
        return consistent;
    }
    let find = |name: &[u8]| crate::artifact::resolver::export(ntdll, b"ntdll.dll\0", name);
    let (Some(create), Some(destroy), Some(get), Some(lock), Some(unlock), Some(protect)) = (
        find(b"RtlCreateHeap\0"),
        find(b"RtlDestroyHeap\0"),
        find(b"RtlGetProcessHeaps\0"),
        find(b"RtlLockHeap\0"),
        find(b"RtlUnlockHeap\0"),
        find(b"NtProtectVirtualMemory\0"),
    ) else {
        return false;
    };
    REAL_CREATE.store(create, Ordering::Release);
    REAL_DESTROY.store(destroy, Ordering::Release);
    GET_HEAPS.store(get, Ordering::Release);
    LOCK_HEAP.store(lock, Ordering::Release);
    UNLOCK_HEAP.store(unlock, Ordering::Release);
    let protect: Protect = unsafe { core::mem::transmute(protect) };
    // kernel32 and kernelbase each import both functions: four slots.
    let mut slots = [(0usize, 0usize); 4];
    let mut index = 0;
    let mut complete = true;
    'patch: for &base in modules {
        for (name, real, hook) in [
            (
                &b"RtlCreateHeap\0"[..],
                create,
                create_hook as *const () as usize,
            ),
            (
                &b"RtlDestroyHeap\0"[..],
                destroy,
                destroy_hook as *const () as usize,
            ),
        ] {
            let Some(slot) = crate::artifact::resolver::import_slot(base, b"ntdll.dll", name)
            else {
                complete = false;
                break 'patch;
            };
            if unsafe { core::ptr::read_volatile(slot as *const usize) } != real {
                complete = false;
                break 'patch;
            }
            // Recorded before the write, so a write whose protection restore
            // failed is still rolled back.
            slots[index] = (slot, real);
            index += 1;
            if !unsafe { write_slot(protect, slot, hook) } {
                complete = false;
                break 'patch;
            }
        }
    }
    if complete {
        unsafe { locked(|| republish()) };
        complete = unsafe { core::ptr::read_volatile((peb + 0xf0) as *const usize) } != 0;
    }
    if !complete {
        for &(slot, real) in &slots[..index] {
            unsafe { write_slot(protect, slot, real) };
        }
        return false;
    }
    INSTALLED.store(true, Ordering::Release);
    true
}
