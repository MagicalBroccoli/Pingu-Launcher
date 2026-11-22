//! Per-thread ART bypass flags, independent of Reflex's bounded marker table.
//!
//! Storage is reserved by the ordinary dispatcher, never by a signal handler.
//! A warmed glibc pthread-specific lookup gives SIGSYS the current thread's
//! frames without allocation or locking. Frames are reused and grow in
//! per-thread blocks; the pthread destructor releases them at thread exit.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering};

const NO_KEY: u32 = u32::MAX;
const FREE: u8 = 0;
const RESERVED: u8 = 1;
const CAPTURED: u8 = 2;
const FRAMES_PER_BLOCK: usize = 64;
const PAGE_SIZE: usize = pingu_protocol::PAGE_SIZE;

static KEY: AtomicU32 = AtomicU32::new(NO_KEY);
static mut KEY_ONCE: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;

struct Frame {
    stack: AtomicU64,
    rip: AtomicU64,
    r11: AtomicU64,
    eflags: AtomicU64,
    phase: AtomicU8,
}

struct Block {
    owner_pid: AtomicI32,
    next: AtomicPtr<Block>,
    frames: [Frame; FRAMES_PER_BLOCK],
}

const _: () = assert!(core::mem::size_of::<Block>() <= PAGE_SIZE);

#[derive(Clone, Copy)]
pub(super) struct SavedFlags {
    pub r11: u64,
    pub eflags: u64,
}

unsafe extern "C" fn destroy_blocks(value: *mut c_void) {
    let mut block = value.cast::<Block>();
    while !block.is_null() {
        let next = unsafe { (*block).next.load(Ordering::Relaxed) };
        unsafe { libc::munmap(block.cast(), PAGE_SIZE) };
        block = next;
    }
}

extern "C" fn initialize_key() {
    let mut key = 0;
    if unsafe { libc::pthread_key_create(&mut key, Some(destroy_blocks)) } != 0 {
        return;
    }
    // Resolve the glibc lookup in ordinary context before publishing KEY.
    // On supported glibc x86-64 this is a TLS read without allocation/locks.
    unsafe { libc::pthread_getspecific(key) };
    KEY.store(key, Ordering::Release);
}

fn key_for_dispatcher() -> Option<libc::pthread_key_t> {
    let mut key = KEY.load(Ordering::Acquire);
    if key == NO_KEY {
        if unsafe { libc::pthread_once(ptr::addr_of_mut!(KEY_ONCE), initialize_key) } != 0 {
            return None;
        }
        key = KEY.load(Ordering::Acquire);
    }
    (key != NO_KEY).then_some(key)
}

fn allocate_block(pid: libc::pid_t) -> *mut Block {
    let memory = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if memory == libc::MAP_FAILED {
        return ptr::null_mut();
    }
    if memory.is_null() {
        unsafe { libc::munmap(memory, PAGE_SIZE) };
        return ptr::null_mut();
    }
    let block = memory.cast::<Block>();
    // MAP_ANONYMOUS supplies zeroed storage: null next, FREE phases and zero
    // frame words are valid representations of every remaining field. Only
    // owner_pid is nonzero. Avoid constructing/writing an aggregate here:
    // LLVM can lower that to libc memset, whose IFUNC-selected AVX/AVX-512
    // implementation clobbers extended vectors before the syscall callback.
    // The bridge preserves legacy XMM lanes, not those helper clobbers.
    unsafe { core::ptr::addr_of_mut!((*block).owner_pid).write(AtomicI32::new(pid)) };
    block
}

/// Returns only storage belonging to the calling thread and process. A child
/// may inherit its parent's pthread value at fork, but must not use its flags.
fn signal_blocks() -> *mut Block {
    let key = KEY.load(Ordering::Acquire);
    if key == NO_KEY {
        return ptr::null_mut();
    }
    let block = unsafe { libc::pthread_getspecific(key).cast::<Block>() };
    if block.is_null() {
        return block;
    }
    let pid = unsafe { libc::getpid() };
    if unsafe { (*block).owner_pid.load(Ordering::Acquire) } != pid {
        return ptr::null_mut();
    }
    block
}

/// Drop completed frames at this stack depth while preserving nested callers.
fn retire_blocks(mut block: *mut Block, stack: u64) {
    while !block.is_null() {
        let current = unsafe { &*block };
        for frame in &current.frames {
            if frame.phase.load(Ordering::Acquire) != FREE
                && frame.stack.load(Ordering::Relaxed) <= stack
            {
                frame.phase.store(FREE, Ordering::Release);
            }
        }
        block = current.next.load(Ordering::Acquire);
    }
}

pub(super) fn retire(stack: u64) {
    retire_blocks(signal_blocks(), stack);
}

/// Reserve a real frame before the bridge executes its raw syscall. This is
/// called only in ordinary guarded dispatcher context and may allocate.
pub(super) fn reserve(stack: u64, rip: u64) -> bool {
    if stack == 0 || rip == 0 {
        return false;
    }
    let Some(key) = key_for_dispatcher() else {
        return false;
    };
    let pid = unsafe { libc::getpid() };
    let mut head = unsafe { libc::pthread_getspecific(key).cast::<Block>() };
    if head.is_null() {
        head = allocate_block(pid);
        if head.is_null() {
            return false;
        }
        if unsafe { libc::pthread_setspecific(key, head.cast()) } != 0 {
            unsafe { destroy_blocks(head.cast()) };
            return false;
        }
    } else if unsafe { (*head).owner_pid.load(Ordering::Acquire) } != pid {
        // After fork only the surviving thread owns this private copy. Clear
        // inherited frames before publishing the child's ownership.
        unsafe { (*head).owner_pid.store(0, Ordering::Release) };
        retire_blocks(head, u64::MAX);
        unsafe { (*head).owner_pid.store(pid, Ordering::Release) };
    }

    let mut block = head;
    loop {
        let current = unsafe { &*block };
        for frame in &current.frames {
            if frame.phase.load(Ordering::Acquire) == FREE {
                frame.stack.store(stack, Ordering::Relaxed);
                frame.rip.store(rip, Ordering::Relaxed);
                frame.phase.store(RESERVED, Ordering::Release);
                return true;
            }
        }
        let mut next = current.next.load(Ordering::Acquire);
        if next.is_null() {
            next = allocate_block(pid);
            if next.is_null() {
                return false;
            }
            current.next.store(next, Ordering::Release);
        }
        block = next;
    }
}

/// Capture actual trap flags. A matching captured frame at the same site is
/// a new ordinary call, not proof of a bypass, so it receives the new flags.
pub(super) fn route(stack: u64, rip: u64, r11: u64, eflags: u64) {
    let mut block = signal_blocks();
    while !block.is_null() {
        let current = unsafe { &*block };
        for frame in &current.frames {
            if frame.phase.load(Ordering::Acquire) == FREE {
                continue;
            }
            let recorded_stack = frame.stack.load(Ordering::Relaxed);
            if recorded_stack == stack && frame.rip.load(Ordering::Relaxed) == rip {
                frame.r11.store(r11, Ordering::Relaxed);
                frame.eflags.store(eflags, Ordering::Relaxed);
                frame.phase.store(CAPTURED, Ordering::Release);
            } else if recorded_stack <= stack {
                frame.phase.store(FREE, Ordering::Release);
            }
        }
        block = current.next.load(Ordering::Acquire);
    }
}

/// Consume a matching captured frame; no matching snapshot means the actual
/// bypass context is forwarded without manufacturing flags.
pub(super) fn bypass(stack: u64, rip: u64) -> Option<SavedFlags> {
    let mut block = signal_blocks();
    let mut saved = None;
    while !block.is_null() {
        let current = unsafe { &*block };
        for frame in &current.frames {
            let phase = frame.phase.load(Ordering::Acquire);
            if phase == FREE {
                continue;
            }
            let recorded_stack = frame.stack.load(Ordering::Relaxed);
            if recorded_stack == stack && frame.rip.load(Ordering::Relaxed) == rip {
                if phase == CAPTURED {
                    saved = Some(SavedFlags {
                        r11: frame.r11.load(Ordering::Relaxed),
                        eflags: frame.eflags.load(Ordering::Relaxed),
                    });
                }
                frame.phase.store(FREE, Ordering::Release);
            } else if recorded_stack <= stack {
                frame.phase.store(FREE, Ordering::Release);
            }
        }
        block = current.next.load(Ordering::Acquire);
    }
    saved
}
