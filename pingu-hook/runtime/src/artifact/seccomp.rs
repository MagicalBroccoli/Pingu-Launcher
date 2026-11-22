//! Catch Windows syscalls that slip past Wine's syscall user dispatch.
//!
//! Wine builds that use syscall user dispatch (SUD, as in GE-Proton) gate PE
//! syscalls with the per-thread selector byte at TEB+0x340. Artifact processes
//! issue raw `syscall` instructions from Wine's ntdll and win32u stubs, so each
//! one depends on that byte being BLOCK whenever Windows code runs. If a thread
//! returns to Windows code with the byte left at ALLOW, the next stub executes
//! its Windows service number as a Linux syscall (0x18, NtAllocateVirtualMemory,
//! is Linux sched_yield and returns 0), and the caller continues on a result
//! that never happened. GE-Proton 11's dispatcher sets BLOCK while still on its
//! kernel stack, so a signal delivered in that window can leave ALLOW behind.
//!
//! The kernel evaluates SUD before seccomp, so a seccomp filter only sees the
//! syscalls that SUD let through. This filter traps x86-64 syscalls whose
//! instruction pointer lies where Wine maps its PE system DLLs. The SIGSYS
//! router hands each such trap to [`repair_leak`], which sets the selector back
//! to BLOCK and rewinds RIP to the `syscall` instruction. The kernel then runs
//! it again and SUD dispatches it like any other Windows syscall, through
//! Artifact's handler and the router's normal bookkeeping.
//!
//! The filter is installed only after SUD has trapped in this process: with
//! Wine builds that use seccomp instead, a rewound call would trap again.
//! It is inherited by forked and executed children. Native programs and
//! libraries live above the trapped range and the Wine preloader below it.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SECCOMP_SET_MODE_FILTER: libc::c_long = 1;
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_long = 1;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Trapped instruction-pointer range [0x6f00_0000_0000, 0x7000_0000_0000).
/// Wine maps ntdll.dll at 0x6fff_ffef_0000 and its other PE system DLLs just
/// below.
const RANGE_START: u64 = 0x6f00_0000_0000;
const RANGE_END: u64 = 0x7000_0000_0000;

// struct seccomp_data: nr (0), arch (4), instruction_pointer (8).
const OFFSET_ARCH: u32 = 4;
const OFFSET_IP_HIGH: u32 = 12;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;

const SYSCALL_INSTRUCTION: u16 = u16::from_le_bytes([0x0f, 0x05]);

const fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

static FILTER: [libc::sock_filter; 9] = [
    statement(BPF_LD_W_ABS, OFFSET_ARCH),
    jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
    statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    statement(BPF_LD_W_ABS, OFFSET_IP_HIGH),
    jump(BPF_JGE_K, (RANGE_END >> 32) as u32, 0, 1),
    statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    jump(BPF_JGE_K, (RANGE_START >> 32) as u32, 0, 1),
    statement(BPF_RET_K, SECCOMP_RET_TRAP),
    statement(BPF_RET_K, SECCOMP_RET_ALLOW),
];

/// Set once SUD delivers a SIGSYS in this process. SUD configuration and this
/// flag both survive fork; exec clears both.
static DISPATCH_SEEN: AtomicBool = AtomicBool::new(false);

/// Install state: `pid << 2 | INSTALLING`, `INSTALLED` or `FAILED`.
/// A forked child inherits both the filter and an INSTALLED state, so it
/// does not stack a second copy.
static STATE: AtomicU64 = AtomicU64::new(0);
const INSTALLING: u64 = 1;
const INSTALLED: u64 = 2;
/// The install failed for this pid; a forked child may still try.
const FAILED: u64 = 3;

/// Number of leaked syscalls repaired, for diagnostics.
static REPAIRED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Install {
    Installed,
    AlreadyInstalled,
    InProgress,
    NoDispatch,
    Disabled,
    Failed,
}

/// The SIGSYS router reports each SUD trap here.
pub(crate) fn note_dispatch_trap() {
    if !DISPATCH_SEEN.load(Ordering::Relaxed) {
        DISPATCH_SEEN.store(true, Ordering::Relaxed);
    }
}

fn installed() -> bool {
    STATE.load(Ordering::Acquire) & 3 == INSTALLED
}

/// Install the filter on every thread of this process, once. Uses raw
/// syscalls only, so it is safe in the SIGSEGV handler that observes
/// Artifact's protocol leaves. A failed install is not retried in the same
/// process.
pub(crate) fn install_once() -> Install {
    let state = STATE.load(Ordering::Acquire);
    if state & 3 == INSTALLED {
        return Install::AlreadyInstalled;
    }
    if !crate::artifact::config::syscall_leak_trap_enabled() {
        return Install::Disabled;
    }
    if !DISPATCH_SEEN.load(Ordering::Relaxed) {
        return Install::NoDispatch;
    }
    let pid = unsafe { libc::getpid() } as u64;
    // Do not retry a failed install on every later syscall.
    if state & 3 == FAILED && state >> 2 == pid {
        return Install::Failed;
    }
    // INSTALLING with another pid: forked while the parent was installing.
    // The child may lack the filter, so it installs its own.
    if state & 3 == INSTALLING && state >> 2 == pid {
        return Install::InProgress;
    }
    if STATE
        .compare_exchange(
            state,
            pid << 2 | INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Install::InProgress;
    }
    let installed = unsafe { install() };
    STATE.store(
        pid << 2 | if installed { INSTALLED } else { FAILED },
        Ordering::Release,
    );
    #[cfg(feature = "debug")]
    unsafe {
        crate::debug::debug_log(if installed {
            c"ART syscall leak trap installed".as_ptr()
        } else {
            c"ART syscall leak trap could not be installed".as_ptr()
        });
    }
    if installed {
        Install::Installed
    } else {
        Install::Failed
    }
}

unsafe fn install() -> bool {
    // An unprivileged filter requires no_new_privs. Steam's container
    // already sets it; the flag cannot be cleared again if TSYNC fails.
    let no_new_privs = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_NO_NEW_PRIVS as libc::c_long,
            1 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if no_new_privs != 0 {
        return false;
    }
    let program = libc::sock_fprog {
        len: FILTER.len() as libc::c_ushort,
        filter: FILTER.as_ptr().cast_mut(),
    };
    // TSYNC applies the filter to every existing thread; threads created
    // later inherit it. A nonzero result names a thread that could not sync.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const libc::sock_fprog,
        )
    };
    result == 0
}

/// Handle a `SYS_SECCOMP` SIGSYS raised by this filter: restore the dispatch
/// selector and rewind to the `syscall` instruction so SUD dispatches it.
/// Returns false, leaving the context unchanged, for any other trap.
///
/// # Safety
/// `context` must be the live signal context of a SIGSYS on this thread.
pub(crate) unsafe fn repair_leak(context: *mut libc::ucontext_t) -> bool {
    if !installed() || context.is_null() {
        return false;
    }
    let gregs = unsafe { &mut (*context).uc_mcontext.gregs };
    let rip = gregs[libc::REG_RIP as usize] as u64;
    let Some(instruction) = rip.checked_sub(2) else {
        return false;
    };
    if !(RANGE_START..RANGE_END).contains(&instruction)
        || crate::procmem::read_u16(instruction) != Some(SYSCALL_INSTRUCTION)
    {
        return false;
    }
    // Log while the selector still allows Linux syscalls from anywhere.
    #[cfg(feature = "debug")]
    let count = REPAIRED.load(Ordering::Relaxed) + 1;
    #[cfg(feature = "debug")]
    if count <= 16 || count.is_power_of_two() {
        unsafe {
            crate::debug::debug_log_hex(c"ART leaked syscall repaired rip=".as_ptr(), instruction);
            crate::debug::debug_log_hex(
                c"ART leaked syscall service=".as_ptr(),
                gregs[libc::REG_RAX as usize] as u64,
            );
            crate::debug::debug_log_dec(c"ART leaked syscalls repaired=".as_ptr(), count);
        }
    }
    if !unsafe { crate::artifact::set_wine_dispatch_block() } {
        return false;
    }
    REPAIRED.fetch_add(1, Ordering::Relaxed);
    // The kernel rolled RAX back to the syscall number; the other argument
    // registers are untouched, and `syscall` sets RCX/R11 again.
    gregs[libc::REG_RIP as usize] = instruction as libc::greg_t;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicI32;

    const TRAPPED_CODE: usize = 0x6fff_f000_0000;
    const BELOW_CODE: usize = 0x6eff_f000_0000;
    const SYS_SECCOMP: i32 = 1;
    const SYS_USER_DISPATCH: i32 = 2;
    const PR_SET_SYSCALL_USER_DISPATCH: libc::c_int = 59;
    const ARCH_SET_GS: libc::c_long = 0x1001;

    static SECCOMP_TRAPS: AtomicI32 = AtomicI32::new(0);
    static DISPATCH_TRAPS: AtomicI32 = AtomicI32::new(0);
    static mut FAKE_TEB: [u8; 0x1000] = [0; 0x1000];

    extern "C" fn sigsys(_: libc::c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
        let context = context.cast::<libc::ucontext_t>();
        unsafe {
            match (*info).si_code {
                SYS_SECCOMP => {
                    SECCOMP_TRAPS.fetch_add(1, Ordering::SeqCst);
                    if !repair_leak(context) {
                        (*context).uc_mcontext.gregs[libc::REG_RAX as usize] = -1;
                    }
                }
                SYS_USER_DISPATCH => {
                    DISPATCH_TRAPS.fetch_add(1, Ordering::SeqCst);
                    // Complete it as Wine would, then leave Windows code.
                    (*context).uc_mcontext.gregs[libc::REG_RAX as usize] = 0x5ecc;
                    *core::ptr::addr_of_mut!(FAKE_TEB).cast::<u8>().add(0x340) = 0;
                }
                _ => {}
            }
        }
    }

    /// Maps `mov eax, getpid; syscall; ret` at a fixed address.
    unsafe fn map_stub(address: usize) -> extern "C" fn() -> i64 {
        let page = unsafe {
            libc::mmap(
                address as *mut libc::c_void,
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_eq!(page as usize, address);
        let code: [u8; 8] = [0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xc3];
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast::<u8>(), code.len()) };
        unsafe { core::mem::transmute::<*mut libc::c_void, extern "C" fn() -> i64>(page) }
    }

    /// A leaked call from the trapped range is rewound and dispatched by SUD;
    /// calls outside the range run natively.
    #[test]
    fn leaked_call_is_redispatched() {
        let child = unsafe { libc::syscall(libc::SYS_fork) };
        assert!(child >= 0);
        if child == 0 {
            let status = unsafe { leaked_call_child() };
            unsafe { libc::_exit(status) };
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child as libc::pid_t, &mut status, 0) },
            child as libc::pid_t
        );
        assert!(libc::WIFEXITED(status), "status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    unsafe fn leaked_call_child() -> i32 {
        unsafe {
            if libc::getauxval(libc::AT_HWCAP2) & 2 == 0 {
                return 0; // No user FSGSBASE: the repair cannot run here.
            }
            let mut action: libc::sigaction = core::mem::zeroed();
            action.sa_sigaction = sigsys as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGSYS, &action, core::ptr::null_mut());
            let inside = map_stub(TRAPPED_CODE);
            let below = map_stub(BELOW_CODE);
            let pid = libc::getpid() as i64;
            let teb = core::ptr::addr_of_mut!(FAKE_TEB).cast::<u8>();
            if libc::syscall(libc::SYS_arch_prctl, ARCH_SET_GS, teb) != 0 {
                return 10;
            }
            // Dispatch only below the trapped range's end; libc and the vDSO
            // live above it and stay exempt, as in Wine.
            if libc::prctl(
                PR_SET_SYSCALL_USER_DISPATCH,
                1 as libc::c_ulong,
                RANGE_END as libc::c_ulong,
                (0x8000_0000_0000 - RANGE_END) as libc::c_ulong,
                teb.add(0x340),
            ) != 0
            {
                return 11;
            }
            note_dispatch_trap();
            if install_once() != Install::Installed || install_once() != Install::AlreadyInstalled {
                return 12;
            }
            // Selector ALLOW, as after the race: the call leaks past SUD.
            *teb.add(0x340) = 0;
            if inside() != 0x5ecc {
                return 13;
            }
            if SECCOMP_TRAPS.load(Ordering::SeqCst) != 1
                || DISPATCH_TRAPS.load(Ordering::SeqCst) != 1
            {
                return 14;
            }
            if REPAIRED.load(Ordering::SeqCst) != 1 {
                return 15;
            }
            if below() != pid || SECCOMP_TRAPS.load(Ordering::SeqCst) != 1 {
                return 16;
            }
            0
        }
    }
}
