//! Installs pingu-hook's handler in Wine's KUSER dispatcher slot and classifies
//! calls arriving through it for a registered Artifact process.
//!
//! Recognized Wine CALL-through-KUSER stubs replay the raw SYSCALL so
//! [`super::sigsys_router`] can route them to Artifact's callback; marked
//! Artifact bypasses retain Wine's original dispatcher with service/XMM
//! normalization.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::procmem::{read_memory, read_u64};

const WINE_DISPATCHER_SLOT: u64 = 0x7ffe_1000;
const THUNK_RETURN_OFFSET: u64 = 0x1f;
const RAW_TARGET_TAG: u64 = 1 << 63;

// Exact saved frame constructed by dispatcher_bridge before changing stacks.
#[repr(C)]
struct DispatcherFrame {
    registers: [u64; 15], // R15..RAX, as pushed by the bridge.
    flags: u64,
    xmm: [[u64; 2]; 16],
    target: u64,
    return_address: u64,
}

const _: () = assert!(
    core::mem::offset_of!(DispatcherFrame, flags) == 0x78
        && core::mem::offset_of!(DispatcherFrame, xmm) == 0x80
        && core::mem::offset_of!(DispatcherFrame, target) == 0x180
        && core::mem::offset_of!(DispatcherFrame, return_address) == 0x188
        && core::mem::size_of::<DispatcherFrame>() == 0x190
);

static ORIGINAL_DISPATCHER: AtomicU64 = AtomicU64::new(0);
static BRIDGE_INSTALLED: AtomicBool = AtomicBool::new(false);
static BRIDGE_INSTALL_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static BRIDGE_INSTALL_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
}

fn log(message: &'static core::ffi::CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn log_hex(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_hex(prefix.as_ptr(), value) };
}

fn log_install_failure() {
    if !BRIDGE_INSTALL_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"artifact dispatcher bridge install failed");
    }
}

/// The stub entry whose call returns to `return_address`.
fn stub_for_return(return_address: u64) -> Option<u64> {
    return_address
        .checked_sub(THUNK_RETURN_OFFSET)
        .filter(|&stub| stub != 0)
}

/// Recognize Wine's CALL-through-KUSER thunk. The service, SystemCall branch,
/// and CALL slot must all belong to this same stub.
fn find_artifact_wine_syscall(return_address: u64, service: u64) -> Option<u64> {
    let start = stub_for_return(return_address)?;
    let service = u32::try_from(service).ok()?;
    let mut code = [0u8; 32];
    if !read_memory(start, &mut code)
        || code[..4] != [0x4c, 0x8b, 0xd1, 0xb8]
        || code[4..8] != service.to_le_bytes()
        || code[8..0x15]
            != [
                0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3,
            ]
        || code[0x15..]
            != [
                0xeb, 0x01, 0xc3, 0xff, 0x14, 0x25, 0x00, 0x10, 0xfe, 0x7f, 0xc3,
            ]
    {
        return None;
    }
    start.checked_add(0x12)
}

/// The KUSER dispatcher bridge's Rust selector, called from
/// [`dispatcher_bridge`]'s naked-asm trampoline on a private per-thread stack.
unsafe extern "C" fn dispatcher_target(
    return_address: u64,
    service: u64,
    saved_frame: *mut c_void,
    xmm5: u64,
    entry_rsp: u64,
) -> u64 {
    let original = ORIGINAL_DISPATCHER.load(Ordering::Acquire);
    let artifact = crate::artifact::active() && crate::artifact::syscall_target().is_some();
    // SAFETY: dispatcher_bridge saved the complete, exclusively owned
    // frame before switching to the selector's private stack.
    let frame = unsafe { &mut *saved_frame.cast::<DispatcherFrame>() };
    unsafe {
        dispatcher_target_for_frame(
            return_address,
            service,
            entry_rsp,
            original,
            artifact,
            xmm5,
            frame,
        )
    }
}

unsafe fn dispatcher_target_for_process(
    return_address: u64,
    service: u64,
    entry_rsp: u64,
    original: u64,
    artifact: bool,
) -> u64 {
    let _dispatch_guard = unsafe { crate::artifact::wine_dispatch_guard() };
    if !artifact || original == 0 {
        return original;
    }
    let trap_rsp = entry_rsp.saturating_add(8);
    super::flags::retire(trap_rsp);

    let Some(raw) = find_artifact_wine_syscall(return_address, service) else {
        return original;
    };
    let trap_rip = raw.saturating_add(2);
    if !super::flags::reserve(trap_rsp, trap_rip) {
        const MESSAGE: &[u8] = b"pingu-hook: ART syscall flag storage unavailable\n";
        unsafe {
            libc::write(libc::STDERR_FILENO, MESSAGE.as_ptr().cast(), MESSAGE.len());
            libc::_exit(127);
        }
    }
    raw | RAW_TARGET_TAG
}

unsafe fn dispatcher_target_for_frame(
    return_address: u64,
    service: u64,
    entry_rsp: u64,
    original: u64,
    artifact: bool,
    xmm5: u64,
    frame: &mut DispatcherFrame,
) -> u64 {
    if artifact && original != 0 && crate::artifact::is_syscall_bypass(xmm5) {
        let service = u64::from(service as u32);
        frame.registers[14] = service;
        frame.xmm[4] = [service, 0];
        frame.xmm[5] = [0, 0];
        return original;
    }
    unsafe { dispatcher_target_for_process(return_address, service, entry_rsp, original, artifact) }
}

/// Private stacks for the bridge's Rust selector, one slot per Windows thread
/// id (`TEB.ClientId.UniqueThread`, a multiple of four). The first word of a
/// slot is a spin lock, so two threads that share a slot only serialize. The
/// array lives in `.bss`, so only the pages a thread actually uses are ever
/// committed.
const BRIDGE_STACK_SLOTS: usize = 1024;
const BRIDGE_STACK_SHIFT: usize = 15;

#[repr(C, align(4096))]
struct BridgeStacks([u8; BRIDGE_STACK_SLOTS << BRIDGE_STACK_SHIFT]);

static mut BRIDGE_STACKS: BridgeStacks =
    BridgeStacks([0; BRIDGE_STACK_SLOTS << BRIDGE_STACK_SHIFT]);

/// Wine's KUSER dispatcher slot trampoline. Saves every register a Windows
/// syscall stub's caller could observe, runs [`dispatcher_target`] on a
/// private per-thread stack (see the field comment on `BRIDGE_STACKS`), and
/// restores everything before jumping to the chosen target, preserving ABI
/// parity on the direct-replay path.
#[unsafe(naked)]
unsafe extern "C" fn dispatcher_bridge() {
    core::arch::naked_asm!(
        "lea rsp, [rsp - 0x108]",
        "movdqu [rsp + 0x00], xmm0", "movdqu [rsp + 0x10], xmm1", "movdqu [rsp + 0x20], xmm2", "movdqu [rsp + 0x30], xmm3",
        "movdqu [rsp + 0x40], xmm4", "movdqu [rsp + 0x50], xmm5", "movdqu [rsp + 0x60], xmm6", "movdqu [rsp + 0x70], xmm7",
        "movdqu [rsp + 0x80], xmm8", "movdqu [rsp + 0x90], xmm9", "movdqu [rsp + 0xa0], xmm10", "movdqu [rsp + 0xb0], xmm11",
        "movdqu [rsp + 0xc0], xmm12", "movdqu [rsp + 0xd0], xmm13", "movdqu [rsp + 0xe0], xmm14", "movdqu [rsp + 0xf0], xmm15",
        "pushfq", "push rax", "push rbx", "push rcx", "push rdx", "push rsi", "push rdi", "push rbp", "push r8", "push r9", "push r10", "push r11", "push r12", "push r13", "push r14", "push r15",
        "mov rbx, rsp",
        "mov rdi, [rbx + 0x188]", "mov rsi, [rbx + 0x70]", "mov rdx, rbx", "mov rcx, [rbx + 0xd0]", "lea r8, [rbx + 0x188]",
        // Run the Rust selector on a private per-thread stack. Everything
        // above this point is spilled to the Windows stack inside a fixed
        // 0x190-byte frame, like the Reflex handler itself; the selector's
        // much deeper call frames must not scribble further below the caller's
        // stack pointer, which Denuvo's VM reads back as scratch. A syscall
        // never touches user stack on Windows. All registers are already saved
        // in the frame, so RAX and R15 are free (R15 is callee-saved and holds
        // the stack slot across the call).
        "lea r15, [rip + {stacks}]",
        "mov rax, gs:[0x48]",
        "shr rax, 2",
        "and eax, {slot_mask}",
        "shl rax, {slot_shift}",
        "add r15, rax",
        "3:",
        "lock bts dword ptr [r15], 0",
        "jnc 4f",
        "pause",
        "jmp 3b",
        "4:",
        "lea rsp, [r15 + {slot_size}]",
        "call {target}",
        "mov dword ptr [r15], 0",
        "mov rsp, rbx", "mov [rsp + 0x180], rax",
        "mov r15, [rsp + 0x00]", "mov r14, [rsp + 0x08]", "mov r13, [rsp + 0x10]", "mov r12, [rsp + 0x18]", "mov r11, [rsp + 0x20]", "mov r10, [rsp + 0x28]", "mov r9, [rsp + 0x30]", "mov r8, [rsp + 0x38]", "mov rbp, [rsp + 0x40]", "mov rdi, [rsp + 0x48]", "mov rsi, [rsp + 0x50]", "mov rdx, [rsp + 0x58]", "mov rcx, [rsp + 0x60]", "mov rbx, [rsp + 0x68]", "mov rax, [rsp + 0x70]",
        "push qword ptr [rsp + 0x78]", "popfq",
        "movdqu xmm0, [rsp + 0x80]", "movdqu xmm1, [rsp + 0x90]", "movdqu xmm2, [rsp + 0xa0]", "movdqu xmm3, [rsp + 0xb0]", "movdqu xmm4, [rsp + 0xc0]", "movdqu xmm5, [rsp + 0xd0]", "movdqu xmm6, [rsp + 0xe0]", "movdqu xmm7, [rsp + 0xf0]", "movdqu xmm8, [rsp + 0x100]", "movdqu xmm9, [rsp + 0x110]", "movdqu xmm10, [rsp + 0x120]", "movdqu xmm11, [rsp + 0x130]", "movdqu xmm12, [rsp + 0x140]", "movdqu xmm13, [rsp + 0x150]", "movdqu xmm14, [rsp + 0x160]", "movdqu xmm15, [rsp + 0x170]",
        // The two exits below land rsp one word apart (0x190 vs. 0x188) on
        // purpose, to account for the KUSER call's extra stack word.
        // `[rsp+0x188]` here is
        // `entry_rsp`: the value RSP held at the moment this trampoline was
        // entered, which is where the ntdll stub's own `call
        // [dispatcher_slot]` pushed its return address (call it
        // RET_ADDR — the address of the stub's own trailing `ret`).
        // `[entry_rsp+8]` is one call frame further out: whatever the stub
        // itself would eventually return to, once *its* `ret` runs.
        //
        // Ordinary path (2:, target = Wine's real dispatcher): this is a
        // tail call, so RSP must be exactly `entry_rsp` with RET_ADDR still
        // at `[rsp]` — Wine's dispatcher runs as a normal called function,
        // eventually does its own `ret`, consumes RET_ADDR, and lands back
        // on the stub's trailing `ret`, which then consumes `[entry_rsp+8]`
        // and returns to the stub's real caller. Two `ret`s total, matching
        // a real `call [dispatcher]; ret` sequence.
        //
        // Tagged path (target = a raw `syscall` instruction found by
        // `find_syscall`, tag bit cleared above): there is no dispatcher
        // call to unwind here — the whole point is to emulate the direct
        // route, where the stub's own inline `test;jne;syscall;ret` runs
        // with no KUSER dispatcher call in between at all. The instruction
        // right after any such `syscall` is always that same `ret` (it's
        // part of the fixed head+branch signature `pe_stub_layout.rs`
        // matches on, so this holds for Reflex's copied stub too). For that
        // one `ret` to consume `[entry_rsp+8]` directly — skipping RET_ADDR
        // entirely, since in the direct route it never existed — RSP must
        // already be `entry_rsp+8` before the jump. Hence `0x190`/`-0x10`
        // instead of `0x188`/`-8`: one extra word, for the one dispatcher
        // call this path never actually makes.
        "bt qword ptr [rsp + 0x180], 63", "jnc 2f", "btr qword ptr [rsp + 0x180], 63",
        "and qword ptr [rsp + 0x78], {clear_flags}", "or qword ptr [rsp + 0x78], {set_flags}", "push qword ptr [rsp + 0x78]", "popfq",
        "lea rsp, [rsp + 0x190]", "jmp qword ptr [rsp - 0x10]",
        "2:", "push qword ptr [rsp + 0x78]", "popfq", "lea rsp, [rsp + 0x188]", "jmp qword ptr [rsp - 8]",
        target = sym dispatcher_target,
        stacks = sym BRIDGE_STACKS,
        slot_mask = const BRIDGE_STACK_SLOTS - 1,
        slot_shift = const BRIDGE_STACK_SHIFT,
        slot_size = const 1usize << BRIDGE_STACK_SHIFT,
        clear_flags = const -0x882i32,
        set_flags = const 0x44u32,
    );
}

fn dispatcher_page_protection(page: u64, size: u64) -> Option<libc::c_int> {
    let end = page.checked_add(size)?;
    let mut protection = None;
    crate::maps::find_line(|line| {
        let Some(mapping) = crate::maps::parse(line) else {
            return false;
        };
        if mapping.start > page || mapping.end < end {
            return false;
        }
        let permissions = mapping.permissions;
        if permissions.len() != 4
            || permissions[0] != b'r'
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
            || !matches!(permissions[3], b'p' | b's')
        {
            return true;
        }
        let mut flags = libc::PROT_READ;
        if permissions[1] == b'w' {
            flags |= libc::PROT_WRITE;
        }
        if permissions[2] == b'x' {
            flags |= libc::PROT_EXEC;
        }
        protection = Some(flags);
        true
    });
    protection
}

/// The caller holds `PageGuard` and has prepared the ART page, if applicable.
unsafe fn swap_dispatcher_slot(
    slot: *mut u64,
    bridge: u64,
    original: &AtomicU64,
    expected_original: Option<u64>,
) -> bool {
    let address = slot as u64;
    let size = pingu_protocol::PAGE_SIZE as u64;
    let page = address & !(size - 1);
    let Some(page_end) = page.checked_add(size) else {
        return false;
    };
    if address == 0
        || !address.is_multiple_of(8)
        || address.checked_add(8).is_none_or(|end| end > page_end)
    {
        return false;
    }
    let Some(protection) = dispatcher_page_protection(page, size) else {
        return false;
    };
    let change_protection = protection & libc::PROT_WRITE == 0;
    if change_protection
        && unsafe {
            libc::mprotect(
                page as *mut c_void,
                size as usize,
                protection | libc::PROT_WRITE,
            )
        } != 0
    {
        return false;
    }
    let observed = unsafe { slot.read_volatile() };
    let installed = observed != 0
        && observed != bridge
        && expected_original.is_none_or(|expected| observed == expected);
    let previous_original = original.load(Ordering::Acquire);
    let already_installed = observed == bridge && previous_original != 0;
    if installed {
        original.store(observed, Ordering::Release);
        unsafe { slot.write_volatile(bridge) };
    }
    let restored = !change_protection
        || unsafe { libc::mprotect(page as *mut c_void, size as usize, protection) } == 0;
    if !restored {
        if installed {
            // The failed restore leaves the page writable. Do not leave a
            // bridge installed when its installation was reported as failed.
            unsafe { slot.write_volatile(observed) };
            original.store(previous_original, Ordering::Release);
        }
        return false;
    }
    installed || already_installed
}

/// Swap Wine's KUSER dispatcher slot for [`dispatcher_bridge`]. Idempotent;
/// safe to call repeatedly until Wine has populated the slot (see the retry
/// note in `kuser.rs::pingu_setup_kuser`).
pub(super) fn install() -> bool {
    let verify_slot = crate::artifact::detected();
    let slot = WINE_DISPATCHER_SLOT as *mut u64;
    let bridge = dispatcher_bridge as *const () as u64;
    if BRIDGE_INSTALLED.load(Ordering::Acquire) {
        if !verify_slot {
            return true;
        }
        if ORIGINAL_DISPATCHER.load(Ordering::Acquire) != 0
            && read_u64(WINE_DISPATCHER_SLOT) == Some(bridge)
        {
            return true;
        }
    }
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        log_install_failure();
        return false;
    };
    let cached = BRIDGE_INSTALLED.load(Ordering::Acquire);
    if cached && !verify_slot {
        return true;
    }
    let known_original = ORIGINAL_DISPATCHER.load(Ordering::Acquire);
    if cached && verify_slot {
        match read_u64(WINE_DISPATCHER_SLOT) {
            Some(value) if value == bridge && known_original != 0 => return true,
            Some(value) if value == known_original && known_original != 0 => {}
            _ => {
                log_install_failure();
                return false;
            }
        }
    }
    let expected_original = (verify_slot && known_original != 0).then_some(known_original);
    if unsafe { swap_dispatcher_slot(slot, bridge, &ORIGINAL_DISPATCHER, expected_original) } {
        BRIDGE_INSTALLED.store(true, Ordering::Release);
        if !BRIDGE_INSTALL_SUCCESS_LOGGED.swap(true, Ordering::AcqRel) {
            log(c"artifact dispatcher bridge installed");
            log_hex(
                c"artifact bridge original Wine dispatcher=",
                ORIGINAL_DISPATCHER.load(Ordering::Acquire),
            );
        }
        true
    } else {
        log_install_failure();
        false
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(miri))]
    struct WineCallStub {
        code: Box<[u8; 256]>,
        stack: Box<[u64; 2]>,
    }

    #[cfg(not(miri))]
    impl WineCallStub {
        const START: usize = 128;
        const SERVICE: u64 = 0x246;
        const ORIGINAL: u64 = 0x1122_3344_5566;

        fn new() -> Self {
            let mut code = Box::new([0x90; 256]);
            code[Self::START..Self::START + 32].copy_from_slice(&[
                0x4c, 0x8b, 0xd1, 0xb8, 0x46, 0x02, 0x00, 0x00, 0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe,
                0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3, 0xeb, 0x01, 0xc3, 0xff, 0x14, 0x25, 0x00,
                0x10, 0xfe, 0x7f, 0xc3,
            ]);
            let return_address = unsafe { code.as_ptr().add(Self::START + 0x1f) } as u64;
            let stack = Box::new([return_address, 0x7766_5544_3322]);
            Self { code, stack }
        }

        fn select(&self, service: u64, original: u64, artifact: bool) -> u64 {
            unsafe {
                super::dispatcher_target_for_process(
                    self.stack[0],
                    service,
                    self.stack.as_ptr() as u64,
                    original,
                    artifact,
                )
            }
        }

        fn raw_address(&self) -> u64 {
            (unsafe { self.code.as_ptr().add(Self::START + 0x12) }) as u64
        }
    }

    #[cfg(not(miri))]
    fn bypass_frame() -> super::DispatcherFrame {
        super::DispatcherFrame {
            registers: [0xa1a2_a3a4_a5a6_a7a8; 15],
            flags: 0x247,
            xmm: [[0x1122_3344_5566_7788, 0x8877_6655_4433_2211]; 16],
            target: 0,
            return_address: 0,
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_ordinary_bypass_uses_original_for_canonical_and_unknown_callers() {
        let fixture = WineCallStub::new();
        let marker = pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC;
        let return_address = fixture.stack[0];
        for (caller, service) in [
            (return_address, WineCallStub::SERVICE),
            (1, 0x1234_5678_0000_0246),
        ] {
            let mut frame = bypass_frame();
            frame.registers[14] = service;
            frame.xmm[5] = [marker, 0xfeed_face_dead_beef];
            let original_registers = frame.registers;
            let original_xmm = frame.xmm;
            let selected = unsafe {
                super::dispatcher_target_for_frame(
                    caller,
                    service,
                    fixture.stack.as_ptr() as u64,
                    WineCallStub::ORIGINAL,
                    true,
                    marker,
                    &mut frame,
                )
            };
            assert_eq!(
                selected,
                WineCallStub::ORIGINAL,
                "a bypass must never replay raw SYSCALL"
            );
            let mut expected_registers = original_registers;
            expected_registers[14] = 0x246;
            assert_eq!(frame.registers, expected_registers);
            assert_eq!(frame.flags, 0x247);
            for (index, expected) in original_xmm.iter().enumerate() {
                assert_eq!(
                    frame.xmm[index],
                    match index {
                        4 => [0x246, 0],
                        5 => [0, 0],
                        _ => *expected,
                    }
                );
            }
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_ordinary_bypass_does_not_retire_a_pending_outer_flag_frame() {
        let fixture = WineCallStub::new();
        let stack = fixture.stack.as_ptr() as u64 + 8;
        let rip = fixture.raw_address() + 2;
        assert!(super::super::flags::reserve(stack, rip));
        super::super::flags::route(stack, rip, 0x8d7, 0x202);
        let marker = pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC;
        let mut frame = bypass_frame();
        frame.xmm[5] = [marker, 0xfeed_face_dead_beef];
        unsafe {
            super::dispatcher_target_for_frame(
                fixture.stack[0],
                WineCallStub::SERVICE,
                fixture.stack.as_ptr() as u64,
                WineCallStub::ORIGINAL,
                true,
                marker,
                &mut frame,
            );
        }
        let saved = super::super::flags::bypass(stack, rip)
            .expect("ordinary bypass must not retire or reserve raw replay state");
        assert_eq!((saved.r11, saved.eflags), (0x8d7, 0x202));
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_ordinary_bypass_leaves_non_target_and_unmarked_frames_unchanged() {
        let fixture = WineCallStub::new();
        for (artifact, marker) in [
            (false, pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC),
            (true, 0x1337_1337_1337_1337),
        ] {
            let mut frame = bypass_frame();
            frame.xmm[5][0] = marker;
            let (registers, xmm, flags) = (frame.registers, frame.xmm, frame.flags);
            let selected = unsafe {
                super::dispatcher_target_for_frame(
                    1,
                    0x1234_5678_0000_0246,
                    fixture.stack.as_ptr() as u64,
                    WineCallStub::ORIGINAL,
                    artifact,
                    marker,
                    &mut frame,
                )
            };
            assert_eq!(selected, WineCallStub::ORIGINAL);
            assert_eq!(
                (frame.registers, frame.xmm, frame.flags),
                (registers, xmm, flags)
            );
        }
    }

    #[cfg(not(miri))]
    #[unsafe(naked)]
    unsafe extern "C" fn owned_bypass_original_dispatcher() {
        // Owned original-dispatcher stand-in records its actual incoming
        // state and returns a real, read-only Linux getpid result.
        core::arch::naked_asm!(
            "mov [rdi], rax",
            "mov [rdi + 8], rcx",
            "mov [rdi + 16], r11",
            "mov [rdi + 24], rsp",
            "pushfq",
            "pop qword ptr [rdi + 32]",
            "movdqu [rdi + 40], xmm4",
            "movdqu [rdi + 56], xmm5",
            "mov eax, 39",
            "syscall",
            "ret",
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_ordinary_bypass_machine_bridge_preserves_real_outcome_flags_and_stack() {
        const CHILD: &str = "PINGU_UNIT_ORDINARY_BYPASS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .env(CHILD, "1")
                .env("PINGU_HOOK_PATH", "artifact")
                .args(["--exact", "artifact::syscall::kuser_dispatch::tests::artifact_ordinary_bypass_machine_bridge_preserves_real_outcome_flags_and_stack", "--test-threads=1"])
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let mut teb = [0u64; 0x80];
        teb[0x48 / 8] = 0x1a0;
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, teb.as_mut_ptr()) },
            0
        );
        crate::artifact::mark_detected();
        crate::artifact::loader::arm_for_test();
        crate::artifact::cpuid(0x1337, 0, 1, pingu_protocol::cpuid::Vendor::Amd, false);
        crate::artifact::cpuid(
            0x336933,
            0x1234_0000,
            0,
            pingu_protocol::cpuid::Vendor::Amd,
            false,
        );
        assert!(crate::artifact::active());
        assert_eq!(crate::artifact::syscall_target(), Some(0x1234_0000));
        super::ORIGINAL_DISPATCHER.store(
            owned_bypass_original_dispatcher as *const () as u64,
            core::sync::atomic::Ordering::Release,
        );
        let mut capture = [0u64; 13];
        let marker = [
            pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC,
            0xfeed_face_dead_beef,
        ];
        unsafe {
            core::arch::asm!(
                "mov [rdi + 72], rsp",
                "push 0x247", "popfq", "pushfq", "pop qword ptr [rdi + 80]",
                "mov rax, 0x1234567800000246",
                "mov rcx, 0x1122334455667788", "mov r11, 0x8877665544332211",
                "movdqu xmm5, [rsi]", "call r12",
                "mov [rdi + 88], rsp", "mov [rdi + 96], rax",
                in("rdi") capture.as_mut_ptr(), in("rsi") marker.as_ptr(),
                in("r12") super::dispatcher_bridge as *const (),
                clobber_abi("C"),
            );
        }
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, 0usize) },
            0
        );
        assert_eq!(capture[0], 0x246);
        assert_eq!(capture[1], 0x1122_3344_5566_7788);
        assert_eq!(capture[2], 0x8877_6655_4433_2211);
        assert_eq!(capture[3], capture[9] - 8);
        assert_eq!(capture[4], capture[10]);
        assert_eq!(&capture[5..7], &[0x246, 0]);
        assert_eq!(&capture[7..9], &[0, 0]);
        assert_eq!(capture[9], capture[11]);
        assert_eq!(capture[12], unsafe { libc::getpid() } as u64);
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_dispatcher_replays_recognized_wine_call_stub_without_iat_match() {
        let fixture = WineCallStub::new();
        assert_eq!(
            fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true),
            fixture.raw_address() | super::RAW_TARGET_TAG,
        );
        assert_eq!(
            fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, false),
            WineCallStub::ORIGINAL,
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_dispatcher_roundtrip_and_reused_site() {
        use std::time::{Duration, Instant};

        const CHILD_ENV: &str = "PINGU_UNIT_ARTIFACT_ROUNDTRIP_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let fixture = WineCallStub::new();
            let mut signal_fixture = super::super::sigsys_router::artifact_tests::Fixture::new(2);
            let rsp = fixture.stack.as_ptr() as u64 + 8;
            let expected = fixture.raw_address();
            let recognized =
                super::find_artifact_wine_syscall(fixture.stack[0], WineCallStub::SERVICE)
                    == Some(expected);
            let selected = fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true);
            let status = if !recognized {
                12
            } else if selected != (expected | super::RAW_TARGET_TAG) {
                11
            } else {
                let outcome =
                    signal_fixture.saturated_roundtrip(rsp, expected + 2, WineCallStub::SERVICE);
                if outcome != 0 {
                    outcome
                } else if fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true)
                    != (expected | super::RAW_TARGET_TAG)
                {
                    20
                } else {
                    let repeated = signal_fixture.saturated_reused_site(
                        rsp,
                        expected + 2,
                        WineCallStub::SERVICE,
                    );
                    if repeated == 0 { 42 } else { repeated }
                }
            };
            unsafe { libc::_exit(status) };
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("artifact::syscall::kuser_dispatch::tests::artifact_dispatcher_roundtrip_and_reused_site")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .env("PINGU_HOOK_PATH", "artifact")
            .env_remove("PINGU_DEBUG")
            .env_remove("PINGU_LOG")
            .env_remove("WINEPREFIX")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("artifact roundtrip child timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(42));
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_dispatcher_reinstalls_after_raw_fork_rollback_without_overwriting_foreign_slot() {
        use core::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe { libc::alarm(8) };
            crate::artifact::mark_detected();
            super::BRIDGE_INSTALLED.store(false, Ordering::Release);
            super::ORIGINAL_DISPATCHER.store(0, Ordering::Release);
            let address = super::WINE_DISPATCHER_SLOT as *mut libc::c_void;
            let mapped = unsafe {
                libc::mmap(
                    address,
                    0x1000,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            if mapped != address {
                unsafe { libc::_exit(20) };
            }
            let slot = mapped.cast::<u64>();
            unsafe {
                core::ptr::write_bytes(mapped.cast::<u8>(), 0xa5, 0x1000);
                slot.write_volatile(WineCallStub::ORIGINAL);
            }
            if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ) } != 0 {
                unsafe { libc::_exit(21) };
            }
            let bridge = super::dispatcher_bridge as *const () as u64;
            if !super::install() || unsafe { slot.read_volatile() } != bridge {
                unsafe { libc::_exit(22) };
            }

            // Warm process-memory's PID before a raw fork between bridge
            // installation and provider commit. SYS_fork bypasses atfork.
            if crate::procmem::read_u64(super::WINE_DISPATCHER_SLOT) != Some(bridge) {
                unsafe { libc::_exit(34) };
            }
            let grandchild = unsafe { libc::syscall(libc::SYS_fork) } as libc::pid_t;
            if grandchild < 0 {
                unsafe { libc::_exit(23) };
            }
            if grandchild == 0 {
                unsafe { libc::alarm(5) };
                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ | libc::PROT_WRITE) }
                    != 0
                {
                    unsafe { libc::_exit(24) };
                }
                // Model the provider's child rollback of its staged page.
                unsafe { slot.write_volatile(WineCallStub::ORIGINAL) };
                let canary = unsafe { mapped.cast::<u8>().add(0x20).cast::<u32>() };
                let wrote_self = crate::procmem::write_u32(canary as u64, 0x4433_2211)
                    && unsafe { canary.read_volatile() } == 0x4433_2211;
                unsafe { canary.write_volatile(0xa5a5_a5a5) };
                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ) } != 0 {
                    unsafe { libc::_exit(25) };
                }
                let read_self = crate::procmem::read_u64(super::WINE_DISPATCHER_SLOT)
                    == Some(WineCallStub::ORIGINAL);
                let installed = super::install();
                if !read_self {
                    unsafe { libc::_exit(35) };
                }
                if !wrote_self {
                    unsafe { libc::_exit(36) };
                }
                if !installed || unsafe { slot.read_volatile() } != bridge {
                    unsafe { libc::_exit(26) };
                }
                if unsafe { mapped.cast::<u8>().add(0x20).read() } != 0xa5 {
                    unsafe { libc::_exit(27) };
                }

                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ | libc::PROT_WRITE) }
                    != 0
                {
                    unsafe { libc::_exit(28) };
                }
                let foreign = 0x3344_5566_7788u64;
                unsafe { slot.write_volatile(foreign) };
                if unsafe { libc::mprotect(mapped, 0x1000, libc::PROT_READ) } != 0 {
                    unsafe { libc::_exit(29) };
                }
                if super::install() || unsafe { slot.read_volatile() } != foreign {
                    unsafe { libc::_exit(30) };
                }
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            loop {
                let waited = unsafe { libc::waitpid(grandchild, &mut status, 0) };
                if waited == grandchild {
                    break;
                }
                if waited < 0 && unsafe { *libc::__errno_location() } != libc::EINTR {
                    unsafe { libc::_exit(31) };
                }
            }
            if !libc::WIFEXITED(status) {
                unsafe { libc::_exit(32) };
            }
            let result = libc::WEXITSTATUS(status);
            if result != 0 {
                unsafe { libc::_exit(result) };
            }
            if unsafe { slot.read_volatile() } != bridge
                || unsafe { mapped.cast::<u8>().add(0x20).read() } != 0xa5
            {
                unsafe { libc::_exit(33) };
            }
            unsafe { libc::_exit(0) };
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if waited == child {
                break;
            }
            if waited < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    panic!("waitpid failed: {error}");
                }
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(child, libc::SIGKILL);
                    libc::waitpid(child, &mut status, 0);
                }
                panic!("dispatcher install child timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            libc::WIFEXITED(status),
            "dispatcher child terminated: {status:#x}"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child status 26=rollback ignored, 30=foreign slot accepted, \
             35=raw-fork self-read used another PID, 36=raw-fork self-write \
             used another PID; 20-25,27-29,31-34=fixture/setup failures"
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_dispatcher_falls_back_for_wrong_service_signature_or_missing_wine_target() {
        let mut fixture = WineCallStub::new();
        assert_eq!(
            fixture.select(WineCallStub::SERVICE + 1, WineCallStub::ORIGINAL, true),
            WineCallStub::ORIGINAL
        );
        assert_eq!(fixture.select(WineCallStub::SERVICE, 0, true), 0);
        for offset in [0, 0x0b, 0x18, 0x1d] {
            let byte = WineCallStub::START + offset;
            fixture.code[byte] ^= 1;
            assert_eq!(
                fixture.select(WineCallStub::SERVICE, WineCallStub::ORIGINAL, true),
                WineCallStub::ORIGINAL,
                "corrupted Wine stub offset {offset:#x}",
            );
            fixture.code[byte] ^= 1;
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn artifact_dispatcher_install_preserves_mapping_permissions_and_unrelated_bytes() {
        use core::sync::atomic::{AtomicU64, Ordering};

        struct Page(*mut u8);
        impl Drop for Page {
            fn drop(&mut self) {
                unsafe { libc::munmap(self.0.cast(), 0x1000) };
            }
        }
        fn permissions(address: u64) -> String {
            std::fs::read_to_string("/proc/self/maps")
                .unwrap()
                .lines()
                .find_map(|line| {
                    let mut fields = line.split_whitespace();
                    let (start, end) = fields.next()?.split_once('-')?;
                    let start = u64::from_str_radix(start, 16).ok()?;
                    let end = u64::from_str_radix(end, 16).ok()?;
                    (start <= address && address < end).then(|| fields.next().unwrap().to_owned())
                })
                .expect("test page is mapped")
        }

        for (protection, expected) in [
            (libc::PROT_READ, "r--p"),
            (libc::PROT_READ | libc::PROT_WRITE, "rw-p"),
            (libc::PROT_READ | libc::PROT_EXEC, "r-xp"),
            (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, "rwxp"),
        ] {
            let mapping = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    0x1000,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            let page = Page(mapping.cast());
            let slot = unsafe { page.0.add(16).cast::<u64>() };
            unsafe {
                core::ptr::write_bytes(page.0, 0xa5, 0x1000);
                slot.write(0x1122_3344_5566_7788);
            }
            assert_eq!(unsafe { libc::mprotect(mapping, 0x1000, protection) }, 0);
            assert_eq!(permissions(page.0 as u64), expected);

            let saved = AtomicU64::new(0);
            assert!(unsafe {
                super::swap_dispatcher_slot(slot, 0x8877_6655_4433_2211, &saved, None)
            });
            assert_eq!(saved.load(Ordering::Acquire), 0x1122_3344_5566_7788);
            assert_eq!(unsafe { slot.read() }, 0x8877_6655_4433_2211);
            assert_eq!(permissions(page.0 as u64), expected);
            for offset in [0, 8, 24, 0xfff] {
                assert_eq!(unsafe { page.0.add(offset).read() }, 0xa5);
            }
        }
    }

    #[test]
    fn bridge_stack_slots_are_power_of_two_and_thread_id_indexable() {
        assert!(super::BRIDGE_STACK_SLOTS.is_power_of_two());
        // Windows thread ids advance by four, so shifting by two and masking
        // gives each of the first SLOTS threads its own stack.
        let slot = |tid: u64| (tid >> 2) as usize & (super::BRIDGE_STACK_SLOTS - 1);
        assert_ne!(slot(0x150), slot(0x154));
        assert_eq!(
            slot(0x150),
            slot(0x150 + 4 * super::BRIDGE_STACK_SLOTS as u64)
        );
        // Slots are 16-byte aligned and hold room for the selector's frames.
        const { assert!(1usize << super::BRIDGE_STACK_SHIFT >= 0x4000) };
    }

    #[cfg(not(miri))]
    extern "C" fn returning_dispatcher() {}

    // Actually executes `dispatcher_bridge` as real machine code via inline
    // asm, and `arch_prctl` has no libc wrapper so it must go through a raw
    // syscall Miri doesn't support either; Miri interprets MIR, not raw
    // instructions jumped to at runtime.
    #[cfg(not(miri))]
    #[test]
    fn bridge_selector_runs_off_the_callers_stack() {
        // The bridge reads the Windows thread id from gs:[0x48], so give this
        // thread a fake TEB. GS is per-thread and unused by the test harness.
        let result = std::thread::spawn(|| {
            let mut teb = [0u64; 0x20];
            teb[0x48 / 8] = 0x154;
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, teb.as_mut_ptr()) },
                0
            );
            super::ORIGINAL_DISPATCHER.store(
                returning_dispatcher as *const () as u64,
                core::sync::atomic::Ordering::SeqCst,
            );
            let bridge = super::dispatcher_bridge as *const () as u64;
            let mut untouched: u64;
            // Canary the 0x1000 bytes below the stack pointer, call the bridge
            // as a Windows syscall stub would, and check that only its own
            // fixed frame (0x190 bytes, plus the call's return address)
            // changed.
            unsafe {
                core::arch::asm!(
                    "sub rsp, 0x1000",
                    "mov rdi, rsp",
                    "mov ecx, 0x200",
                    "mov rax, 0xa5a5a5a5a5a5a5a5",
                    "cld",
                    "rep stosq",
                    "add rsp, 0x1000",
                    "mov eax, 0x19",
                    "call {bridge}",
                    "lea rdi, [rsp - 0x800]",
                    "mov ecx, 0xc0",
                    "mov rax, 0xa5a5a5a5a5a5a5a5",
                    "xor r8d, r8d",
                    "repe scasq",
                    "sete r8b",
                    bridge = in(reg) bridge,
                    out("r8") untouched,
                    out("rax") _,
                    out("rcx") _,
                    out("rdi") _,
                    clobber_abi("C"),
                );
            }
            let lock_released = unsafe {
                core::ptr::addr_of!(super::BRIDGE_STACKS)
                    .cast::<u32>()
                    .add((0x154 / 4) << 13)
                    .read_volatile()
            };
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, 0usize) },
                0
            );
            (untouched, lock_released)
        })
        .join()
        .unwrap();
        assert_eq!(
            result.0, 1,
            "the caller's stack below the frame was written"
        );
        assert_eq!(result.1, 0, "the slot lock was not released");
    }
}
