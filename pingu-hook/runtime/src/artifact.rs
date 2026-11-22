//! The Artifact path, selected by `PINGU_HOOK_PATH=artifact`. This file
//! coordinates the ARTIFACT session (registration, handler, readiness); the
//! submodules hold its loader support, CPUID trap handler, `KUSER_SHARED_DATA`
//! provider, syscall interception and the PE resolver bridge.

pub(crate) mod config;
pub(crate) mod cpuid;
pub(crate) mod entry;
pub(crate) mod kuser;
pub(crate) mod loader;
pub(crate) mod peb_heaps;
pub(crate) mod resolver;
pub(crate) mod seccomp;
pub(crate) mod syscall;

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use pingu_protocol::artifact::{CpuidAction, State};

struct SessionCoordinator {
    owner: AtomicI32,
    state: State,
}

impl SessionCoordinator {
    const fn new() -> Self {
        Self {
            owner: AtomicI32::new(0),
            state: State::new(),
        }
    }

    // A negative owner means one thread is clearing inherited state. Other
    // signal handlers must decline instead of waiting on that thread.
    fn claim(&self, pid: libc::pid_t) -> bool {
        if pid <= 0 {
            return false;
        }
        let owner = self.owner.load(Ordering::Acquire);
        if owner == pid {
            return true;
        }
        if owner == -pid
            || self
                .owner
                .compare_exchange(owner, -pid, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        self.state.after_fork();
        self.owner.store(pid, Ordering::Release);
        true
    }

    fn is_active(&self, pid: libc::pid_t) -> bool {
        pid > 0 && self.owner.load(Ordering::Acquire) == pid && self.state.has_target_process()
    }

    fn syscall_target(&self, pid: libc::pid_t) -> Option<u64> {
        if !self.is_active(pid) {
            return None;
        }
        self.state.route_syscall()
    }

    fn cpuid(
        &self,
        pid: libc::pid_t,
        leaf: u32,
        rcx: u64,
        rdx: u64,
        ready: bool,
        early_handler_allowed: bool,
    ) -> CpuidAction {
        if !self.claim(pid) {
            return CpuidAction::Native;
        }
        self.state
            .cpuid_from(leaf, rcx, rdx, ready, early_handler_allowed)
    }

    fn after_fork(&self) {
        self.owner.store(0, Ordering::Release);
        self.state.after_fork();
    }
}

static SESSION: SessionCoordinator = SessionCoordinator::new();
static INITIALIZING: AtomicI32 = AtomicI32::new(0);
static DETECTED: AtomicBool = AtomicBool::new(false);
static FSGSBASE_AVAILABLE: AtomicBool = AtomicBool::new(false);

fn trace_stage(message: &core::ffi::CStr) {
    #[cfg(feature = "debug")]
    unsafe {
        crate::debug::debug_log(message.as_ptr())
    };
    #[cfg(not(feature = "debug"))]
    let _ = message;
}

#[cfg(feature = "debug")]
static TRACED_PROTOCOL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn trace_protocol(bit: u32, message: &core::ffi::CStr) {
    #[cfg(feature = "debug")]
    if TRACED_PROTOCOL.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        trace_stage(message);
    }
    #[cfg(not(feature = "debug"))]
    let _ = (bit, message);
}

extern "C" fn initialize_capabilities() {
    // Linux exposes this bit only when userspace FSGSBASE is enabled.
    let available = unsafe { libc::getauxval(libc::AT_HWCAP2) } & 2 != 0;
    FSGSBASE_AVAILABLE.store(available, Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array.00101")]
static INITIALIZE_CAPABILITIES: extern "C" fn() = initialize_capabilities;

pub(crate) fn mark_detected() {
    DETECTED.store(true, Ordering::Release);
}

pub(crate) fn detected() -> bool {
    DETECTED.load(Ordering::Acquire)
}

pub(crate) fn active() -> bool {
    let Some(_guard) = (unsafe { wine_dispatch_guard() }) else {
        return false;
    };
    SESSION.is_active(unsafe { libc::getpid() })
}

pub(crate) fn syscall_target() -> Option<u64> {
    let _guard = unsafe { wine_dispatch_guard() }?;
    SESSION.syscall_target(unsafe { libc::getpid() })
}

/// The bypass value read from the registered handler's code; 0 until known.
static HANDLER_BYPASS: AtomicU64 = AtomicU64::new(0);

/// Whether XMM5's low quadword marks a syscall the Artifact handler let
/// through. Until the handler's own value is known, only the original
/// `SYSCALL_BYPASS_MAGIC` counts.
pub(crate) fn is_syscall_bypass(xmm5: u64) -> bool {
    xmm5 == selected_bypass(HANDLER_BYPASS.load(Ordering::Acquire))
}

/// The Intel identity the registered Artifact release's hypervisor presents:
/// the 0x1337-bypass releases report a different CPU from the 0x6969 ones.
pub(crate) fn intel_identity() -> pingu_protocol::artifact::cpu::IntelIdentity {
    identity_for(HANDLER_BYPASS.load(Ordering::Acquire))
}

fn identity_for(learned: u64) -> pingu_protocol::artifact::cpu::IntelIdentity {
    if learned == pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC_1337 {
        pingu_protocol::artifact::cpu::IntelIdentity::Pentium4425Y
    } else {
        pingu_protocol::artifact::cpu::IntelIdentity::Core
    }
}

fn selected_bypass(learned: u64) -> u64 {
    if learned == 0 {
        pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC
    } else {
        learned
    }
}

/// Record the bypass value the registered handler loads, once.
fn learn_handler_bypass(pid: libc::pid_t) {
    if HANDLER_BYPASS.load(Ordering::Acquire) != 0 {
        return;
    }
    let Some(target) = SESSION.syscall_target(pid) else {
        return;
    };
    let mut code = [0u8; 0x200];
    let Some(len) = [code.len(), 0x100, 0x80]
        .into_iter()
        .find(|len| crate::artifact::resolver::read_slice(target as usize, &mut code[..*len]))
    else {
        return;
    };
    let Some(value) = pingu_protocol::artifact::handler_bypass_magic(&code[..len]) else {
        return;
    };
    if HANDLER_BYPASS
        .compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        && value == pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC_1337
    {
        trace_protocol(0x100, c"ART handler uses the 0x1337 bypass");
    }
}

fn trace_generation() {
    if crate::artifact::config::artifact_generation()
        == pingu_protocol::artifact::profile::Generation::Vbs20
    {
        trace_protocol(0x400, c"ART VBS 2.0 profile selected");
    } else {
        trace_protocol(0x800, c"ART VBS 1.9 profile selected");
    }
}

/// `early_handler_allowed`: a handler leaf sent before registration may be
/// kept (the CPUID site is not a known non-Artifact module).
pub(crate) fn cpuid(
    leaf: u32,
    rcx: u64,
    rdx: u64,
    vendor: pingu_protocol::cpuid::Vendor,
    early_handler_allowed: bool,
) -> CpuidAction {
    // Register, handler and readiness are Artifact-only protocol leaves:
    // Artifact is running, so the loader boundary must already be armed.
    if matches!(leaf, 0x1337 | 0x336933 | 0x1338) {
        crate::artifact::loader::require_armed();
    }
    let Some(_guard) = (unsafe { wine_dispatch_guard() }) else {
        return CpuidAction::Native;
    };
    let pid = unsafe { libc::getpid() };
    if leaf == 0x1337 {
        trace_protocol(1, c"ART protocol register observed");
    }
    if matches!(leaf, 0x1337 | 0x336933 | 0x1338) {
        // From here on Artifact routes Windows syscalls through raw stubs that
        // rely on Wine's dispatch selector; trap any that slip past it.
        // Without an earlier dispatch trap this waits for the SIGSYS router.
        let _ = crate::artifact::seccomp::install_once();
    }
    if leaf == 0x336933 {
        trace_protocol(2, c"ART protocol handler observed");
        if !SESSION.is_active(pid) {
            trace_protocol(32, c"ART protocol handler arrived before register");
            if !early_handler_allowed {
                trace_protocol(128, c"ART protocol early handler ignored");
            }
        }
    }
    if leaf == 0x1338 {
        trace_protocol(16, c"ART protocol readiness requested");
    }
    if leaf == 0x1338 && SESSION.is_active(pid) {
        learn_handler_bypass(pid);
        crate::artifact::kuser::apply_profile(vendor);
        trace_generation();
    }
    let provider_ready = leaf == 0x1338 && crate::artifact::kuser::profile_ready();
    if leaf == 0x1338 && !provider_ready {
        trace_protocol(
            64,
            c"ART protocol readiness requested before the provider was ready",
        );
    }
    let action = SESSION.cpuid(pid, leaf, rcx, rdx, provider_ready, early_handler_allowed);
    if action == CpuidAction::Ready {
        trace_protocol(4, c"ART protocol readiness delivered");
    }
    if action == CpuidAction::Query {
        trace_protocol(8, c"ART protocol profile query observed");
    }
    if leaf == 0x1337 && SESSION.is_active(pid) {
        // Learn the handler's bypass as early as possible: the 0x1337-bypass
        // releases need it for their ready marker and Intel identity.
        learn_handler_bypass(pid);
        crate::artifact::kuser::apply_profile(vendor);
        trace_generation();
    }
    if matches!(leaf, 0x1337 | 0x336933) && SESSION.is_active(pid) {
        learn_handler_bypass(pid);
        if HANDLER_BYPASS.load(Ordering::Acquire)
            == pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC_1337
            && crate::artifact::kuser::publish_ready_marker()
        {
            trace_protocol(0x200, c"ART ready marker published");
        }
    }
    action
}

#[derive(Debug)]
pub(crate) enum InitializeError {
    UnsupportedGsBaseAccess,
    NotWineThread,
    Busy,
    Provider(crate::artifact::kuser::PrepareError),
    Dispatcher,
}

/// Only an ordinary Wine PE thread with an initialized TEB may call this.
/// All allocations and native worker creation finish before ART DllMain runs.
pub(crate) fn prepare() -> Result<(), InitializeError> {
    if !FSGSBASE_AVAILABLE.load(Ordering::Acquire) {
        return Err(InitializeError::UnsupportedGsBaseAccess);
    }
    mark_detected();
    let Some(_dispatch) = (unsafe { wine_dispatch_guard() }) else {
        return Err(InitializeError::NotWineThread);
    };
    trace_stage(c"ART prepare entered Wine context");
    let pid = unsafe { libc::getpid() };
    let previous = INITIALIZING.load(Ordering::Acquire);
    if previous == pid
        || INITIALIZING
            .compare_exchange(previous, pid, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return Err(InitializeError::Busy);
    }
    struct InitializationGuard;
    impl Drop for InitializationGuard {
        fn drop(&mut self) {
            INITIALIZING.store(0, Ordering::Release);
        }
    }
    let _initializing = InitializationGuard;
    if !SESSION.claim(pid) {
        return Err(InitializeError::Busy);
    }
    if crate::artifact::kuser::ready() {
        return Ok(());
    }
    trace_stage(c"ART prepare KUSER starting");
    crate::artifact::kuser::prepare().map_err(InitializeError::Provider)?;
    trace_stage(c"ART prepare KUSER completed");
    if let Err(error) = crate::artifact::kuser::prepare_dispatch_page() {
        crate::artifact::kuser::rollback().map_err(InitializeError::Provider)?;
        return Err(InitializeError::Provider(error));
    }
    trace_stage(c"ART prepare dispatcher starting");
    if !crate::artifact::syscall::install_wine_syscall_dispatcher_bridge() {
        crate::artifact::kuser::rollback().map_err(InitializeError::Provider)?;
        return Err(InitializeError::Dispatcher);
    }
    crate::artifact::kuser::commit();
    trace_stage(c"ART prepare completed");
    Ok(())
}

pub(crate) fn after_fork() {
    #[cfg(feature = "debug")]
    TRACED_PROTOCOL.store(0, Ordering::Relaxed);
    DETECTED.store(false, Ordering::Release);
    INITIALIZING.store(0, Ordering::Release);
    HANDLER_BYPASS.store(0, Ordering::Release);
    SESSION.after_fork();
    crate::artifact::kuser::after_fork();
}

pub(crate) struct SignalDispatchGuard(u8);

/// Scope Linux syscalls on a Wine thread in a positively attributed process.
/// RDGSBASE avoids issuing a denied syscall to find the TEB; Linux-only
/// workers have GS=0 and must never access gs:[0x340].
pub(crate) unsafe fn wine_dispatch_guard() -> Option<SignalDispatchGuard> {
    if !detected() || !FSGSBASE_AVAILABLE.load(Ordering::Acquire) {
        return None;
    }
    let gs: usize;
    unsafe {
        core::arch::asm!("rdgsbase {base}", base = out(reg) gs,
            options(nomem, nostack, preserves_flags));
    }
    if gs == 0 {
        return None;
    }
    let previous: u8;
    unsafe {
        core::arch::asm!(
            "mov {previous}, byte ptr gs:[0x340]",
            "mov byte ptr gs:[0x340], 0",
            previous = out(reg_byte) previous,
            options(nostack, preserves_flags),
        );
    }
    Some(SignalDispatchGuard(previous))
}

/// Put this thread's Wine dispatch selector back to BLOCK. Only for a thread
/// that just trapped from Windows code with the selector wrongly at ALLOW.
pub(crate) unsafe fn set_wine_dispatch_block() -> bool {
    if !FSGSBASE_AVAILABLE.load(Ordering::Acquire) {
        return false;
    }
    let gs: usize;
    unsafe {
        core::arch::asm!("rdgsbase {base}", base = out(reg) gs,
            options(nomem, nostack, preserves_flags));
    }
    if gs == 0 {
        return false;
    }
    unsafe {
        core::arch::asm!(
            "mov byte ptr gs:[0x340], 1",
            options(nostack, preserves_flags)
        );
    }
    true
}

impl Drop for SignalDispatchGuard {
    fn drop(&mut self) {
        unsafe {
            core::arch::asm!("mov byte ptr gs:[0x340], {previous}",
                previous = in(reg_byte) self.0, options(nostack, preserves_flags));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionCoordinator;
    use pingu_protocol::artifact::CpuidAction;

    #[test]
    fn raw_fork_child_rejects_parent_route_and_registers_a_fresh_session() {
        let session = SessionCoordinator::new();
        let parent = unsafe { libc::getpid() };
        session.cpuid(parent, 0x1337, 0, 0x174, false, false);
        session.cpuid(parent, 0x336933, 0x1111_0000, 0, false, false);
        assert!(session.is_active(parent));
        assert_eq!(session.syscall_target(parent), Some(0x1111_0000));

        let child = unsafe { libc::syscall(libc::SYS_fork) };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            let child_pid = unsafe { libc::getpid() };
            let inherited_rejected =
                !session.is_active(child_pid) && session.syscall_target(child_pid).is_none();
            let reset =
                session.cpuid(child_pid, 0x336967, 0, 0, false, false) == CpuidAction::Native;
            session.cpuid(child_pid, 0x1337, 0, 0x180, false, false);
            session.cpuid(child_pid, 0x336933, 0x2222_0000, 0, false, false);
            let registered = session.is_active(child_pid)
                && session.syscall_target(child_pid) == Some(0x2222_0000);
            let ready = crate::artifact::kuser::ready();
            let no_fake_ready = !ready
                && session.cpuid(child_pid, 0x1338, 0, 0, ready, false) == CpuidAction::Native;
            unsafe {
                libc::_exit(
                    if inherited_rejected && reset && registered && no_fake_ready {
                        0
                    } else {
                        1
                    },
                );
            }
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(child as libc::pid_t, &mut status, 0) },
            child as libc::pid_t
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert!(session.is_active(parent));
        assert_eq!(session.syscall_target(parent), Some(0x1111_0000));
    }
}

#[cfg(test)]
mod bypass_selection_tests {
    #[test]
    fn unknown_handler_keeps_the_original_bypass_value() {
        assert_eq!(
            super::selected_bypass(0),
            pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC
        );
        let anno = pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC_1337;
        assert_eq!(super::selected_bypass(anno), anno);
    }

    #[test]
    fn only_the_1337_handler_selects_the_pentium_identity() {
        use pingu_protocol::artifact::cpu::IntelIdentity;
        assert_eq!(super::identity_for(0), IntelIdentity::Core);
        assert_eq!(
            super::identity_for(pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC),
            IntelIdentity::Core
        );
        assert_eq!(
            super::identity_for(pingu_protocol::artifact::SYSCALL_BYPASS_MAGIC_1337),
            IntelIdentity::Pentium4425Y
        );
    }
}
