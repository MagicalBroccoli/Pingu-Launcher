//! ARTIFACT's PID-first CPUID handshake and syscall resume contract.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub mod cpu;
pub mod kuser;
pub mod profile;

pub const SYSCALL_BYPASS_MAGIC: u64 = 0x6969_6969_6969_6969;
/// Bypass value used by the Artifact build in Anno 117 (the Reflex value).
pub const SYSCALL_BYPASS_MAGIC_1337: u64 = 0x1337_1337_1337_1337;

/// The bypass value a registered Artifact handler loads into XMM5, read from
/// the first `movabs rax, imm64` in its code that holds a known value. Each
/// handler build uses exactly one of them.
pub fn handler_bypass_magic(code: &[u8]) -> Option<u64> {
    code.windows(10).find_map(|w| {
        if w[0] != 0x48 || w[1] != 0xb8 {
            return None;
        }
        let value = u64::from_le_bytes(w[2..10].try_into().unwrap());
        matches!(value, SYSCALL_BYPASS_MAGIC | SYSCALL_BYPASS_MAGIC_1337).then_some(value)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuidAction {
    Native,
    /// Ordinary CPUID query in a PID-registered ART session.
    Query,
    Zero,
    /// Write only RAX=1; all other incoming registers remain unchanged.
    Ready,
}

#[derive(Debug)]
pub struct State {
    target_pid: AtomicU64,
    /// First-wins handler. Some Artifact builds (Anno 117) announce it with
    /// 0x336933 before the 0x1337 registration, so it can be stored before a
    /// target PID exists; routing still requires a registered PID.
    callback: AtomicU64,
    ready_pending: AtomicBool,
}

impl State {
    pub const fn new() -> Self {
        Self {
            target_pid: AtomicU64::new(0),
            callback: AtomicU64::new(0),
            ready_pending: AtomicBool::new(false),
        }
    }

    /// `provider_ready` must describe the real process-private live provider.
    /// Registering a PID or callback alone never asserts provider readiness.
    pub fn cpuid(&self, leaf: u32, rcx: u64, rdx: u64, provider_ready: bool) -> CpuidAction {
        self.cpuid_from(leaf, rcx, rdx, provider_ready, false)
    }

    /// `early_handler_allowed` says whether a handler sent before the PID
    /// registration may be kept. The caller decides from the CPUID site.
    pub fn cpuid_from(
        &self,
        leaf: u32,
        rcx: u64,
        rdx: u64,
        provider_ready: bool,
        early_handler_allowed: bool,
    ) -> CpuidAction {
        match leaf {
            0x1337 if rdx != 0 => {
                if self
                    .target_pid
                    .compare_exchange(0, rdx, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.ready_pending.store(true, Ordering::Release);
                }
            }
            0x336933 if rcx != 0 && (early_handler_allowed || self.has_target_process()) => {
                let _ = self
                    .callback
                    .compare_exchange(0, rcx, Ordering::AcqRel, Ordering::Acquire);
            }
            0x336967 if self.has_target_process() => return CpuidAction::Zero,
            0x1338
                if self.has_target_process()
                    && provider_ready
                    && self.ready_pending.swap(false, Ordering::AcqRel) =>
            {
                return CpuidAction::Ready;
            }
            _ => {}
        }
        if self.has_target_process() && !matches!(leaf, 0x1337 | 0x336933 | 0x1338 | 0x336967) {
            CpuidAction::Query
        } else {
            CpuidAction::Native
        }
    }

    pub fn has_target_process(&self) -> bool {
        self.target_pid.load(Ordering::Acquire) != 0
    }

    pub fn route_syscall(&self) -> Option<u64> {
        if !self.has_target_process() {
            return None;
        }
        let target = self.callback.load(Ordering::Acquire);
        // `has_target_process` above already requires a registered PID.
        (target != 0).then_some(target)
    }

    /// The child has no provider worker and must register its own session.
    pub fn after_fork(&self) {
        self.callback.store(0, Ordering::Release);
        self.target_pid.store(0, Ordering::Release);
        self.ready_pending.store(false, Ordering::Release);
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{CpuidAction, State};

    #[test]
    fn pid_first_registration_routes_only_after_a_nonzero_callback() {
        let state = State::new();
        assert!(state.route_syscall().is_none());
        assert_eq!(
            state.cpuid(0x1337, 0xdead, 0x174, false),
            CpuidAction::Native
        );
        assert!(state.route_syscall().is_none());
        assert_eq!(state.cpuid(0x336933, 0, 0, false), CpuidAction::Native);
        assert!(state.route_syscall().is_none());
        assert_eq!(
            state.cpuid(0x336933, 0x6ffffa761000, 0, false),
            CpuidAction::Native
        );
        let target = state.route_syscall().expect("registered ART callback");
        assert_eq!(target, 0x6ffffa761000);
        state.cpuid(0x1337, 0, 0x999, true);
        state.cpuid(0x336933, 0x6ffffa762000, 0, true);
        assert_eq!(state.route_syscall(), Some(0x6ffffa761000));
    }

    #[test]
    fn readiness_waits_for_the_real_provider_and_is_consumed_once() {
        let state = State::new();
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, false);
        state.cpuid(0x336933, 0x6ffffa761000, 0, false);
        assert_eq!(state.cpuid(0x1338, 0, 0, false), CpuidAction::Native);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Ready);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, true);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
    }

    #[test]
    fn optional_control_is_zero_only_for_the_registered_process() {
        let state = State::new();
        assert_eq!(state.cpuid(0x336967, 0, 0, false), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, false);
        assert_eq!(state.cpuid(0x336967, 0, 0, false), CpuidAction::Zero);
    }

    #[test]
    fn cpu_profile_requires_pid_registration_and_ends_at_fork() {
        let state = State::new();
        assert_eq!(state.cpuid(1, 0, 0, false), CpuidAction::Native);
        state.cpuid(0x336933, 0x1234, 0, false);
        assert_eq!(state.cpuid(1, 0, 0, false), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, false);
        assert_eq!(state.cpuid(1, 0, 0, false), CpuidAction::Query);
        assert_eq!(state.cpuid(0x1338, 0, 0, false), CpuidAction::Native);
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Ready);
        assert_eq!(state.cpuid(1, 0, 0, true), CpuidAction::Query);
        assert_eq!(state.cpuid(0x336933, 0, 0, false), CpuidAction::Native);
        state.after_fork();
        assert_eq!(state.cpuid(1, 0, 0, true), CpuidAction::Native);
    }
}

#[cfg(test)]
mod order_tests {
    use super::{CpuidAction, State};

    #[test]
    fn a_handler_sent_before_registration_is_used_after_registration() {
        let state = State::new();
        assert_eq!(
            state.cpuid_from(0x336933, 0x6ffffa761000, 0, false, true),
            CpuidAction::Native
        );
        assert!(state.route_syscall().is_none());
        state.cpuid(0x1337, 0, 0x174, false);
        assert_eq!(state.route_syscall(), Some(0x6ffffa761000));
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Ready);
        state.cpuid_from(0x336933, 0x6ffffa762000, 0, false, true);
        assert_eq!(state.route_syscall(), Some(0x6ffffa761000));
    }

    #[test]
    fn an_untrusted_early_handler_is_ignored() {
        let state = State::new();
        state.cpuid_from(0x336933, 0xbad000, 0, false, false);
        state.cpuid(0x1337, 0, 0x174, false);
        assert!(state.route_syscall().is_none());
        state.cpuid(0x336933, 0x6ffffa761000, 0, false);
        assert_eq!(state.route_syscall(), Some(0x6ffffa761000));
    }

    #[test]
    fn a_zero_pid_registration_is_rejected() {
        let state = State::new();
        state.cpuid_from(0x336933, 0x6ffffa761000, 0, false, true);
        state.cpuid(0x1337, 0, 0, false);
        assert!(!state.has_target_process());
        assert!(state.route_syscall().is_none());
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x174, false);
        assert_eq!(state.route_syscall(), Some(0x6ffffa761000));
    }

    #[test]
    fn an_early_handler_does_not_survive_fork() {
        let state = State::new();
        state.cpuid_from(0x336933, 0x6ffffa761000, 0, false, true);
        state.after_fork();
        state.cpuid(0x1337, 0, 0x180, false);
        assert!(state.route_syscall().is_none());
    }
}

#[cfg(test)]
mod fork_tests {
    use super::{CpuidAction, State};

    #[test]
    fn fork_child_cannot_route_or_claim_the_parent_provider_readiness() {
        let state = State::new();
        state.cpuid(0x1337, 0, 0x174, false);
        state.cpuid(0x336933, 0x6ffffa761000, 0, false);
        assert!(state.route_syscall().is_some());
        state.after_fork();
        assert!(state.route_syscall().is_none());
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Native);
        state.cpuid(0x1337, 0, 0x180, true);
        assert!(state.route_syscall().is_none());
        assert_eq!(state.cpuid(0x1338, 0, 0, true), CpuidAction::Ready);
    }
}

#[cfg(test)]
mod handler_bypass_tests {
    use super::*;

    fn movabs(value: u64) -> [u8; 10] {
        let mut code = [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0];
        code[2..].copy_from_slice(&value.to_le_bytes());
        code
    }

    #[test]
    fn finds_the_value_each_known_handler_loads() {
        for value in [SYSCALL_BYPASS_MAGIC, SYSCALL_BYPASS_MAGIC_1337] {
            let other = if value == SYSCALL_BYPASS_MAGIC {
                SYSCALL_BYPASS_MAGIC_1337
            } else {
                SYSCALL_BYPASS_MAGIC
            };
            let mut code = [0u8; 38];
            code[..8].copy_from_slice(&[0x48, 0x89, 0xc1, 0x66, 0x41, 0x0f, 0x7e, 0xe3]);
            code[8..18].copy_from_slice(&movabs(0x1234_5678_9abc_def0));
            code[18..28].copy_from_slice(&movabs(value));
            code[28..].copy_from_slice(&movabs(other));
            assert_eq!(handler_bypass_magic(&code), Some(value));
        }
    }

    #[test]
    fn unknown_or_truncated_code_has_no_value() {
        assert_eq!(handler_bypass_magic(&movabs(0x4242_4242_4242_4242)), None);
        assert_eq!(
            handler_bypass_magic(&movabs(SYSCALL_BYPASS_MAGIC)[..9]),
            None
        );
        assert_eq!(handler_bypass_magic(&[]), None);
    }
}
