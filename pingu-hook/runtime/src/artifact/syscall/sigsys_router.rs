//! The SIGSYS boundary: pingu-hook's syscall-trap handler, installed by
//! `hooks.rs` alongside the CPUID SIGSEGV handler. Routes positively
//! registered Artifact `SYS_USER_DISPATCH` calls to Artifact's callback,
//! repairs leaked Windows syscalls trapped by `seccomp`, and
//! forwards everything else to Wine.

use core::ffi::{c_int, c_void};
use core::ptr;
use libc::siginfo_t;
use libc::ucontext_t;

const SYS_SECCOMP: c_int = 1;
const SYS_USER_DISPATCH: c_int = 2;

const _: () = assert!(
    core::mem::size_of::<libc::_libc_fpstate>() == 512
        && core::mem::offset_of!(libc::_libc_fpstate, _xmm) == 160
);

enum ArtifactFpState {
    Legacy,
    Xsave(*mut u64),
}

/// Validate within the fixed legacy prefix before accessing an XSAVE header.
/// The caller supplies a live kernel frame, including its declared extension.
unsafe fn artifact_fp_state(fp: *mut libc::_libc_fpstate) -> Option<ArtifactFpState> {
    let bytes = fp.cast::<u8>();
    // SAFETY: all three metadata words are inside the fixed 512-byte prefix.
    let (magic, extent, size) = unsafe {
        (
            bytes.add(464).cast::<u32>().read_unaligned(),
            bytes.add(468).cast::<u32>().read_unaligned(),
            bytes.add(480).cast::<u32>().read_unaligned(),
        )
    };
    if magic != 0x4650_5853 {
        return Some(ArtifactFpState::Legacy);
    }
    // Linux's extended size includes the trailing FP_XSTATE_MAGIC2 word;
    // xstate_size includes the entire 64-byte XSAVE header at offset 512.
    if extent < 580 || size < 576 || size > extent - 4 {
        return None;
    }
    Some(ArtifactFpState::Xsave(unsafe { bytes.add(512).cast() }))
}

unsafe fn publish_artifact_sse(state: &ArtifactFpState) {
    if let ArtifactFpState::Xsave(header) = state {
        // SAFETY: validated kernel metadata declares a complete XSAVE header.
        // Preserve every other component bit and all extended component data.
        unsafe { header.write_unaligned(header.read_unaligned() | 2) };
    }
}

unsafe extern "C" {
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
}

pub(crate) unsafe extern "C" fn syscallhook(
    sig: c_int,
    info: *mut siginfo_t,
    context: *mut c_void,
) {
    let _errno = crate::errno::Errno::save();
    let handled = if info.is_null() || context.is_null() {
        false
    } else {
        unsafe {
            let context = context.cast::<ucontext_t>();
            match ptr::addr_of!((*info).si_code).read() {
                SYS_USER_DISPATCH => crate::artifact::seccomp::note_dispatch_trap(),
                // A Windows syscall that leaked past dispatch: rewind it so
                // dispatch handles it. Must run before the guard below, whose
                // drop would restore the leaked ALLOW selector.
                SYS_SECCOMP if crate::artifact::seccomp::repair_leak(context) => return,
                _ => {}
            }
            let _dispatch_guard = crate::artifact::wine_dispatch_guard();
            let artifact_target = if crate::artifact::active() {
                crate::artifact::syscall_target()
            } else {
                None
            };
            // Artifact is active and this Wine uses dispatch: arm the trap.
            if artifact_target.is_some()
                && ptr::addr_of!((*info).si_code).read() == SYS_USER_DISPATCH
            {
                let _ = crate::artifact::seccomp::install_once();
            }
            redirect(info, context, artifact_target)
        }
    };
    if !handled {
        unsafe { forward_signal(sig, info, context) };
    }
}

unsafe fn redirect(
    info: *const siginfo_t,
    context: *mut ucontext_t,
    artifact_target: Option<u64>,
) -> bool {
    let Some(target) = artifact_target else {
        return false;
    };
    if info.is_null() || context.is_null() {
        return false;
    }
    let fpregs = unsafe { ptr::addr_of!((*context).uc_mcontext.fpregs).read() };
    if fpregs.is_null() {
        return false;
    }
    let code = unsafe { ptr::addr_of!((*info).si_code).read() };
    // ART's contract covers SUD only.
    if code != SYS_USER_DISPATCH {
        return false;
    }
    // Refuse malformed extended metadata before changing any registers.
    // Old-style FXSAVE needs no header write.
    let Some(artifact_fpstate) = (unsafe { artifact_fp_state(fpregs) }) else {
        return false;
    };
    let xmm = unsafe { ptr::addr_of_mut!((*fpregs)._xmm).cast::<[u8; 16]>() };
    let xmm5 = unsafe { xmm.add(5).read() };
    let gregs = unsafe { ptr::addr_of_mut!((*context).uc_mcontext.gregs).cast::<libc::greg_t>() };
    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() as u64 };
    let rsp = unsafe { gregs.add(libc::REG_RSP as usize).read() as u64 };
    let bypass =
        crate::artifact::is_syscall_bypass(u64::from_le_bytes(xmm5[..8].try_into().unwrap()));
    let service = unsafe { gregs.add(libc::REG_RAX as usize).read() as u32 };
    let mut xmm4 = [0u8; 16];
    xmm4[..4].copy_from_slice(&service.to_le_bytes());
    unsafe { xmm.add(4).write(xmm4) };
    unsafe { publish_artifact_sse(&artifact_fpstate) };

    if bypass {
        if let Some(saved) = super::flags::bypass(rsp, rip) {
            unsafe {
                gregs
                    .add(libc::REG_R11 as usize)
                    .write(saved.r11 as libc::greg_t);
                gregs
                    .add(libc::REG_EFL as usize)
                    .write(saved.eflags as libc::greg_t);
            }
        }
        unsafe {
            xmm.add(5).write([0; 16]);
            gregs
                .add(libc::REG_RAX as usize)
                .write(libc::greg_t::from(service));
        }
        return false;
    }

    super::flags::route(
        rsp,
        rip,
        unsafe { gregs.add(libc::REG_R11 as usize).read() as u64 },
        unsafe { gregs.add(libc::REG_EFL as usize).read() as u64 },
    );

    unsafe {
        let r11 = gregs.add(libc::REG_R11 as usize).read();
        gregs.add(libc::REG_EFL as usize).write(r11);
        gregs.add(libc::REG_RAX as usize).write(rip as libc::greg_t);
        gregs
            .add(libc::REG_RCX as usize)
            .write(target as libc::greg_t);
        gregs
            .add(libc::REG_RIP as usize)
            .write(target as libc::greg_t);
    }
    true
}

#[cfg(all(test, not(miri)))]
pub(in crate::artifact::syscall) mod artifact_tests {
    use super::{SYS_SECCOMP, SYS_USER_DISPATCH, redirect};
    use core::mem::MaybeUninit;
    use libc::{_libc_fpstate, greg_t, siginfo_t, ucontext_t};

    const TARGET: u64 = 0x1234_5678_9000;
    const SERVICE: u64 = 0x1357_9bdf_89ab_cdef;
    const ORIGINAL_XMM4: [u32; 4] = [0x4444_4444; 4];
    const ORIGINAL_XMM5: [u32; 4] = [0x5555_5555; 4];
    const ART_BYPASS: [u32; 4] = [0x6969_6969, 0x6969_6969, 0xaaaa_aaaa, 0xbbbb_bbbb];
    const UNKNOWN_BYPASS: [u32; 4] = [0x1337_1337, 0x1337_1337, 0xaaaa_aaaa, 0xbbbb_bbbb];

    #[repr(C, align(64))]
    struct ExtendedFpState {
        legacy: _libc_fpstate,
        upper_xstate: [u8; 1024],
    }

    pub(in crate::artifact::syscall) struct Fixture {
        info: siginfo_t,
        context: ucontext_t,
        fpstate: Box<ExtendedFpState>,
        stack: Box<[u64; 8]>,
        code: Box<[u8; 32]>,
    }

    impl Fixture {
        pub(in crate::artifact::syscall) fn new(code: i32) -> Self {
            let mut info = unsafe { MaybeUninit::<siginfo_t>::zeroed().assume_init() };
            info.si_code = code;
            let mut context = unsafe { MaybeUninit::<ucontext_t>::zeroed().assume_init() };
            let mut fpstate = Box::new(ExtendedFpState {
                legacy: unsafe { MaybeUninit::<_libc_fpstate>::zeroed().assume_init() },
                upper_xstate: [0xa6; 1024],
            });
            fpstate.legacy._xmm[4].element = ORIGINAL_XMM4;
            fpstate.legacy._xmm[5].element = ORIGINAL_XMM5;
            fpstate.legacy._xmm[6].element = [0x6666_6666; 4];
            context.uc_mcontext.fpregs = &mut fpstate.legacy;
            let stack = Box::new([
                0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
            ]);
            let mut instructions = Box::new([0x90; 32]);
            instructions[14..18].copy_from_slice(&[0x0f, 0x05, 0x0f, 0x05]);
            let registers = &mut context.uc_mcontext.gregs;
            registers[libc::REG_RIP as usize] = unsafe { instructions.as_ptr().add(16) } as greg_t;
            registers[libc::REG_RSP as usize] = stack.as_ptr() as greg_t;
            registers[libc::REG_RAX as usize] = SERVICE as greg_t;
            registers[libc::REG_RCX as usize] = 0x1234_4321;
            registers[libc::REG_RDX as usize] = 0x2222_aaaa;
            registers[libc::REG_R8 as usize] = 0x3333_bbbb;
            registers[libc::REG_R9 as usize] = 0x4444_cccc;
            registers[libc::REG_R10 as usize] = 0x1111_dddd;
            registers[libc::REG_R11 as usize] = 0x8d7;
            registers[libc::REG_EFL as usize] = 0x202;
            registers[libc::REG_RBX as usize] = 0x1234_abcd;
            registers[libc::REG_R12 as usize] = 0x5678_efab;
            Self {
                info,
                context,
                fpstate,
                stack,
                code: instructions,
            }
        }

        fn register(&self, index: i32) -> u64 {
            self.context.uc_mcontext.gregs[index as usize] as u64
        }

        fn route_art(&mut self, target: Option<u64>) -> bool {
            unsafe { redirect(&self.info, &mut self.context, target) }
        }

        pub(in crate::artifact::syscall) fn saturated_roundtrip(
            &mut self,
            rsp: u64,
            rip: u64,
            service: u64,
        ) -> i32 {
            self.info.si_code = SYS_USER_DISPATCH;
            let registers = &mut self.context.uc_mcontext.gregs;
            registers[libc::REG_RSP as usize] = rsp as greg_t;
            registers[libc::REG_RIP as usize] = rip as greg_t;
            registers[libc::REG_RAX as usize] = service as greg_t;
            registers[libc::REG_R11 as usize] = 0x8d7;
            registers[libc::REG_EFL as usize] = 0x202;
            self.fpstate.legacy._xmm[4].element = ORIGINAL_XMM4;
            self.fpstate.legacy._xmm[5].element = ORIGINAL_XMM5;
            let initial = self.context.uc_mcontext.gregs;

            if !unsafe { redirect(&self.info, &mut self.context, Some(TARGET)) } {
                return 13;
            }
            let mut expected = initial;
            expected[libc::REG_RAX as usize] = rip as greg_t;
            expected[libc::REG_RCX as usize] = TARGET as greg_t;
            expected[libc::REG_RIP as usize] = TARGET as greg_t;
            expected[libc::REG_EFL as usize] = 0x8d7;
            if self.context.uc_mcontext.gregs != expected
                || self.fpstate.legacy._xmm[4].element != [service as u32, 0, 0, 0]
                || self.fpstate.legacy._xmm[5].element != ORIGINAL_XMM5
            {
                return 14;
            }

            let child = unsafe { libc::fork() };
            if child < 0 {
                return 18;
            }
            if child == 0 {
                unsafe { libc::alarm(4) };
                self.context.uc_mcontext.gregs = initial;
                self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
                self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
                self.fpstate.legacy._xmm[5].element = ART_BYPASS;
                let own_registers = self.context.uc_mcontext.gregs;
                let forwarded = !unsafe { redirect(&self.info, &mut self.context, Some(TARGET)) };
                let unchanged = self.context.uc_mcontext.gregs == own_registers
                    && self.fpstate.legacy._xmm[4].element == [service as u32, 0, 0, 0]
                    && self.fpstate.legacy._xmm[5].element == [0; 4];
                unsafe { libc::_exit(if forwarded && unchanged { 42 } else { 19 }) };
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut status = 0;
            loop {
                let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
                if waited == child {
                    break;
                }
                if waited < 0 {
                    if unsafe { *libc::__errno_location() } == libc::EINTR {
                        continue;
                    }
                    return 19;
                }
                if std::time::Instant::now() >= deadline {
                    unsafe {
                        libc::kill(child, libc::SIGKILL);
                        libc::waitpid(child, &mut status, 0);
                    }
                    return 19;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 42 {
                return 19;
            }

            self.context.uc_mcontext.gregs = initial;
            self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
            self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
            self.fpstate.legacy._xmm[5].element = ART_BYPASS;
            if unsafe { redirect(&self.info, &mut self.context, Some(TARGET)) } {
                return 15;
            }
            if self.context.uc_mcontext.gregs != initial {
                return 16;
            }
            if self.fpstate.legacy._xmm[4].element != [service as u32, 0, 0, 0]
                || self.fpstate.legacy._xmm[5].element != [0; 4]
                || self.fpstate.legacy._xmm[6].element != [0x6666_6666; 4]
                || self.fpstate.upper_xstate != [0xa6; 1024]
            {
                return 17;
            }
            0
        }

        pub(in crate::artifact::syscall) fn saturated_reused_site(
            &mut self,
            rsp: u64,
            rip: u64,
            service: u64,
        ) -> i32 {
            self.info.si_code = SYS_USER_DISPATCH;
            let registers = &mut self.context.uc_mcontext.gregs;
            registers[libc::REG_RSP as usize] = rsp as greg_t;
            registers[libc::REG_RIP as usize] = rip as greg_t;
            registers[libc::REG_RAX as usize] = service as greg_t;
            registers[libc::REG_R11 as usize] = 0x8d7;
            registers[libc::REG_EFL as usize] = 0x202;
            self.fpstate.legacy._xmm[5].element = ORIGINAL_XMM5;
            let first = self.context.uc_mcontext.gregs;
            if !unsafe { redirect(&self.info, &mut self.context, Some(TARGET)) } {
                return 20;
            }

            self.context.uc_mcontext.gregs = first;
            self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x246;
            self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x206;
            let second = self.context.uc_mcontext.gregs;
            if !unsafe { redirect(&self.info, &mut self.context, Some(TARGET)) } {
                return 21;
            }
            self.context.uc_mcontext.gregs = second;
            self.context.uc_mcontext.gregs[libc::REG_R11 as usize] = 0x111;
            self.context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x222;
            self.fpstate.legacy._xmm[5].element = ART_BYPASS;
            if unsafe { redirect(&self.info, &mut self.context, Some(TARGET)) } {
                return 22;
            }
            if self.context.uc_mcontext.gregs != second {
                return 23;
            }
            if self.fpstate.legacy._xmm[4].element != [service as u32, 0, 0, 0]
                || self.fpstate.legacy._xmm[5].element != [0; 4]
            {
                return 24;
            }
            0
        }

        fn assert_unrelated_fpstate_unchanged(&self) {
            assert_eq!(self.fpstate.legacy._xmm[6].element, [0x6666_6666; 4]);
            assert_eq!(self.fpstate.upper_xstate, [0xa6; 1024]);
        }
    }

    #[test]
    fn artifact_callback_uses_post_syscall_rip_and_fresh_xmm4_without_touching_arguments() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        let initial = fixture.context.uc_mcontext.gregs;
        let stack = *fixture.stack;
        assert!(fixture.route_art(Some(TARGET)));

        let mut expected = initial;
        expected[libc::REG_RAX as usize] = initial[libc::REG_RIP as usize];
        expected[libc::REG_RCX as usize] = TARGET as greg_t;
        expected[libc::REG_RIP as usize] = TARGET as greg_t;
        expected[libc::REG_EFL as usize] = initial[libc::REG_R11 as usize];
        assert_eq!(fixture.context.uc_mcontext.gregs, expected);
        assert_eq!(*fixture.stack, stack);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, ORIGINAL_XMM5);
        fixture.assert_unrelated_fpstate_unchanged();
        assert_eq!(fixture.code[16..18], [0x0f, 0x05]);
    }

    #[test]
    fn artifact_bypass_forwards_service32_and_clears_only_xmm5() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        let mut expected = fixture.context.uc_mcontext.gregs;
        expected[libc::REG_RAX as usize] = 0x89ab_cdef;
        let stack = *fixture.stack;
        assert!(!fixture.route_art(Some(TARGET)));

        assert_eq!(fixture.context.uc_mcontext.gregs, expected);
        assert_eq!(*fixture.stack, stack);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, [0; 4]);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[test]
    fn artifact_sse_edits_publish_only_the_sse_xsave_header_bit() {
        for bypass in [false, true] {
            let mut fixture = Fixture::new(SYS_USER_DISPATCH);
            let bytes = (&mut fixture.fpstate.legacy as *mut _libc_fpstate).cast::<u8>();
            unsafe {
                bytes.add(464).cast::<u32>().write_unaligned(0x4650_5853);
                bytes.add(468).cast::<u32>().write_unaligned(836);
                bytes.add(480).cast::<u32>().write_unaligned(832);
            }
            fixture.fpstate.upper_xstate[..8].copy_from_slice(&4u64.to_ne_bytes());
            if bypass {
                fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
            }
            assert_eq!(fixture.route_art(Some(TARGET)), !bypass);
            assert_eq!(&fixture.fpstate.upper_xstate[..8], &6u64.to_ne_bytes());
            assert_eq!(&fixture.fpstate.upper_xstate[8..], &[0xa6; 1016]);
            assert_eq!(
                fixture.fpstate.legacy._xmm[4].element,
                [0x89ab_cdef, 0, 0, 0]
            );
        }
    }

    #[test]
    fn artifact_sse_rejects_malformed_metadata_before_touching_a_guarded_extension() {
        struct Mapping(*mut core::ffi::c_void);
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.0, 8192);
                }
            }
        }
        assert_eq!(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }, 4096);
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                8192,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        let mapping = Mapping(raw);
        let bytes = raw.cast::<u8>();
        assert_eq!(
            unsafe { libc::mprotect(bytes.add(4096).cast(), 4096, libc::PROT_NONE) },
            0
        );
        let prefix = unsafe { bytes.add(4096 - 512) };
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.context.uc_mcontext.fpregs = prefix.cast();
        for (extent, size) in [
            (576u32, 576u32),
            (580, 575),
            (580, 577),
            (u32::MAX, u32::MAX),
        ] {
            unsafe {
                core::ptr::write_bytes(prefix, 0, 512);
                prefix.add(464).cast::<u32>().write_unaligned(0x4650_5853);
                prefix.add(468).cast::<u32>().write_unaligned(extent);
                prefix.add(480).cast::<u32>().write_unaligned(size);
            }
            let initial = fixture.context.uc_mcontext.gregs;
            let before = unsafe { core::slice::from_raw_parts(prefix, 512) }.to_vec();
            assert!(!fixture.route_art(Some(TARGET)));
            assert_eq!(fixture.context.uc_mcontext.gregs, initial);
            assert_eq!(unsafe { core::slice::from_raw_parts(prefix, 512) }, before);
        }
        unsafe { prefix.add(464).cast::<u32>().write_unaligned(0) };
        assert!(fixture.route_art(Some(TARGET)));
        assert_eq!(
            unsafe { (*fixture.context.uc_mcontext.fpregs)._xmm[4].element },
            [0x89ab_cdef, 0, 0, 0]
        );
        drop(mapping);
    }

    #[test]
    fn artifact_does_not_accept_unknown_bypass_magic() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.fpstate.legacy._xmm[5].element = UNKNOWN_BYPASS;
        let rip = fixture.register(libc::REG_RIP);
        assert!(fixture.route_art(Some(TARGET)));
        assert_eq!(fixture.register(libc::REG_RAX), rip);
        assert_eq!(fixture.register(libc::REG_RIP), TARGET);
        assert_eq!(
            fixture.fpstate.legacy._xmm[4].element,
            [0x89ab_cdef, 0, 0, 0]
        );
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, UNKNOWN_BYPASS);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[test]
    fn artifact_foreign_or_unregistered_call_forwards_unchanged() {
        let mut fixture = Fixture::new(SYS_USER_DISPATCH);
        fixture.fpstate.legacy._xmm[5].element = ART_BYPASS;
        let initial = fixture.context.uc_mcontext.gregs;
        let stack = *fixture.stack;
        assert!(!fixture.route_art(None));
        assert_eq!(fixture.context.uc_mcontext.gregs, initial);
        assert_eq!(*fixture.stack, stack);
        assert_eq!(fixture.fpstate.legacy._xmm[4].element, ORIGINAL_XMM4);
        assert_eq!(fixture.fpstate.legacy._xmm[5].element, ART_BYPASS);
        fixture.assert_unrelated_fpstate_unchanged();
    }

    #[test]
    fn artifact_does_not_claim_seccomp_events() {
        for xmm5 in [ART_BYPASS, UNKNOWN_BYPASS] {
            let mut fixture = Fixture::new(SYS_SECCOMP);
            fixture.fpstate.legacy._xmm[5].element = xmm5;
            let initial = fixture.context.uc_mcontext.gregs;
            assert!(!fixture.route_art(Some(TARGET)));
            assert_eq!(fixture.context.uc_mcontext.gregs, initial);
            assert_eq!(fixture.fpstate.legacy._xmm[4].element, ORIGINAL_XMM4);
            assert_eq!(fixture.fpstate.legacy._xmm[5].element, xmm5);
            fixture.assert_unrelated_fpstate_unchanged();
        }
    }
}
