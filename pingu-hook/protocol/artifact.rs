//! Artifact registration, readiness and CPU presentation.
//!
//! Three variants of the Artifact hypervisor protocol are handled. Variant 1
//! (the older sources, Anno 117 and F1 25) keeps Reflex's `0x1337` bypass
//! marker. Variant 2 is the default: unlike the older Reflex ordering, PID
//! registration precedes the syscall handler, and a separate, one-shot CPUID
//! acknowledges KUSER preparation. Variant 3 (FM27's November build) keeps
//! variant 2's protocol with variant 1's hidden-feature CPU presentation.
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::cpuid::{Registers, Vendor};

pub const REGISTER_PROCESS: u32 = 0x1337;
pub const KUSER_READY: u32 = 0x1338;
pub const REGISTER_HANDLER: u32 = 0x336933;
/// Bypass marker of variants 2 and 3.
pub const SYSCALL_BYPASS_MAGIC: u64 = 0x6969_6969_6969_6969;
/// Bypass marker of variant 1.
pub const VARIANT1_SYSCALL_BYPASS_MAGIC: u64 = crate::reflex::SYSCALL_BYPASS_MAGIC;

/// The bypass marker a registered handler loads into XMM5: the first
/// `movabs rax, imm64` in its code that holds a known marker.
pub fn handler_bypass_magic(code: &[u8]) -> Option<u64> {
    code.windows(10).find_map(|window| {
        if window[..2] != [0x48, 0xb8] {
            return None;
        }
        let value = u64::from_le_bytes(window[2..].try_into().ok()?);
        matches!(value, SYSCALL_BYPASS_MAGIC | VARIANT1_SYSCALL_BYPASS_MAGIC).then_some(value)
    })
}

/// Variant 3's CPUID replies: variant 1's hidden-feature replies, except the
/// hypervisor leaves, where the target process falls through to the generic
/// SimpleSvm answers on the real hypervisor (variant 2 answered zero here).
pub fn variant3_reply(leaf: u32, native_ebx: u32) -> Option<Registers> {
    match leaf {
        // CPUID_HV_VENDOR_AND_MAX_FUNCTIONS: max leaf + "SimpleSvm   ".
        0x4000_0000 => Some(Registers::new(
            0x4000_0001,
            0x706d_6953,
            0x7653_656c,
            0x2020_206d,
        )),
        // CPUID_HV_INTERFACE: "Hv#0" (no Microsoft interface conformance).
        0x4000_0001 => Some(Registers::new(0x3023_7648, 0, 0, 0)),
        _ => variant1_reply(Vendor::Amd, leaf, native_ebx),
    }
}

/// Variant 1's CPUID replies: leaf 1 and the brand string
/// are replaced (AVX and XSAVE hidden), every other leaf stays native.
pub fn variant1_reply(vendor: Vendor, leaf: u32, native_ebx: u32) -> Option<Registers> {
    const HIDDEN: u32 = (1 << 12) | (0x3f << 25);
    let apic = native_ebx & 0xff_00_00_00;
    match (vendor, leaf) {
        (Vendor::Amd, 1) => Some(Registers::new(
            0x00a2_0f12,
            0x0010_0800 | apic,
            0x7ef8_320b & !HIDDEN,
            0x178b_fbff,
        )),
        (Vendor::Amd, 0x8000_0002) => Some(Registers::new(
            0x3230_4744,
            0x4254_5253,
            0x464d_3450,
            0x2020_2041,
        )),
        (Vendor::Amd, 0x8000_0003) => Some(Registers::new(
            0x2020_2020,
            0x2020_2020,
            0x2020_2020,
            0x2020_2020,
        )),
        (Vendor::Amd, 0x8000_0004) => Some(Registers::new(
            0x2020_2020,
            0x2020_2020,
            0x2020_2020,
            0x0020_2020,
        )),
        (Vendor::Intel, 1) => Some(Registers::new(
            0x000a_0655,
            0x0020_0800 | apic,
            0x73fa_fbff & !HIDDEN,
            0xbfeb_fbff,
        )),
        // "Intel(R) Pentium(R) CPU 4425Y @ 1.70GHz"
        (Vendor::Intel, 0x8000_0002) => Some(Registers::new(
            0x6574_6e49,
            0x2952_286c,
            0x6e65_5020,
            0x6d75_6974,
        )),
        (Vendor::Intel, 0x8000_0003) => Some(Registers::new(
            0x2029_5228,
            0x2055_5043,
            0x3532_3434,
            0x2040_2059,
        )),
        (Vendor::Intel, 0x8000_0004) => Some(Registers::new(0x3037_2e31, 0x007a_4847, 0, 0)),
        _ => None,
    }
}

/// Process-local registration and one-shot readiness. A failed preparation
/// stays retryable; concurrent polls never acknowledge a half-applied page.
pub struct Session {
    pid: AtomicU64,
    readiness: AtomicU32,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub const fn new() -> Self {
        Self {
            pid: AtomicU64::new(0),
            readiness: AtomicU32::new(0),
        }
    }

    pub fn register(&self, pid: u64) {
        if pid != 0 {
            let _ = self
                .pid
                .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    pub fn pid(&self) -> u64 {
        self.pid.load(Ordering::Acquire)
    }

    /// Returns true exactly once, and only after `prepare` succeeds.
    pub fn take_ready(&self, prepare: impl FnOnce() -> bool) -> bool {
        if self.pid() == 0
            || self
                .readiness
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        let ready = prepare();
        self.readiness
            .store(if ready { 2 } else { 0 }, Ordering::Release);
        ready
    }
}

/// Variant 2's target-process replies on AMD (the SimpleSvm profile). `None`
/// explicitly means native pass-through, including the topology leaves.
/// The runtime adds the native APIC ID to leaf 1 EBX.
pub fn session_amd_reply(leaf: u32, subleaf: u32) -> Option<Registers> {
    match leaf {
        REGISTER_PROCESS | KUSER_READY | REGISTER_HANDLER => None,
        _ => crate::cpuid::variant2_amd_reply(leaf, subleaf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_bypass_marker_is_read_from_the_first_known_movabs() {
        let movabs = |value: u64| {
            let mut code = [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0];
            code[2..].copy_from_slice(&value.to_le_bytes());
            code
        };
        let mut code = [0u8; 30];
        code[..10].copy_from_slice(&movabs(0x1234_5678_9abc_def0));
        code[10..20].copy_from_slice(&movabs(VARIANT1_SYSCALL_BYPASS_MAGIC));
        code[20..].copy_from_slice(&movabs(SYSCALL_BYPASS_MAGIC));
        assert_eq!(
            handler_bypass_magic(&code),
            Some(VARIANT1_SYSCALL_BYPASS_MAGIC)
        );
        assert_eq!(handler_bypass_magic(&movabs(7)), None);
        assert_eq!(
            handler_bypass_magic(&movabs(SYSCALL_BYPASS_MAGIC)[..9]),
            None
        );
    }

    #[test]
    fn variant1_replies_match_the_older_hypervisor_sources() {
        let amd = variant1_reply(Vendor::Amd, 1, 0x0700_0000).unwrap();
        assert_eq!(
            (amd.eax, amd.ebx, amd.ecx, amd.edx),
            (0x00a2_0f12, 0x0710_0800, 0x00f8_220b, 0x178b_fbff)
        );
        let intel = variant1_reply(Vendor::Intel, 1, 0x0b00_0000).unwrap();
        assert_eq!(
            (intel.eax, intel.ebx, intel.ecx, intel.edx),
            (0x000a_0655, 0x0b20_0800, 0x01fa_ebff, 0xbfeb_fbff)
        );
        let mut brand = [0u8; 48];
        for (index, leaf) in (0x8000_0002..=0x8000_0004).enumerate() {
            let words = variant1_reply(Vendor::Intel, leaf, 0).unwrap();
            for (part, word) in [words.eax, words.ebx, words.ecx, words.edx]
                .into_iter()
                .enumerate()
            {
                brand[index * 16 + part * 4..][..4].copy_from_slice(&word.to_le_bytes());
            }
        }
        assert_eq!(&brand[..40], b"Intel(R) Pentium(R) CPU 4425Y @ 1.70GHz\0");
        for vendor in [Vendor::Amd, Vendor::Intel] {
            for leaf in [0, 7, 0xd, 0x8000_0001] {
                assert_eq!(variant1_reply(vendor, leaf, 0), None);
            }
        }
    }

    #[test]
    fn variant3_signs_the_hypervisor_leaves_like_the_november_source() {
        assert_eq!(
            variant3_reply(0x4000_0000, 0),
            Some(Registers::new(
                0x4000_0001,
                0x706d_6953,
                0x7653_656c,
                0x2020_206d
            ))
        );
        assert_eq!(
            variant3_reply(0x4000_0001, 0),
            Some(Registers::new(0x3023_7648, 0, 0, 0))
        );
        // Everything else stays on the hidden-feature profile.
        assert_eq!(variant3_reply(0, 0), None);
        assert!(variant3_reply(1, 0x0700_0000).is_some());
    }

    #[test]
    fn readiness_requires_registration_and_success_and_is_one_shot() {
        let state = Session::new();
        assert!(!state.take_ready(|| panic!("unregistered poll must not prepare")));
        state.register(0);
        assert_eq!(state.pid(), 0);
        state.register(0x134);
        assert!(!state.take_ready(|| false));
        assert!(state.take_ready(|| {
            assert!(!state.take_ready(|| panic!("nested poll must not prepare")));
            true
        }));
        state.register(0x999);
        assert_eq!(state.pid(), 0x134);
        assert!(!state.take_ready(|| panic!("duplicate registration must not rearm")));
    }

    #[test]
    fn subleaves_do_not_leak_host_avx512_or_unknown_features() {
        let features = session_amd_reply(7, 0).unwrap();
        assert_eq!(features.ebx & (1 << 16), 0);
        assert_eq!(features.edx & (1 << 14), 0);
        for (leaf, subleaf) in [(7, 1), (0xd, 7), (0x8000_001d, 4), (0x8000_0023, 0)] {
            assert_eq!(session_amd_reply(leaf, subleaf), Some(Registers::default()));
        }
        assert_eq!(session_amd_reply(0xd, 0).unwrap().eax, 0x207);
        assert_eq!(session_amd_reply(0xd, 2).unwrap().ebx, 0x240);
        for leaf in [
            REGISTER_PROCESS,
            REGISTER_HANDLER,
            KUSER_READY,
            0xb,
            0x8000_001e,
        ] {
            assert_eq!(session_amd_reply(leaf, 0), None);
        }
    }
}
