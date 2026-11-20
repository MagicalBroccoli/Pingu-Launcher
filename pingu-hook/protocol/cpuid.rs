//! CPUID reply tables and the process-wide CPU identity they're chosen from.
//!
//! A CPUID leaf's canned reply depends on three independent things: the host
//! CPU vendor (detected once, real hardware), whether Proton has AVX enabled
//! (`PROTON_AVX`), and the [`CpuPresentation`] — modern ("Denuvo") by
//! default, or [`CpuPresentation::Legacy`] for a title whose Reflex protocol
//! (see `docs/protocol/game-quirks.md`) or KUSER dispatch recipe needs an
//! older-looking CPU. [`ActiveCpuIdentity`] holds that identity as a single
//! atomic so `runtime/src/cpuid.rs`'s SIGSEGV handler can read/update it
//! without a lock. This file only builds replies and encodes/decodes that
//! state; it has no idea how a CPUID trap actually reaches it.
use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Registers {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl Registers {
    pub const fn new(eax: u32, ebx: u32, ecx: u32, edx: u32) -> Self {
        Self { eax, ebx, ecx, edx }
    }
}

/// CPUID replies used by Artifact variant 2 on AMD (the SimpleSvm profile). The hypervisor
/// source gates these values on the registered target process; the runtime
/// applies them when `artifact.dll` is mapped on an AMD host. Returns `None`
/// for leaves that pass through to native `CPUID` (`0xb` and `0x8000_001e`).
pub fn variant2_amd_reply(leaf: u32, subleaf: u32) -> Option<Registers> {
    let reply = match leaf {
        0 => Registers::new(0x10, 0x6874_7541, 0x444d_4163, 0x6974_6e65),
        1 => Registers::new(0x00a2_0f12, 0x0010_0800, 0x7ef8_320b, 0x178b_fbff),
        5 => Registers::new(0x40, 0x40, 0x3, 0x11),
        6 => Registers::new(0x4, 0x0, 0x1, 0x0),
        7 => match subleaf {
            0 => Registers::new(0x0, 0x219c_97a9, 0x0040_068c, 0x10),
            _ => Registers::default(),
        },
        0xb | 0x8000_001e => return None,
        0xd => match subleaf {
            0 => Registers::new(0x207, 0x340, 0x988, 0x0),
            1 => Registers::new(0xf, 0x350, 0x1800, 0x0),
            2 => Registers::new(0x100, 0x240, 0x0, 0x0),
            9 => Registers::new(0x8, 0x980, 0x0, 0x0),
            0xb => Registers::new(0x10, 0x0, 0x1, 0x0),
            0xc => Registers::new(0x18, 0x0, 0x1, 0x0),
            _ => Registers::default(),
        },
        0xf => match subleaf {
            0 => Registers::new(0x0, 0xff, 0x0, 0x2),
            1 => Registers::new(0x0, 0x40, 0xff, 0x7),
            _ => Registers::default(),
        },
        0x10 => match subleaf {
            0 => Registers::new(0x0, 0x2, 0x0, 0x0),
            1 => Registers::new(0xf, 0x0, 0x4, 0xf),
            _ => Registers::default(),
        },
        0x8000_0000 => Registers::new(0x8000_0023, 0x6874_7541, 0x444d_4163, 0x6974_6e65),
        0x8000_0001 => Registers::new(0x00a2_0f12, 0x2000_0000, 0x75c2_37ff, 0x2fd3_fbff),
        // Preserve the source's MSVC multi-character constants as the exact
        // register values assigned by the hypervisor.
        0x8000_0002 => Registers::new(0x3230_4744, 0x4254_5253, 0x464d_3450, 0x2020_2041),
        0x8000_0003 => Registers::new(0x2020_2020, 0x2020_2020, 0x2020_2020, 0x2020_2020),
        0x8000_0004 => Registers::new(0x2020_2020, 0x2020_2020, 0x2020_2020, 0x0020_2020),
        0x8000_0005 => Registers::new(0xff40_ff40, 0xff40_ff40, 0x2008_0140, 0x2008_0140),
        0x8000_0006 => Registers::new(0x4800_2200, 0x6800_4200, 0x0200_6140, 0x0100_9140),
        0x8000_0007 => Registers::new(0x0, 0x3b, 0x0, 0x6799),
        0x8000_0008 => Registers::new(0x3030, 0x111e_f657, 0x400f, 0x0001_0000),
        0x8000_000a => Registers::new(0x1, 0x8000, 0x0, 0x101b_bcff),
        0x8000_0019 => Registers::new(0xf040_f040, 0xf040_0000, 0x0, 0x0),
        0x8000_001a => Registers::new(0x6, 0x0, 0x0, 0x0),
        0x8000_001b => Registers::new(0x3ff, 0x0, 0x0, 0x0),
        0x8000_001d => match subleaf {
            0 => Registers::new(0x4121, 0x01c0_003f, 0x3f, 0x0),
            1 => Registers::new(0x4122, 0x01c0_003f, 0x3f, 0x0),
            2 => Registers::new(0x4143, 0x01c0_003f, 0x3ff, 0x2),
            3 => Registers::new(0x3c163, 0x03c0_003f, 0x7fff, 0x1),
            _ => Registers::default(),
        },
        0x8000_001f => Registers::new(0x1780f, 0x173, 0x1fd, 0x1),
        0x8000_0020 => match subleaf {
            0 => Registers::new(0x0, 0x2, 0x0, 0x0),
            1 => Registers::new(0xb, 0x0, 0x0, 0xf),
            _ => Registers::default(),
        },
        0x8000_0021 => Registers::new(0x4d, 0x0, 0x0, 0x0),
        _ => Registers::default(),
    };
    Some(reply)
}

/// Applies the Intel HyperDbg artifact profile's bitmask and forced-feature
/// overrides to a native leaf 7, subleaf 0 result.
pub const fn with_intel_leaf7_features(native: Registers) -> Registers {
    Registers::new(
        0,
        (native.ebx & 0x23dc_bfff) | 0x0180_0000,
        (native.ecx & 0xffc1_a7bd) | 0x0040_0200,
        (native.edx & 0xff7f_fef3) | 0x0000_4000,
    )
}

/// CPUID replies used by Artifact variant 2 on Intel (the HyperDbg profile). The runtime
/// preserves the native APIC-ID byte of leaf 1 EBX and merges native leaf 7
/// subleaf 0 feature bits via [`with_intel_leaf7_features`]. Returns `None`
/// for leaf `0xb`, which passes through to native `CPUID`.
pub fn variant2_intel_reply(leaf: u32, subleaf: u32) -> Option<Registers> {
    let reply = match leaf {
        0 => Registers::new(0x20, 0x756e_6547, 0x6c65_746e, 0x4965_6e69),
        1 => Registers::new(0x000d_0670, 0x0010_0800, 0x7ffa_fbff, 0xbfeb_fbff),
        2 => Registers::new(0x00fe_ff01, 0xf0, 0x0, 0x0),
        4 => match subleaf {
            0 => Registers::new(0x3c00_4121, 0x02c0_003f, 0x3f, 0x0),
            1 => Registers::new(0x3c00_4122, 0x01c0_003f, 0x3f, 0x0),
            2 => Registers::new(0x3c00_4143, 0x03c0_003f, 0x7ff, 0x0),
            3 => Registers::new(0x1c03_c163, 0x02c0_003f, 0x7fff, 0x4),
            _ => Registers::default(),
        },
        5 => Registers::new(0x40, 0x40, 0x3, 0x1010_1020),
        6 => Registers::new(0x00df_cff7, 0x2, 0x409, 0x3),
        7 => match subleaf {
            0 => with_intel_leaf7_features(Registers::default()),
            _ => Registers::default(),
        },
        0xa => Registers::new(0x0830_0805, 0x0, 0xf, 0x8604),
        0xb => return None,
        0xd => match subleaf {
            0 => Registers::new(0x207, 0x340, 0xa88, 0x0),
            1 => Registers::new(0xf, 0x3d0, 0x19900, 0x0),
            2 => Registers::new(0x100, 0x240, 0x0, 0x0),
            8 => Registers::new(0x80, 0x0, 0x1, 0x0),
            9 => Registers::new(0x8, 0xa80, 0x0, 0x0),
            0xb => Registers::new(0x10, 0x0, 0x1, 0x0),
            0xc => Registers::new(0x18, 0x0, 0x1, 0x0),
            0xf => Registers::new(0x328, 0x0, 0x1, 0x0),
            0x10 => Registers::new(0x8, 0x0, 0x1, 0x0),
            _ => Registers::default(),
        },
        0x14 => match subleaf {
            0 => Registers::new(0x1, 0x5f, 0x7, 0x0),
            1 => Registers::new(0x0249_0002, 0x003f_003f, 0x0, 0x0),
            _ => Registers::default(),
        },
        0x15 => Registers::new(0x2, 0xb2, 0x0249_f000, 0x0),
        0x16 => Registers::new(0xfa0, 0x157c, 0x64, 0x0),
        0x18 => match subleaf {
            0 => Registers::new(0x8, 0x0, 0x0, 0x0),
            1 => Registers::new(0x0, 0x0008_0001, 0x20, 0x4022),
            2 => Registers::new(0x0, 0x0008_0006, 0x4, 0x4022),
            3 => Registers::new(0x0, 0x0010_000f, 0x1, 0x4125),
            4 => Registers::new(0x0, 0x0004_0001, 0x10, 0x4024),
            5 => Registers::new(0x0, 0x0004_0006, 0x8, 0x4024),
            6 => Registers::new(0x0, 0x0008_0008, 0x1, 0x4124),
            7 => Registers::new(0x0, 0x0008_0007, 0x80, 0x4043),
            8 => Registers::new(0x0, 0x0008_0009, 0x80, 0x4043),
            _ => Registers::default(),
        },
        0x19 => Registers::new(0x7, 0x14, 0x3, 0x0),
        0x1b => match subleaf {
            0 => Registers::new(0x1, 0x1, 0x0, 0x0),
            _ => Registers::default(),
        },
        0x1c => Registers::new(0x4000_000b, 0x7, 0x7, 0x0),
        0x1f => match subleaf {
            0 => Registers::new(0x1, 0x2, 0x100, 0x0),
            1 => Registers::new(0x4, 0x10, 0x201, 0x0),
            _ => Registers::default(),
        },
        0x20 => match subleaf {
            0 => Registers::new(0x0, 0x1, 0x0, 0x0),
            _ => Registers::default(),
        },
        0x8000_0000 => Registers::new(0x8000_0008, 0x0, 0x0, 0x0),
        0x8000_0001 => Registers::new(0x0, 0x0, 0x121, 0x2c10_0800),
        // Intel(R) Core(TM) 5 223PQE
        0x8000_0002 => Registers::new(0x6574_6e49, 0x2952_286c, 0x726f_4320, 0x4d54_2865),
        0x8000_0003 => Registers::new(0x2035_2029, 0x5033_3232, 0x0000_4551, 0x0),
        0x8000_0006 => Registers::new(0x0, 0x0, 0x0800_7040, 0x0),
        0x8000_0007 => Registers::new(0x0, 0x0, 0x0, 0x100),
        0x8000_0008 => Registers::new(0x302e, 0x0, 0x0, 0x0),
        _ => Registers::default(),
    };
    Some(reply)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Unknown,
    Intel,
    Amd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CpuPresentation {
    Denuvo = 0,
    Legacy = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuIdentity {
    vendor: Vendor,
    avx_enabled: bool,
    presentation: CpuPresentation,
}

const MODERN_BRAND: [u32; 12] = [
    0x756e_6544,
    0x4f77_4f76,
    0x5550_4320,
    0x3120_4020,
    0x2037_3333,
    0x007a_4847,
    0,
    0,
    0,
    0,
    0,
    0,
];
const LEGACY_INTEL_BRAND: [u32; 12] = [
    0x6574_6e49,
    0x2952_286c,
    0x726f_4320,
    0x4d54_2865,
    0x3969_2029,
    0x3930_312d,
    0x204b_3030,
    0x2055_5043,
    0x2e33_2040,
    0x4847_3037,
    0x0000_007a,
    0,
];
const LEGACY_AMD_BRAND: [u32; 12] = [
    0x2044_4d41,
    0x657a_7952,
    0x2039_206e,
    0x3030_3935,
    0x3231_2058,
    0x726f_432d,
    0x7250_2065,
    0x7365_636f,
    0x2072_6f73,
    0x2020_2020,
    0x2020_2020,
    0x0020_2020,
];

impl CpuIdentity {
    pub const fn denuvo(vendor: Vendor, avx_enabled: bool) -> Self {
        Self {
            vendor,
            avx_enabled,
            presentation: CpuPresentation::Denuvo,
        }
    }

    pub const fn vendor(self) -> Vendor {
        self.vendor
    }

    pub const fn presentation(self) -> CpuPresentation {
        self.presentation
    }

    pub const fn with_presentation(self, presentation: CpuPresentation) -> Self {
        Self {
            presentation,
            ..self
        }
    }

    pub fn fixed_reply(self, leaf: u32) -> Option<Registers> {
        let reply = match leaf {
            1 => self.leaf1(),
            0x4000_0000 => match self.vendor {
                Vendor::Unknown => Registers::default(),
                Vendor::Intel => Registers::new(0x4000_0001, 0x6570_7948, 0x6762_4472, 0),
                Vendor::Amd => Registers::new(0x4000_0001, 0x706d_6953, 0x7653_656c, 0x2020_206d),
            },
            0x4000_0001 => match self.vendor {
                Vendor::Unknown => Registers::default(),
                Vendor::Intel | Vendor::Amd => Registers::new(0x3023_7648, 0, 0, 0),
            },
            0x8000_0002..=0x8000_0004 => {
                let brand = match (self.presentation, self.vendor) {
                    (CpuPresentation::Legacy, Vendor::Intel) => &LEGACY_INTEL_BRAND,
                    (CpuPresentation::Legacy, Vendor::Amd | Vendor::Unknown) => &LEGACY_AMD_BRAND,
                    (CpuPresentation::Denuvo, _) => &MODERN_BRAND,
                };
                let offset = ((leaf - 0x8000_0002) * 4) as usize;
                Registers::new(
                    brand[offset],
                    brand[offset + 1],
                    brand[offset + 2],
                    brand[offset + 3],
                )
            }
            _ => return None,
        };
        Some(reply)
    }

    fn leaf1(self) -> Registers {
        match (self.presentation, self.vendor, self.avx_enabled) {
            (CpuPresentation::Denuvo, Vendor::Unknown, _) => Registers::default(),
            (CpuPresentation::Denuvo, Vendor::Intel, false) => {
                Registers::new(0x000a_0655, 0x0020_0800, 0x01fa_ebff, 0xbfeb_fbff)
            }
            (CpuPresentation::Denuvo, Vendor::Intel, true)
            | (CpuPresentation::Legacy, Vendor::Intel, _) => {
                Registers::new(0x000a_0655, 0x0020_0800, 0x7bfa_fbff, 0xbfeb_fbff)
            }
            (CpuPresentation::Denuvo, Vendor::Amd, false) => {
                Registers::new(0x00a2_0f12, 0x0010_0800, 0x00f8_220b, 0x178b_fbff)
            }
            (CpuPresentation::Denuvo, Vendor::Amd, true) => {
                Registers::new(0x00a2_0f12, 0x0010_0800, 0x7ad8_320b, 0x178b_fbff)
            }
            (CpuPresentation::Legacy, Vendor::Amd, _) => {
                Registers::new(0x00a2_0f10, 0x0018_0800, 0x7ad8_320b, 0x178b_fbff)
            }
            (CpuPresentation::Legacy, Vendor::Unknown, _) => {
                Registers::new(0x00a2_0f10, 0x0018_0800, 0x7ad8_320b, 0)
            }
        }
    }

    const fn encode(self) -> u32 {
        let vendor = match self.vendor {
            Vendor::Unknown => 0,
            Vendor::Intel => 1,
            Vendor::Amd => 2,
        };
        let avx_enabled = if self.avx_enabled { 1 } else { 0 };
        vendor | (avx_enabled << 2) | (self.presentation as u32) << 3
    }

    const fn decode(raw: u32) -> Self {
        let vendor = match raw & 0b11 {
            1 => Vendor::Intel,
            2 => Vendor::Amd,
            _ => Vendor::Unknown,
        };
        let presentation = if raw & (1 << 3) == 0 {
            CpuPresentation::Denuvo
        } else {
            CpuPresentation::Legacy
        };
        Self {
            vendor,
            avx_enabled: raw & (1 << 2) != 0,
            presentation,
        }
    }
}

impl Vendor {
    pub fn from_leaf0(registers: Registers) -> Self {
        match (registers.ebx, registers.edx, registers.ecx) {
            (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => Self::Intel,
            (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Self::Amd,
            _ => Self::Unknown,
        }
    }
}

pub fn proton_avx_enabled(value: Option<&[u8]>) -> bool {
    value == Some(b"1".as_slice())
}

const WINE_SYSTEM_RIP_MIN: u64 = 0x0000_6fff_ff00_0000;
const WINE_SYSTEM_RIP_MAX: u64 = 0x0000_7000_0000_0000;

pub fn is_wine_system_rip(address: u64) -> bool {
    (WINE_SYSTEM_RIP_MIN..WINE_SYSTEM_RIP_MAX).contains(&address)
}

#[derive(Debug)]
pub struct ActiveCpuIdentity {
    raw_identity: AtomicU32,
}

impl ActiveCpuIdentity {
    pub const fn new() -> Self {
        Self {
            raw_identity: AtomicU32::new(CpuIdentity::denuvo(Vendor::Unknown, false).encode()),
        }
    }

    pub fn load(&self) -> CpuIdentity {
        CpuIdentity::decode(self.raw_identity.load(Ordering::Acquire))
    }

    pub fn configure_host(&self, vendor: Vendor, avx_enabled: bool) {
        loop {
            let current = self.raw_identity.load(Ordering::Acquire);
            let presentation = CpuIdentity::decode(current).presentation();
            let next = CpuIdentity::denuvo(vendor, avx_enabled)
                .with_presentation(presentation)
                .encode();
            if self
                .raw_identity
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn select_legacy_presentation(&self) {
        loop {
            let current = self.raw_identity.load(Ordering::Acquire);
            let next = CpuIdentity::decode(current)
                .with_presentation(CpuPresentation::Legacy)
                .encode();
            if self
                .raw_identity
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    pub fn fixed_reply(&self, leaf: u32) -> Option<Registers> {
        self.load().fixed_reply(leaf)
    }
}

impl Default for ActiveCpuIdentity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::{Registers, variant2_amd_reply, variant2_intel_reply, with_intel_leaf7_features};

    #[test]
    fn variant2_amd_profile_matches_simple_svm_cpu_registers() {
        assert_eq!(
            variant2_amd_reply(0, 0),
            Some(Registers::new(0x10, 0x6874_7541, 0x444d_4163, 0x6974_6e65,))
        );
        assert_eq!(
            variant2_amd_reply(1, 0),
            Some(Registers::new(
                0x00a2_0f12,
                0x0010_0800,
                0x7ef8_320b,
                0x178b_fbff,
            ))
        );
        assert_eq!(
            variant2_amd_reply(7, 0),
            Some(Registers::new(0x0, 0x219c_97a9, 0x0040_068c, 0x10))
        );
        assert_eq!(variant2_amd_reply(7, 1), Some(Registers::default()));
        assert_eq!(variant2_amd_reply(0xb, 0), None);
        assert_eq!(variant2_amd_reply(0x8000_001e, 0), None);
        assert_eq!(
            variant2_amd_reply(0x8000_0002, 0),
            Some(Registers::new(
                0x3230_4744,
                0x4254_5253,
                0x464d_3450,
                0x2020_2041,
            ))
        );
        assert_eq!(
            variant2_amd_reply(0x8000_0003, 0),
            Some(Registers::new(
                0x2020_2020,
                0x2020_2020,
                0x2020_2020,
                0x2020_2020,
            ))
        );
        assert_eq!(
            variant2_amd_reply(0x8000_0004, 0),
            Some(Registers::new(
                0x2020_2020,
                0x2020_2020,
                0x2020_2020,
                0x0020_2020,
            ))
        );
        assert_eq!(
            variant2_amd_reply(0x4000_0000, 0),
            Some(Registers::default())
        );
    }

    #[test]
    fn artifact_intel_profile_matches_hyperdbg_cpu_registers() {
        assert_eq!(
            variant2_intel_reply(0, 0),
            Some(Registers::new(0x20, 0x756e_6547, 0x6c65_746e, 0x4965_6e69,))
        );
        assert_eq!(
            variant2_intel_reply(1, 0),
            Some(Registers::new(
                0x000d_0670,
                0x0010_0800,
                0x7ffa_fbff,
                0xbfeb_fbff,
            ))
        );
        assert_eq!(
            with_intel_leaf7_features(Registers::new(
                0x1234_5678,
                0xffff_ffff,
                0xffff_ffff,
                0xffff_ffff,
            )),
            Registers::new(0x0, 0x23dc_bfff, 0xffc1_a7bd, 0xff7f_fef3)
        );
        assert_eq!(variant2_intel_reply(7, 1), Some(Registers::default()));
        assert_eq!(variant2_intel_reply(0xb, 0), None);
        assert_eq!(
            variant2_intel_reply(0x8000_0002, 0),
            Some(Registers::new(
                0x6574_6e49,
                0x2952_286c,
                0x726f_4320,
                0x4d54_2865,
            ))
        );
        assert_eq!(
            variant2_intel_reply(0x8000_0003, 0),
            Some(Registers::new(0x2035_2029, 0x5033_3232, 0x0000_4551, 0x0,))
        );
        assert_eq!(
            variant2_intel_reply(0x8000_0004, 0),
            Some(Registers::default())
        );
        assert_eq!(
            variant2_intel_reply(0x4000_0000, 0),
            Some(Registers::default())
        );
    }
}
