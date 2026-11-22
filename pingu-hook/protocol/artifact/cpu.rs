//! The registered ART guest CPU view, independent of the host's real XSTATE.

use crate::cpuid::{Registers, Vendor};

/// Native `doCpuid` assignments differ between the supplied AMD and Intel code.
pub fn native_words(vendor: Vendor, native: Registers) -> [u64; 4] {
    let words = [native.eax, native.ebx, native.ecx, native.edx];
    match vendor {
        Vendor::Intel => words.map(|word| word as i32 as i64 as u64),
        _ => words.map(u64::from),
    }
}

/// The Intel CPU identity an Artifact release's hypervisor presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntelIdentity {
    /// Releases whose handler uses the 0x6969 bypass (Planet Zoo 2).
    Core,
    /// Releases whose handler uses the 0x1337 bypass (Anno 117, F1 25): the
    /// hypervisor reports "Intel(R) Pentium(R) CPU 4425Y @ 1.70GHz".
    Pentium4425Y,
}

/// Leaf 1 and brand leaves of [`IntelIdentity::Pentium4425Y`], as the
/// release's Vmexit.c assigns them. Other leaves stay native there.
pub fn pentium_4425y_reply(leaf: u32, native: impl FnOnce() -> Registers) -> Option<[u64; 4]> {
    Some(match leaf {
        1 => [
            0x000a_0655,
            0x0020_0800 | u64::from(native().ebx & 0xff00_0000),
            0x73fa_fbff,
            0xbfeb_fbff,
        ],
        // "Intel(R) Pentium(R) CPU 4425Y @ 1.70GHz"
        0x8000_0002 => [0x6574_6e49, 0x2952_286c, 0x6e65_5020, 0x6d75_6974],
        0x8000_0003 => [0x2029_5228, 0x2055_5043, 0x3532_3434, 0x2040_2059],
        0x8000_0004 => [0x3037_2e31, 0x007a_4847, 0, 0],
        _ => return None,
    })
}

/// Source guest assignments, not the older compatibility profiles in `cpuid`.
/// The caller must have received `CpuidAction::Query` for the registered process.
/// This emulates CPUID replies only; it does not change XCR0 or execute XSAVE.
pub fn reply(
    vendor: Vendor,
    leaf: u32,
    subleaf: u32,
    native: impl FnOnce() -> Registers,
) -> [u64; 4] {
    match (vendor, leaf, subleaf) {
        (Vendor::Unknown, _, _) | (_, 0xb, _) | (Vendor::Amd, 0x8000_001e, _) => {
            native_words(vendor, native())
        }
        (Vendor::Amd, 0, _) => [0x10, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
        (Vendor::Amd, 1, _) => [
            0x00a2_0f12,
            0x0010_0800 | u64::from(native().ebx & 0xff00_0000),
            0x7ef8_320b,
            0x178b_fbff,
        ],
        (Vendor::Amd, 5, _) => [0x40, 0x40, 3, 0x11],
        (Vendor::Amd, 6, _) => [4, 0, 1, 0],
        (Vendor::Amd, 7, 0) => [0, 0x219c_97a9, 0x0040_068c, 0x10],
        (Vendor::Amd, 0xd, 0) => [0x207, 0x340, 0x988, 0],
        (Vendor::Amd, 0xd, 1) => [0xf, 0x350, 0x1800, 0],
        (Vendor::Amd, 0xd, 2) => [0x100, 0x240, 0, 0],
        (Vendor::Amd, 0xd, 9) => [8, 0x980, 0, 0],
        (Vendor::Amd, 0xd, 0xb) => [0x10, 0, 1, 0],
        (Vendor::Amd, 0xd, 0xc) => [0x18, 0, 1, 0],
        (Vendor::Amd, 0xf, 0) => [0, 0xff, 0, 2],
        (Vendor::Amd, 0xf, 1) => [0, 0x40, 0xff, 7],
        (Vendor::Amd, 0x10, 0) => [0, 2, 0, 0],
        (Vendor::Amd, 0x10, 1) => [0xf, 0, 4, 0xf],
        (Vendor::Amd, 0x8000_0000, _) => [0x8000_0023, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
        (Vendor::Amd, 0x8000_0001, _) => [0x00a2_0f12, 0x2000_0000, 0x75c2_37ff, 0x2fd3_fbff],
        (Vendor::Amd, 0x8000_0002, _) => [0x3230_4744, 0x4254_5253, 0x464d_3450, 0x2020_2041],
        (Vendor::Amd, 0x8000_0003, _) => [0x2020_2020; 4],
        (Vendor::Amd, 0x8000_0004, _) => [0x2020_2020, 0x2020_2020, 0x2020_2020, 0x0020_2020],
        (Vendor::Amd, 0x8000_0005, _) => [0xff40_ff40, 0xff40_ff40, 0x2008_0140, 0x2008_0140],
        (Vendor::Amd, 0x8000_0006, _) => [0x4800_2200, 0x6800_4200, 0x0200_6140, 0x0100_9140],
        (Vendor::Amd, 0x8000_0007, _) => [0, 0x3b, 0, 0x6799],
        (Vendor::Amd, 0x8000_0008, _) => [0x3030, 0x111e_f657, 0x400f, 0x1_0000],
        (Vendor::Amd, 0x8000_000a, _) => [1, 0x8000, 0, 0x101b_bcff],
        (Vendor::Amd, 0x8000_0019, _) => [0xf040_f040, 0xf040_0000, 0, 0],
        (Vendor::Amd, 0x8000_001a, _) => [6, 0, 0, 0],
        (Vendor::Amd, 0x8000_001b, _) => [0x3ff, 0, 0, 0],
        (Vendor::Amd, 0x8000_001d, 0) => [0x4121, 0x01c0_003f, 0x3f, 0],
        (Vendor::Amd, 0x8000_001d, 1) => [0x4122, 0x01c0_003f, 0x3f, 0],
        (Vendor::Amd, 0x8000_001d, 2) => [0x4143, 0x01c0_003f, 0x3ff, 2],
        (Vendor::Amd, 0x8000_001d, 3) => [0x0003_c163, 0x03c0_003f, 0x7fff, 1],
        (Vendor::Amd, 0x8000_001f, _) => [0x1_780f, 0x173, 0x1fd, 1],
        (Vendor::Amd, 0x8000_0020, 0) => [0, 2, 0, 0],
        (Vendor::Amd, 0x8000_0020, 1) => [0xb, 0, 0, 0xf],
        (Vendor::Amd, 0x8000_0021, _) => [0x4d, 0, 0, 0],
        (Vendor::Intel, 0, _) => [0x20, 0x756e_6547, 0x6c65_746e, 0x4965_6e69],
        (Vendor::Intel, 1, _) => [
            0x000d_0670,
            0x0010_0800 | u64::from(native().ebx & 0xff00_0000),
            0x7ffa_fbff,
            0xbfeb_fbff,
        ],
        (Vendor::Intel, 2, _) => [0x00fe_ff01, 0xf0, 0, 0],
        (Vendor::Intel, 4, 0) => [0x3c00_4121, 0x02c0_003f, 0x3f, 0],
        (Vendor::Intel, 4, 1) => [0x3c00_4122, 0x01c0_003f, 0x3f, 0],
        (Vendor::Intel, 4, 2) => [0x3c00_4143, 0x03c0_003f, 0x7ff, 0],
        (Vendor::Intel, 4, 3) => [0x1c03_c163, 0x02c0_003f, 0x7fff, 4],
        (Vendor::Intel, 5, _) => [0x40, 0x40, 3, 0x1010_1020],
        (Vendor::Intel, 6, _) => [0x00df_cff7, 2, 0x409, 3],
        (Vendor::Intel, 7, 0) => {
            let r = native();
            [
                0,
                u64::from((r.ebx & 0x23dc_bfff) | 0x0180_0000),
                // Vmexit.c assigns INT32 CpuInfo words to UINT64 guest GPRs.
                ((r.ecx & 0xffc1_a7bd) as i32 as i64 as u64) | 0x0040_0200,
                ((r.edx & 0xff7f_fef3) as i32 as i64 as u64) | 0x4000,
            ]
        }
        (Vendor::Intel, 0xa, _) => [0x0830_0805, 0, 0xf, 0x8604],
        (Vendor::Intel, 0xd, 0) => [0x207, 0x340, 0xa88, 0],
        (Vendor::Intel, 0xd, 1) => [0xf, 0x3d0, 0x1_9900, 0],
        (Vendor::Intel, 0xd, 2) => [0x100, 0x240, 0, 0],
        (Vendor::Intel, 0xd, 8) => [0x80, 0, 1, 0],
        (Vendor::Intel, 0xd, 9) => [8, 0xa80, 0, 0],
        (Vendor::Intel, 0xd, 0xb) => [0x10, 0, 1, 0],
        (Vendor::Intel, 0xd, 0xc) => [0x18, 0, 1, 0],
        (Vendor::Intel, 0xd, 0xf) => [0x328, 0, 1, 0],
        (Vendor::Intel, 0xd, 0x10) => [8, 0, 1, 0],
        (Vendor::Intel, 0x14, 0) => [1, 0x5f, 7, 0],
        (Vendor::Intel, 0x14, 1) => [0x0249_0002, 0x003f_003f, 0, 0],
        (Vendor::Intel, 0x15, _) => [2, 0xb2, 0x0249_f000, 0],
        (Vendor::Intel, 0x16, _) => [0xfa0, 0x157c, 0x64, 0],
        (Vendor::Intel, 0x18, 0) => [8, 0, 0, 0],
        (Vendor::Intel, 0x18, 1) => [0, 0x0008_0001, 0x20, 0x4022],
        (Vendor::Intel, 0x18, 2) => [0, 0x0008_0006, 4, 0x4022],
        (Vendor::Intel, 0x18, 3) => [0, 0x0010_000f, 1, 0x4125],
        (Vendor::Intel, 0x18, 4) => [0, 0x0004_0001, 0x10, 0x4024],
        (Vendor::Intel, 0x18, 5) => [0, 0x0004_0006, 8, 0x4024],
        (Vendor::Intel, 0x18, 6) => [0, 0x0008_0008, 1, 0x4124],
        (Vendor::Intel, 0x18, 7) => [0, 0x0008_0007, 0x80, 0x4043],
        (Vendor::Intel, 0x18, 8) => [0, 0x0008_0009, 0x80, 0x4043],
        (Vendor::Intel, 0x19, _) => [7, 0x14, 3, 0],
        (Vendor::Intel, 0x1b, 0) => [1, 1, 0, 0],
        (Vendor::Intel, 0x1c, _) => [0x4000_000b, 7, 7, 0],
        (Vendor::Intel, 0x1f, 0) => [1, 2, 0x100, 0],
        (Vendor::Intel, 0x1f, 1) => [4, 0x10, 0x201, 0],
        (Vendor::Intel, 0x20, 0) => [0, 1, 0, 0],
        (Vendor::Intel, 0x8000_0000, _) => [0x8000_0008, 0, 0, 0],
        (Vendor::Intel, 0x8000_0001, _) => [0, 0, 0x121, 0x2c10_0800],
        (Vendor::Intel, 0x8000_0002, _) => [0x6574_6e49, 0x2952_286c, 0x726f_4320, 0x4d54_2865],
        (Vendor::Intel, 0x8000_0003, _) => [0x2035_2029, 0x5033_3232, 0x4551, 0],
        (Vendor::Intel, 0x8000_0006, _) => [0, 0, 0x0800_7040, 0],
        (Vendor::Intel, 0x8000_0007, _) => [0, 0, 0, 0x100],
        (Vendor::Intel, 0x8000_0008, _) => [0x302e, 0, 0, 0],
        _ => [0; 4],
    }
}

#[cfg(test)]
mod tests {
    use super::reply;
    use crate::cpuid::{Registers, Vendor};

    #[test]
    fn source_profile_does_not_leak_unknown_host_capabilities() {
        let native = Registers::new(1, 2, 4, 8);
        assert_eq!(reply(Vendor::Amd, 0x24, 0, || native), [0; 4]);
    }

    #[test]
    fn amd_subleaf_termination_does_not_advertise_native_bf16() {
        let native = Registers::new(0x20, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff);
        let base = reply(Vendor::Amd, 7, 0, || native);
        assert_eq!(base[0], 0);
        assert_ne!(base[1] & (1 << 5), 0);
        assert_eq!(reply(Vendor::Amd, 7, 1, || native), [0; 4]);
    }

    #[test]
    fn core_migration_changes_only_the_native_apic_byte_of_the_fixed_identity() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            let before = reply(vendor, 1, 0, || Registers::new(0, 0x0700_0000, 0, 0));
            let after = reply(vendor, 1, 0, || Registers::new(0, 0x0b00_0000, 0, 0));
            assert_eq!(before[1] >> 24, 7);
            assert_eq!(after[1] >> 24, 11);
            assert_eq!(before[1] & 0x00ff_ffff, after[1] & 0x00ff_ffff);
            assert_eq!(
                [before[0], before[2], before[3]],
                [after[0], after[2], after[3]]
            );
        }
    }

    #[test]
    fn intel_filtering_preserves_source_signed_guest_feature_words() {
        let native = Registers::new(0, (1 << 5) | (1 << 16), 1 << 31, 1 << 31);
        let result = reply(Vendor::Intel, 7, 0, || native);
        assert_ne!(result[1] & (1 << 5), 0);
        assert_eq!(result[1] & (1 << 16), 0);
        assert_eq!(result[1] & 0x0180_0000, 0x0180_0000);
        assert_eq!(result[2] >> 32, u64::from(u32::MAX));
        assert_eq!(result[3] >> 32, u64::from(u32::MAX));
        assert_eq!(result[2] & 0x0040_0200, 0x0040_0200);
        assert_eq!(result[3] & 0x4000, 0x4000);
    }

    #[test]
    fn intel_native_topology_keeps_signed_words_in_full_guest_registers() {
        let native = Registers::new(0x8000_0000, 0x8000_0001, 0x7fff_ffff, 0x8000_0000);
        assert_eq!(
            reply(Vendor::Intel, 0xb, 0, || native),
            [
                0xffff_ffff_8000_0000,
                0xffff_ffff_8000_0001,
                0x7fff_ffff,
                0xffff_ffff_8000_0000
            ],
        );
    }
}
