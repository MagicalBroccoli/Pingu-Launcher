//! Versioned Artifact CPU metadata; no host CPU state is changed here.
use crate::artifact::cpu::IntelIdentity;
use crate::cpuid::{Registers, Vendor};

/// Validate a PE64 header before using it to attribute an anonymous code view.
pub fn pe_image_contains(base: u64, address: u64, dos: &[u8], pe: &[u8]) -> bool {
    if base & 0xffff != 0
        || dos.len() < 64
        || pe.len() < 84
        || &dos[..2] != b"MZ"
        || &pe[..4] != b"PE\0\0"
        || u16::from_le_bytes([pe[4], pe[5]]) != 0x8664
        || u16::from_le_bytes([pe[24], pe[25]]) != 0x20b
    {
        return false;
    }
    let header = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]);
    let size = u32::from_le_bytes([pe[80], pe[81], pe[82], pe[83]]);
    (64..=0x1000).contains(&header)
        && (0x1000..=0x80000000).contains(&size)
        && base
            .checked_add(u64::from(size))
            .is_some_and(|end| (base..end).contains(&address))
}

/// Unknown mappings retain the previous conservative address-range policy.
pub fn native_wine_view(address: u64, path: Option<&[u8]>) -> bool {
    if let Some(path) = path {
        let path = path.strip_suffix(b" (deleted)").unwrap_or(path);
        let name = path.rsplit(|b| *b == b'/').next().unwrap_or_default();
        let contains = |part: &[u8]| path.windows(part.len()).any(|w| w == part);
        if contains(b"/wine/x86_64-windows/") || contains(b"/wine/x86_64-unix/") {
            return true;
        }
        if (contains(b"/windows/system32/") || contains(b"/windows/syswow64/"))
            && [
                b"ntdll.dll".as_slice(),
                b"kernel32.dll",
                b"kernelbase.dll",
                b"win32u.dll",
            ]
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
        {
            return true;
        }
        let extension = name.get(name.len().saturating_sub(4)..).unwrap_or_default();
        if extension.eq_ignore_ascii_case(b".exe") || extension.eq_ignore_ascii_case(b".dll") {
            return false;
        }
    }
    crate::cpuid::is_wine_system_rip(address)
}

/// End of a valid PE64 image mapped at `base`, checked as [`pe_image_contains`]
/// checks it.
pub fn pe_image_end(base: u64, dos: &[u8], pe: &[u8]) -> Option<u64> {
    pe_image_contains(base, base, dos, pe)
        .then(|| base + u64::from(u32::from_le_bytes([pe[80], pe[81], pe[82], pe[83]])))
}

/// The addresses around `address` that get the same Wine-view answer as
/// `address`, so one answer can be reused for all of them.
///
/// `mapping` is the `/proc/self/maps` entry containing `address`. For
/// anonymous code, the answer comes from the closest preceding PE image that
/// contains the address: `image_end` is that image's end, and
/// `closer_image_end` is the largest end of any closer image that does not
/// contain `address` (such an image would win below its end). The fallback,
/// [`crate::cpuid::is_wine_system_rip`], changes only at the Wine system range
/// bounds, so the range never crosses them.
pub fn constant_wine_view_range(
    address: u64,
    mapping: (u64, u64),
    anonymous: bool,
    image_end: Option<u64>,
    closer_image_end: u64,
) -> Option<(u64, u64)> {
    let (mut start, mut end) = mapping;
    if anonymous {
        if let Some(image_end) = image_end {
            end = end.min(image_end);
        }
        start = start.max(closer_image_end);
    }
    let (wine_start, wine_end) = crate::cpuid::wine_system_rip_range();
    if address < wine_start {
        end = end.min(wine_start);
    } else if address < wine_end {
        start = start.max(wine_start);
        end = end.min(wine_end);
    } else {
        start = start.max(wine_end);
    }
    (start..end).contains(&address).then_some((start, end))
}

/// Which hypervisor generation an Artifact release's tokens were made with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    /// VBS 1.9: leaf 1 and brand fixed, XSAVE/AVX masked, other leaves
    /// native, KUSER processor-feature and XSTATE fields cleared.
    Vbs19,
    /// VBS 2.0: the full fixed CPUID table with AVX/XSAVE reported, and only
    /// the identity KUSER writes. Its tokens expect XCR0 = 0x7.
    Vbs20,
}

/// Text of the dialog an `artifact.dll` shows when the host's XCR0 is not
/// the 0x7 its VBS 2.0 tokens were made with. VBS 1.9 builds do not have it.
pub const VBS20_MARKER: &[u8] = b"Run specifically the included VBS.cmd";

/// Whether `image` (a whole `artifact.dll`, or a chunk of it) contains
/// [`VBS20_MARKER`].
pub fn contains_vbs20_marker(image: &[u8]) -> bool {
    image
        .windows(VBS20_MARKER.len())
        .any(|window| window == VBS20_MARKER)
}

/// Choose the generation for a session: the `PINGU_VBS20` override
/// (`forced`), else VBS 2.0 exactly when the release's `artifact.dll`
/// contains [`VBS20_MARKER`].
pub fn select_generation(forced: Option<bool>, vbs20_marker: bool) -> Generation {
    match forced {
        Some(true) => Generation::Vbs20,
        Some(false) => Generation::Vbs19,
        None if vbs20_marker => Generation::Vbs20,
        None => Generation::Vbs19,
    }
}

/// CPUID reply for an Artifact query. VBS 1.9: hypervisor identity and brand
/// leaves, XSAVE/AVX bits masked in leaf 1, a zeroed high-leaf range, and
/// native words for everything else. VBS 2.0: the source's full table.
pub fn reply(
    generation: Generation,
    vendor: Vendor,
    intel: IntelIdentity,
    leaf: u32,
    subleaf: u32,
    native: impl FnOnce() -> Registers,
) -> [u64; 4] {
    if vendor == Vendor::Unknown {
        return crate::artifact::cpu::native_words(vendor, native());
    }
    if generation == Generation::Vbs20 {
        return crate::artifact::cpu::reply(vendor, leaf, subleaf, native);
    }
    if leaf == 1 || (0x8000_0002..=0x8000_0004).contains(&leaf) {
        let mut words = if vendor == Vendor::Intel && intel == IntelIdentity::Pentium4425Y {
            crate::artifact::cpu::pentium_4425y_reply(leaf, native).unwrap_or([0; 4])
        } else {
            crate::artifact::cpu::reply(vendor, leaf, subleaf, native)
        };
        if leaf == 1 {
            words[2] &= !((1 << 12)
                | (1 << 25)
                | (1 << 26)
                | (1 << 27)
                | (1 << 28)
                | (1 << 29)
                | (1 << 30));
        }
        return words;
    }
    if (0x0033_6934..0x8000_0000).contains(&leaf) {
        return [0; 4];
    }
    crate::artifact::cpu::native_words(vendor, native())
}

/// KUSER_SHARED_DATA writes for Artifact: the shared identity fields, then
/// for VBS 1.9 the processor-feature and XSTATE fields cleared. Wine's clock
/// fields and the gaps between ranges are left alone.
pub fn visit_writes(
    generation: Generation,
    vendor: Vendor,
    mut write: impl FnMut(usize, u8),
) -> bool {
    if !crate::artifact::kuser::visit_artifact_writes(vendor, &mut write) {
        return false;
    }
    if generation == Generation::Vbs20 {
        return true;
    }
    for at in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
        write(at, 0);
    }
    for range in [0x3d8..0x3e8, 0x3ec..0x600, 0x604..0x804, 0x808..0x818] {
        for at in range {
            write(at, 0);
        }
    }
    true
}

/// After registering, the Artifact build that uses the 0x1337 bypass (seen
/// in Anno 117) polls this KUSER_SHARED_DATA marker and sleeps in 100 ms
/// waitable-timer waits until it appears. Other builds must not see it.
pub const READY_MARKER_OFFSET: usize = 0xffc;
pub const READY_MARKER: u32 = 0x1337_1337;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_code_requires_a_valid_bounded_pe64_image() {
        let base = 0x6fffff6d0000;
        let mut dos = [0u8; 64];
        dos[..2].copy_from_slice(b"MZ");
        dos[0x3c..].copy_from_slice(&0x80u32.to_le_bytes());
        let mut pe = [0u8; 84];
        pe[..4].copy_from_slice(b"PE\0\0");
        pe[4..6].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[24..26].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[80..84].copy_from_slice(&0x22000u32.to_le_bytes());
        assert!(pe_image_contains(base, base + 0x8b80, &dos, &pe));
        assert!(!pe_image_contains(base, base + 0x23000, &dos, &pe));
        assert!(!pe_image_contains(base, base - 1, &dos, &pe));
        assert!(!pe_image_contains(
            u64::MAX - 0xffff,
            u64::MAX - 1,
            &dos,
            &pe
        ));
        assert!(!pe_image_contains(base, base + 0x1000, &dos[..10], &pe));
        pe[4..6].copy_from_slice(&0x14cu16.to_le_bytes());
        assert!(!pe_image_contains(base, base + 0x8b80, &dos, &pe));
    }

    #[test]
    fn observed_high_application_image_is_not_a_wine_system_caller() {
        assert!(!native_wine_view(
            0x6fffff6d8b80,
            Some(b"/private test/native-profile-fixture.exe")
        ));
        assert!(!native_wine_view(
            0x6fffff6d8b80,
            Some(b"/game/artifact.dll (deleted)")
        ));
    }

    #[test]
    fn attributed_wine_cpu_state_modules_keep_the_native_view() {
        for path in [
            b"/proton/files/lib/wine/x86_64-unix/ntdll.so".as_slice(),
            b"/prefix/drive_c/windows/system32/ntdll.dll".as_slice(),
        ] {
            assert!(native_wine_view(0x7f0000001000, Some(path)));
        }
    }

    #[test]
    fn unattributed_addresses_keep_the_existing_safe_fallback() {
        assert!(native_wine_view(0x6fffff6d8b80, None));
        assert!(!native_wine_view(0x140001000, None));
    }

    #[test]
    fn leaf_one_matches_new_sources_for_both_vendors() {
        for (vendor, eax, ecx, edx) in [
            (Vendor::Amd, 0xa20f12, 0x00f8220b, 0x178bfbff),
            (Vendor::Intel, 0xd0670, 0x01faebff, 0xbfebfbff),
        ] {
            assert_eq!(
                reply(Generation::Vbs19, vendor, IntelIdentity::Core, 1, 0, || {
                    Registers::new(0, 0xf3000000, 0, 0)
                }),
                [eax, 0xf3100800, ecx, edx]
            );
        }
    }

    #[test]
    fn removed_tables_use_native_words_including_signed_intel() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            for (leaf, subleaf) in [(0, 0), (7, 0), (7, 1), (0xd, 0), (0x80000001, 0)] {
                let native = Registers::new(0x80000000, 0xffffffff, 3, 0x80000001);
                let expected = if vendor == Vendor::Intel {
                    [0xffffffff80000000, u64::MAX, 3, 0xffffffff80000001]
                } else {
                    [0x80000000, 0xffffffff, 3, 0x80000001]
                };
                assert_eq!(
                    reply(
                        Generation::Vbs19,
                        vendor,
                        IntelIdentity::Core,
                        leaf,
                        subleaf,
                        || native
                    ),
                    expected
                );
            }
        }
    }

    #[test]
    fn generation_follows_the_override_then_the_marker() {
        for marker in [false, true] {
            assert_eq!(select_generation(Some(true), marker), Generation::Vbs20);
            assert_eq!(select_generation(Some(false), marker), Generation::Vbs19);
        }
        assert_eq!(select_generation(None, true), Generation::Vbs20);
        assert_eq!(select_generation(None, false), Generation::Vbs19);
    }

    #[test]
    fn marker_is_found_anywhere_in_the_image() {
        let mut image = [0u8; 4096];
        assert!(!contains_vbs20_marker(&image));
        image[1000..1000 + VBS20_MARKER.len()].copy_from_slice(VBS20_MARKER);
        assert!(contains_vbs20_marker(&image));
        assert!(!contains_vbs20_marker(
            &VBS20_MARKER[..VBS20_MARKER.len() - 1]
        ));
        assert!(contains_vbs20_marker(VBS20_MARKER));
    }

    #[test]
    fn vbs20_uses_the_full_source_table_with_avx_reported() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            for (leaf, subleaf) in [(0, 0), (1, 0), (7, 0), (0xd, 0), (0xd, 1), (0x80000001, 0)] {
                let native = Registers::new(0x1234, 0xf300_0000, 0x5678, 0x9abc);
                assert_eq!(
                    reply(
                        Generation::Vbs20,
                        vendor,
                        IntelIdentity::Core,
                        leaf,
                        subleaf,
                        || native
                    ),
                    crate::artifact::cpu::reply(vendor, leaf, subleaf, || native)
                );
            }
            let leaf1 = reply(Generation::Vbs20, vendor, IntelIdentity::Core, 1, 0, || {
                Registers::new(0, 0, 0, 0)
            });
            assert_eq!(leaf1[2] & (1 << 27 | 1 << 28), 1 << 27 | 1 << 28);
            assert_eq!(
                reply(
                    Generation::Vbs20,
                    vendor,
                    IntelIdentity::Core,
                    0xd,
                    0,
                    || panic!("fixed")
                )[0],
                0x207
            );
        }
    }

    #[test]
    fn vbs20_kuser_writes_keep_wine_xstate_and_feature_bytes() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            let mut page = [0xa5u8; crate::artifact::kuser::PAGE_SIZE];
            assert!(visit_writes(Generation::Vbs20, vendor, |at, byte| page
                [at] =
                byte));
            assert!(page[0x3d8..0x3e8].iter().all(|&b| b == 0xa5));
            assert!(page[0x3ec..0x600].iter().all(|&b| b == 0xa5));
            assert_eq!(page[0x285], 1);
            assert_eq!(page[0x29b], 1);
            assert_eq!(page[0x295], 1);
            assert_eq!(page[0x297], u8::from(vendor == Vendor::Amd));
        }
    }

    #[test]
    fn retains_brand_overrides_and_high_leaf_zero_range() {
        assert_eq!(
            reply(
                Generation::Vbs19,
                Vendor::Intel,
                IntelIdentity::Core,
                0x80000004,
                0,
                || panic!("fixed reply")
            ),
            [0; 4]
        );
        for vendor in [Vendor::Amd, Vendor::Intel] {
            assert_eq!(
                reply(
                    Generation::Vbs19,
                    vendor,
                    IntelIdentity::Core,
                    0x336934,
                    0,
                    || panic!("zero range")
                ),
                [0; 4]
            );
            assert_eq!(
                reply(
                    Generation::Vbs19,
                    vendor,
                    IntelIdentity::Core,
                    0x80000002,
                    0,
                    || panic!("brand")
                ),
                crate::artifact::cpu::reply(vendor, 0x80000002, 0, || panic!("brand"))
            );
        }
    }

    #[test]
    fn kuser_clears_exact_source_xstate_ranges_preserving_wine_clock_and_gaps() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            let mut page = [0xa5; crate::artifact::kuser::PAGE_SIZE];
            assert!(visit_writes(Generation::Vbs19, vendor, |at, byte| page
                [at] =
                byte));
            for at in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
                assert_eq!(page[at], 0);
            }
            for range in [0x3d8..0x3e8, 0x3ec..0x600, 0x604..0x804, 0x808..0x818] {
                assert!(page[range].iter().all(|b| *b == 0));
            }
            assert!(
                page[READY_MARKER_OFFSET..READY_MARKER_OFFSET + 4]
                    .iter()
                    .all(|b| *b == 0xa5)
            );
            for range in [
                0x3c6..0x3c8,
                0x3e8..0x3ec,
                0x600..0x604,
                0x804..0x808,
                0x818..0x820,
            ] {
                assert!(page[range].iter().all(|b| *b == 0xa5));
            }
        }
    }

    #[test]
    fn unknown_vendor_is_not_supported() {
        assert!(!visit_writes(
            Generation::Vbs19,
            Vendor::Unknown,
            |_, _| panic!("unsupported vendor")
        ));
    }

    #[test]
    fn pentium_identity_matches_the_1337_release_hypervisor() {
        let native = || Registers::new(0, 0xf300_0000, 0, 0);
        let pentium = IntelIdentity::Pentium4425Y;
        assert_eq!(
            reply(Generation::Vbs19, Vendor::Intel, pentium, 1, 0, native),
            [
                0x000a_0655,
                0xf320_0800,
                0x0000_0000_73fa_fbff & !0x7e00_1000,
                0xbfeb_fbff
            ]
        );
        let mut brand = [0u8; 48];
        for (i, leaf) in (0x8000_0002..=0x8000_0004).enumerate() {
            let words = reply(Generation::Vbs19, Vendor::Intel, pentium, leaf, 0, || {
                panic!("fixed brand")
            });
            for (j, word) in words.iter().enumerate() {
                brand[i * 16 + j * 4..][..4].copy_from_slice(&(*word as u32).to_le_bytes());
            }
        }
        assert_eq!(&brand[..40], b"Intel(R) Pentium(R) CPU 4425Y @ 1.70GHz\0");
        // AMD and other leaves are unaffected by the Intel identity.
        for vendor in [Vendor::Amd, Vendor::Intel] {
            assert_eq!(
                reply(Generation::Vbs19, vendor, pentium, 7, 0, || Registers::new(
                    1, 2, 3, 4
                )),
                reply(Generation::Vbs19, vendor, IntelIdentity::Core, 7, 0, || {
                    Registers::new(1, 2, 3, 4)
                })
            );
        }
        assert_eq!(
            reply(Generation::Vbs19, Vendor::Amd, pentium, 1, 0, native),
            reply(
                Generation::Vbs19,
                Vendor::Amd,
                IntelIdentity::Core,
                1,
                0,
                native
            )
        );
    }

    #[test]
    fn wine_view_range_follows_the_mapping_image_and_wine_bounds() {
        let (wine_start, wine_end) = crate::cpuid::wine_system_rip_range();
        // A file-backed game mapping below the Wine range: the whole mapping.
        let game = (0x1_4000_1000, 0x1_4520_0000);
        assert_eq!(
            constant_wine_view_range(0x1_4500_3dc3, game, false, None, 0),
            Some(game)
        );
        // Anonymous code is cut to its image and past closer, non-containing images.
        assert_eq!(
            constant_wine_view_range(0x5000, (0x1000, 0x9000), true, Some(0x7000), 0x3000),
            Some((0x3000, 0x7000))
        );
        // A closer image ending past the address leaves nothing to cache.
        assert_eq!(
            constant_wine_view_range(0x5000, (0x1000, 0x9000), true, Some(0x7000), 0x6000),
            None
        );
        // Mappings that straddle the Wine range bounds are cut at them.
        let straddle = (wine_start - 0x1000, wine_start + 0x1000);
        assert_eq!(
            constant_wine_view_range(wine_start - 0x10, straddle, false, None, 0),
            Some((wine_start - 0x1000, wine_start))
        );
        assert_eq!(
            constant_wine_view_range(wine_start + 0x10, straddle, false, None, 0),
            Some((wine_start, wine_start + 0x1000))
        );
        let above = (wine_end - 0x1000, wine_end + 0x1000);
        assert_eq!(
            constant_wine_view_range(wine_end + 0x10, above, false, None, 0),
            Some((wine_end, wine_end + 0x1000))
        );
    }

    #[test]
    fn pe_image_end_requires_a_valid_image() {
        let base = 0x6fff_ff6d_0000;
        let mut dos = [0u8; 64];
        dos[..2].copy_from_slice(b"MZ");
        dos[0x3c..].copy_from_slice(&0x80u32.to_le_bytes());
        let mut pe = [0u8; 84];
        pe[..4].copy_from_slice(b"PE\0\0");
        pe[4..6].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[24..26].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[80..84].copy_from_slice(&0x22000u32.to_le_bytes());
        assert_eq!(pe_image_end(base, &dos, &pe), Some(base + 0x22000));
        pe[4..6].copy_from_slice(&0x14cu16.to_le_bytes());
        assert_eq!(pe_image_end(base, &dos, &pe), None);
    }
}
