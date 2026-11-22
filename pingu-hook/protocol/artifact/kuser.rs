//! Artifact `KUSER_SHARED_DATA` identity writes.
use crate::cpuid::Vendor;

pub use crate::PAGE_SIZE;

fn visit_system_root(write: &mut impl FnMut(usize, u8)) {
    for (index, byte) in b"C:\\Windows\0".iter().copied().enumerate() {
        write(0x30 + index * 2, byte);
        write(0x31 + index * 2, 0);
    }
    for offset in 0x46..0x134 {
        write(offset, 0);
    }
}

fn visit_ops(ops: &[(usize, usize, u64)], write: &mut impl FnMut(usize, u8)) {
    for &(offset, size, value) in ops {
        for (index, byte) in value.to_le_bytes()[..size].iter().copied().enumerate() {
            write(offset + index, byte);
        }
    }
}

/// Source ART identity metadata.
/// QpcData stays native: Wine, not the source Windows kernel, owns its clock.
pub fn visit_artifact_writes(vendor: Vendor, mut write: impl FnMut(usize, u8)) -> bool {
    if vendor == Vendor::Unknown {
        return false;
    }
    visit_system_root(&mut write);
    visit_ops(IDENTITY_OPS, &mut write);
    if vendor == Vendor::Intel {
        write(0x297, 0);
    }
    true
}

const IDENTITY_OPS: &[(usize, usize, u64)] = &[
    (0x260, 8, 0x0000000100006658),
    (0x268, 4, 0x00090001),
    (0x26c, 4, 0x0000000a),
    (0x270, 4, 0),
    (0x274, 4, 0x01010000),
    (0x278, 4, 0x00010000),
    (0x27c, 4, 0x00010101),
    (0x280, 4, 0x00010101),
    (0x284, 4, 0x00000100),
    (0x288, 4, 0x01010101),
    (0x28c, 4, 0),
    (0x290, 4, 1),
    (0x294, 4, 0x01000101),
    (0x298, 4, 0x01010101),
    (0x29c, 4, 0x00010001),
    (0x2a0, 4, 0),
    (0x2a4, 4, 0),
    (0x2a8, 4, 0),
    (0x2ac, 4, 0),
    (0x2b0, 4, 1),
    (0x2d0, 8, 0x00320A0000000110),
    (0x2e8, 8, 0x00000100007FB10B),
    (0x2f4, 4, 0),
    (0x36c, 8, 0),
    (0x374, 8, 0),
    (0x37c, 4, 1),
    (0x3c0, 6, 0x0000000100000010),
];

#[cfg(test)]
mod artifact_tests {
    use crate::cpuid::{Registers, Vendor};

    #[test]
    fn artifact_shared_cpu_count_agrees_with_the_registered_cpuid_view() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            let mut page = [0xa5u8; super::PAGE_SIZE];
            page[0x3c0..0x3c4].copy_from_slice(&12u32.to_le_bytes());
            assert!(super::visit_artifact_writes(vendor, |offset, byte| page
                [offset] =
                byte));
            let cpuid = crate::artifact::cpu::reply(vendor, 1, 0, || Registers::new(0, 0, 0, 0));
            let count = u32::from_le_bytes(page[0x3c0..0x3c4].try_into().unwrap());
            assert_eq!(u64::from(count), (cpuid[1] >> 16) & 0xff);
            assert_eq!(page[0x297], u8::from(vendor == Vendor::Amd));
        }
    }

    #[test]
    fn artifact_identity_does_not_replace_native_clock_controls_or_xstate() {
        for vendor in [Vendor::Amd, Vendor::Intel] {
            let mut page = [0xa5u8; super::PAGE_SIZE];
            page[0x3c6..0x3c8].copy_from_slice(&[0x12, 0x34]);
            let before = page;
            assert!(super::visit_artifact_writes(vendor, |offset, byte| page
                [offset] =
                byte));
            for range in [
                0x8..0x20,
                0x2e4..0x2e8,
                0x300..0x368,
                0x3c6..0x3c8,
                0x3d8..0x820,
                0xffc..0x1000,
            ] {
                assert_eq!(page[range.clone()], before[range]);
            }
        }
    }
}
