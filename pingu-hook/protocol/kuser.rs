//! `KUSER_SHARED_DATA` patch recipes and the state machine that arbitrates
//! between them. A [`Recipe`] is a byte-offset write list for one of the
//! title families in `docs/protocol/game-quirks.md` (resume/selector/
//! dispatch); [`PatchState`] tracks which recipe (if any) has been applied
//! to the live shared page, so a later request for a different, compatible
//! recipe waits or is rejected instead of corrupting a page mid-write. This
//! file only describes *what* to write and *whether* a given recipe may
//! apply now; `runtime/src/kuser.rs` owns the actual page, its
//! `mprotect`/`PageGuard` locking, and the `PINGU_SYSCALL_HACK` control
//! that writes into the recipe's applied page afterward (see
//! `docs/protocol/topspin-investigation.md` for why that flag still exists).
use core::sync::atomic::{AtomicU32, Ordering};

pub const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Recipe {
    Resume = 0,
    Selector = 1,
    Dispatch = 2,
    /// Artifact variant 2 (the default) on an Intel host.
    Variant2Intel = 3,
    /// Artifact variant 2 (the default) on an AMD host.
    Variant2Amd = 4,
    /// Artifact variant 1: handlers that use the `0x1337` bypass (Anno 117, F1 25).
    Variant1 = 5,
    /// Artifact variant 3: variant 2's protocol, but XSAVE/AVX hidden everywhere
    /// (FM27's November SimpleSvm profile).
    Variant3 = 6,
}

impl Recipe {
    pub const fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Resume),
            1 => Some(Self::Selector),
            2 => Some(Self::Dispatch),
            3 => Some(Self::Variant2Intel),
            4 => Some(Self::Variant2Amd),
            5 => Some(Self::Variant1),
            6 => Some(Self::Variant3),
            _ => None,
        }
    }

    pub fn visit_writes(self, avx_enabled: bool, mut write: impl FnMut(usize, u8)) {
        let ops: &[(usize, usize, u64)] = match self {
            Self::Dispatch => DISPATCH_OPS,
            Self::Selector => SELECTOR_OPS,
            Self::Resume => {
                for (index, byte) in b"C:\\Windows\0".iter().copied().enumerate() {
                    write(0x30 + index * 2, byte);
                    write(0x31 + index * 2, 0);
                }
                for offset in 0x46..0x134 {
                    write(offset, 0);
                }
                RESUME_OPS
            }
            Self::Variant2Intel | Self::Variant2Amd | Self::Variant1 | Self::Variant3 => {
                for (index, byte) in b"C:\\Windows\0".iter().copied().enumerate() {
                    write(0x30 + index * 2, byte);
                    write(0x31 + index * 2, 0);
                }
                for offset in 0x46..0x134 {
                    write(offset, 0);
                }
                ARTIFACT_OPS
            }
        };
        for &(offset, size, value) in ops {
            for (index, byte) in value.to_le_bytes()[..size].iter().copied().enumerate() {
                write(offset + index, byte);
            }
        }
        match self {
            Self::Resume => {
                for offset in [0x290, 0x294, 0x295, 0x297] {
                    write(offset, 0);
                }
                if !avx_enabled {
                    for offset in [0x285, 0x29b, 0x29c] {
                        write(offset, 0);
                    }
                }
                for offset in (0x3f0..0x5f0).chain(0x604..0x804) {
                    write(offset, 0);
                }
            }
            Self::Variant2Intel => {
                write(0x297, 0);
                write(0x295, 1);
            }
            Self::Variant2Amd => {
                write(0x295, 1);
                // VBS.cmd's Windows prerequisite removes all XCR0 components
                // above AVX. Present that OS state in the KUSER XState fields
                // instead of Wine's host AVX-512 mask; the SimpleSvm source
                // assumes this prerequisite is met.
                for (offset, value) in [(0x3d8, 7u64), (0x3e0, 7u64)] {
                    for (index, byte) in value.to_le_bytes().into_iter().enumerate() {
                        write(offset + index, byte);
                    }
                }
                for (index, byte) in 0x340u32.to_le_bytes().into_iter().enumerate() {
                    write(0x3e8 + index, byte);
                }
            }
            Self::Variant1 => {
                for offset in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
                    write(offset, 0);
                }
                for offset in (0x3d8..0x3e8)
                    .chain(0x3ec..0x600)
                    .chain(0x604..0x804)
                    .chain(0x808..0x818)
                {
                    write(offset, 0);
                }
                // The game waits for this word, which the hypervisor writes last.
                for (index, byte) in 0x1337_1337u32.to_le_bytes().into_iter().enumerate() {
                    write(0xffc + index, byte);
                }
            }
            Self::Variant3 => {
                // The same hidden-feature clearing as Variant1, but variant 2's
                // protocol has no 0xffc marker and Wine's 0x3e8 gap stays.
                for offset in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
                    write(offset, 0);
                }
                for offset in (0x3d8..0x3e8)
                    .chain(0x3ec..0x600)
                    .chain(0x604..0x804)
                    .chain(0x808..0x818)
                {
                    write(offset, 0);
                }
            }
            Self::Dispatch | Self::Selector => {}
        }
    }
}

const ARTIFACT_OPS: &[(usize, usize, u64)] = &[
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
    (0x3c0, 8, 0x0083000100000010),
];

const RESUME_OPS: &[(usize, usize, u64)] = &[
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
    (0x3d8, 8, 0),
    (0x3e0, 8, 0),
    (0x3ec, 4, 0),
    (0x5f0, 8, 0),
    (0x5f8, 8, 0),
    (0x808, 8, 0),
    (0x810, 8, 0),
    (0x2d0, 8, 0x00320A0000000110),
    (0x2e8, 8, 0x00000100007FB10B),
    (0x2f4, 4, 0),
    (0x36c, 8, 0),
    (0x374, 8, 0),
    (0x37c, 4, 1),
    (0x3c0, 8, 0x0083000100000010),
    (0xffc, 4, 0x13371337),
];

const DISPATCH_OPS: &[(usize, usize, u64)] = &[
    (0x26e, 8, 0),
    (0x283, 8, 0x0101010000010000),
    (0x288, 8, 0x0000000001010101),
    (0x268, 8, 0x0000000A00090001),
    (0x261, 8, 0x0100000001000066),
    (0x272, 8, 0x0000010100000000),
    (0x3c0, 4, 0x10),
    (0x260, 8, 0x0000000100006658),
    (0x282, 8, 0x0101000001000001),
    (0x2d0, 4, 0x0110),
    (0x2e8, 4, 0x007FB10B),
    (0x378, 4, 0),
    (0x2e8, 8, 0x00000100007FB10B),
    (0x273, 8, 0x0100000101000000),
    (0x2d0, 8, 0x00320A0000000110),
    (0x000, 8, 0x0FA0000000000000),
    (0x378, 8, 0x0000000100000000),
    (0x3c0, 8, 0x0083000100000010),
    (0x26c, 8, 0x000000000000000A),
    (0x2f4, 4, 0),
    (0x264, 4, 1),
    (0x270, 4, 0),
    (0x281, 8, 0x0100000100000101),
];

const SELECTOR_OPS: &[(usize, usize, u64)] = &[
    (0x2d6, 4, 0x0001_0034),
    (0x2e8, 4, 0x00bf_9c8f),
    (0x3c0, 4, 0x0000_0010),
    (0x288, 4, 0x0101_0101),
    (0x268, 4, 0x0009_0001),
    (0x2f4, 4, 0),
    (0x264, 4, 1),
    (0x2d0, 4, 0x0000_0310),
    (0x260, 4, 0x0000_6658),
    (0x26c, 4, 0x0000_000a),
    (0x270, 4, 0),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchError {
    Conflict,
    ApplyFailed,
}

const PATCH_UNAPPLIED: u32 = 0;
const PATCH_RESUME_APPLYING: u32 = 1;
const PATCH_RESUME_READY: u32 = 2;
const PATCH_RESUME_FAILED: u32 = 3;
const PATCH_DISPATCH_APPLYING: u32 = 4;
const PATCH_DISPATCH_READY: u32 = 5;
const PATCH_DISPATCH_FAILED: u32 = 6;
const PATCH_SELECTOR_APPLYING: u32 = 7;
const PATCH_SELECTOR_READY: u32 = 8;
const PATCH_SELECTOR_FAILED: u32 = 9;
const PATCH_VARIANT2_INTEL_APPLYING: u32 = 10;
const PATCH_VARIANT2_INTEL_READY: u32 = 11;
const PATCH_VARIANT2_INTEL_FAILED: u32 = 12;
const PATCH_VARIANT2_AMD_APPLYING: u32 = 13;
const PATCH_VARIANT2_AMD_READY: u32 = 14;
const PATCH_VARIANT2_AMD_FAILED: u32 = 15;
const PATCH_VARIANT1_APPLYING: u32 = 16;
const PATCH_VARIANT1_READY: u32 = 17;
const PATCH_VARIANT1_FAILED: u32 = 18;
const PATCH_ARTIFACT_VARIANT3_APPLYING: u32 = 19;
const PATCH_ARTIFACT_VARIANT3_READY: u32 = 20;
const PATCH_ARTIFACT_VARIANT3_FAILED: u32 = 21;
const PATCH_WAIT_LIMIT: u32 = 4096;

#[derive(Debug, Default)]
pub struct PatchState(AtomicU32);

impl PatchState {
    pub const fn new() -> Self {
        Self(AtomicU32::new(PATCH_UNAPPLIED))
    }

    pub fn recover_after_fork(&self) {
        let _ = self
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| match state {
                PATCH_RESUME_APPLYING => Some(PATCH_RESUME_FAILED),
                PATCH_DISPATCH_APPLYING => Some(PATCH_DISPATCH_FAILED),
                PATCH_SELECTOR_APPLYING => Some(PATCH_SELECTOR_FAILED),
                PATCH_VARIANT2_INTEL_APPLYING => Some(PATCH_VARIANT2_INTEL_FAILED),
                PATCH_VARIANT2_AMD_APPLYING => Some(PATCH_VARIANT2_AMD_FAILED),
                PATCH_VARIANT1_APPLYING => Some(PATCH_VARIANT1_FAILED),
                PATCH_ARTIFACT_VARIANT3_APPLYING => Some(PATCH_ARTIFACT_VARIANT3_FAILED),
                _ => None,
            });
    }

    pub fn patch(
        &self,
        recipe: Recipe,
        apply: impl FnOnce() -> bool,
        mut wait: impl FnMut(),
    ) -> Result<(), PatchError> {
        let (applying_state, ready_state, failed_state) = match recipe {
            Recipe::Resume => (
                PATCH_RESUME_APPLYING,
                PATCH_RESUME_READY,
                PATCH_RESUME_FAILED,
            ),
            Recipe::Dispatch => (
                PATCH_DISPATCH_APPLYING,
                PATCH_DISPATCH_READY,
                PATCH_DISPATCH_FAILED,
            ),
            Recipe::Selector => (
                PATCH_SELECTOR_APPLYING,
                PATCH_SELECTOR_READY,
                PATCH_SELECTOR_FAILED,
            ),
            Recipe::Variant2Intel => (
                PATCH_VARIANT2_INTEL_APPLYING,
                PATCH_VARIANT2_INTEL_READY,
                PATCH_VARIANT2_INTEL_FAILED,
            ),
            Recipe::Variant2Amd => (
                PATCH_VARIANT2_AMD_APPLYING,
                PATCH_VARIANT2_AMD_READY,
                PATCH_VARIANT2_AMD_FAILED,
            ),
            Recipe::Variant1 => (
                PATCH_VARIANT1_APPLYING,
                PATCH_VARIANT1_READY,
                PATCH_VARIANT1_FAILED,
            ),
            Recipe::Variant3 => (
                PATCH_ARTIFACT_VARIANT3_APPLYING,
                PATCH_ARTIFACT_VARIANT3_READY,
                PATCH_ARTIFACT_VARIANT3_FAILED,
            ),
        };
        let mut completion_state = failed_state;
        let mut waits = 0;
        loop {
            let current = self.0.load(Ordering::Acquire);
            if current == ready_state {
                return Ok(());
            }
            let another_recipe_apply = matches!(
                current,
                PATCH_DISPATCH_APPLYING
                    | PATCH_SELECTOR_APPLYING
                    | PATCH_VARIANT2_INTEL_APPLYING
                    | PATCH_VARIANT2_AMD_APPLYING
                    | PATCH_VARIANT1_APPLYING
                    | PATCH_ARTIFACT_VARIANT3_APPLYING
            );
            if another_recipe_apply && current != applying_state {
                if waits == PATCH_WAIT_LIMIT {
                    return Err(PatchError::Conflict);
                }
                waits += 1;
                wait();
                continue;
            }
            if current != PATCH_UNAPPLIED && !(applying_state..=failed_state).contains(&current) {
                let can_transition_from_recipe = recipe != Recipe::Resume
                    && matches!(
                        current,
                        PATCH_RESUME_READY
                            | PATCH_RESUME_FAILED
                            | PATCH_DISPATCH_READY
                            | PATCH_DISPATCH_FAILED
                            | PATCH_SELECTOR_READY
                            | PATCH_SELECTOR_FAILED
                            | PATCH_VARIANT2_INTEL_READY
                            | PATCH_VARIANT2_INTEL_FAILED
                            | PATCH_VARIANT2_AMD_READY
                            | PATCH_VARIANT2_AMD_FAILED
                            | PATCH_VARIANT1_READY
                            | PATCH_VARIANT1_FAILED
                            | PATCH_ARTIFACT_VARIANT3_READY
                            | PATCH_ARTIFACT_VARIANT3_FAILED
                    );
                if !can_transition_from_recipe {
                    return Err(PatchError::Conflict);
                }
                completion_state = current;
            }
            if current == applying_state {
                if waits == PATCH_WAIT_LIMIT {
                    return Err(PatchError::Conflict);
                }
                waits += 1;
                wait();
                continue;
            }
            if self
                .0
                .compare_exchange_weak(current, applying_state, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        struct Completion<'a> {
            patch_state: &'a AtomicU32,
            completion_state: u32,
        }
        impl Drop for Completion<'_> {
            fn drop(&mut self) {
                self.patch_state
                    .store(self.completion_state, Ordering::Release);
            }
        }
        let mut completion = Completion {
            patch_state: &self.0,
            completion_state,
        };
        if apply() {
            completion.completion_state = ready_state;
            Ok(())
        } else {
            Err(PatchError::ApplyFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PAGE_SIZE, Recipe};

    #[test]
    fn artifact_recipes_keep_xsave_and_omit_ready_marker() {
        let mut intel = [0xffu8; PAGE_SIZE];
        Recipe::Variant2Intel.visit_writes(false, |offset, byte| intel[offset] = byte);
        assert_eq!(intel[0x285], 1);
        assert_eq!(intel[0x295], 1);
        assert_eq!(intel[0x297], 0);
        assert_eq!(intel[0x29c], 1);
        assert_eq!(intel[0x3d8], 0xff);
        assert_eq!(&intel[0xffc..0x1000], &[0xff; 4]);

        let mut amd = [0xffu8; PAGE_SIZE];
        Recipe::Variant2Amd.visit_writes(false, |offset, byte| amd[offset] = byte);
        assert_eq!(amd[0x285], 1);
        assert_eq!(amd[0x295], 1);
        assert_eq!(amd[0x297], 1);
        assert_eq!(amd[0x29c], 1);
        assert_eq!(u64::from_le_bytes(amd[0x3d8..0x3e0].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(amd[0x3e0..0x3e8].try_into().unwrap()), 7);
        assert_eq!(
            u32::from_le_bytes(amd[0x3e8..0x3ec].try_into().unwrap()),
            0x340
        );
        assert_eq!(&amd[0xffc..0x1000], &[0xff; 4]);
    }

    #[test]
    fn variant1_recipe_hides_xstate_and_publishes_the_ready_marker() {
        let mut page = [0xa5u8; PAGE_SIZE];
        Recipe::Variant1.visit_writes(true, |offset, byte| page[offset] = byte);
        for offset in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
            assert_eq!(page[offset], 0);
        }
        for range in [0x3d8..0x3e8, 0x3ec..0x600, 0x604..0x804, 0x808..0x818] {
            assert!(page[range].iter().all(|byte| *byte == 0));
        }
        assert_eq!(&page[0xffc..0x1000], &0x1337_1337u32.to_le_bytes());
        // Wine owns the clock fields and the gaps between the cleared ranges.
        for range in [0x3e8..0x3ec, 0x600..0x604, 0x804..0x808, 0x818..0x820] {
            assert!(page[range].iter().all(|byte| *byte == 0xa5));
        }
        assert_eq!(Recipe::from_raw(5), Some(Recipe::Variant1));
    }

    #[test]
    fn variant3_recipe_hides_xstate_without_a_ready_marker() {
        let mut page = [0xa5u8; PAGE_SIZE];
        Recipe::Variant3.visit_writes(true, |offset, byte| page[offset] = byte);
        for offset in [0x285, 0x290, 0x294, 0x295, 0x297, 0x29b, 0x29c] {
            assert_eq!(page[offset], 0);
        }
        for range in [0x3d8..0x3e8, 0x3ec..0x600, 0x604..0x804, 0x808..0x818] {
            assert!(page[range].iter().all(|byte| *byte == 0));
        }
        // Variant 3 has no ready marker at 0xffc and leaves Wine's
        // 0x3e8 clock field alone.
        assert_eq!(&page[0xffc..0x1000], &[0xa5; 4]);
        assert_eq!(&page[0x3e8..0x3ec], &[0xa5; 4]);
        // The shared Artifact block still applies.
        assert_eq!(&page[0x30..0x32], b"C\0");
        assert_eq!(Recipe::from_raw(6), Some(Recipe::Variant3));
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::*;

    #[test]
    fn older_ready_page_is_not_mistaken_for_the_artifact_recipe() {
        let state = PatchState::new();
        assert_eq!(state.patch(Recipe::Resume, || true, || {}), Ok(()));
        let mut applied = false;
        assert_eq!(
            state.patch(
                Recipe::Variant2Amd,
                || {
                    applied = true;
                    true
                },
                || {}
            ),
            Ok(())
        );
        assert!(applied);
        assert_eq!(
            state.patch(
                Recipe::Resume,
                || panic!("must reject incompatible recipe"),
                || {}
            ),
            Err(PatchError::Conflict)
        );
    }
}
