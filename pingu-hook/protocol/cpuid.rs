//! CPUID register types, host CPU vendor detection, and Wine system RIP bounds.
use core::sync::atomic::{AtomicU8, Ordering};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Vendor {
    Unknown = 0,
    Intel = 1,
    Amd = 2,
}

impl Vendor {
    pub fn from_leaf0(registers: Registers) -> Self {
        match (registers.ebx, registers.edx, registers.ecx) {
            (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => Self::Intel,
            (0x6874_7541, 0x6974_6e65, 0x444d_4163) => Self::Amd,
            _ => Self::Unknown,
        }
    }

    const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Intel,
            2 => Self::Amd,
            _ => Self::Unknown,
        }
    }
}

const WINE_SYSTEM_RIP_MIN: u64 = 0x0000_6fff_ff00_0000;
const WINE_SYSTEM_RIP_MAX: u64 = 0x0000_7000_0000_0000;

pub fn is_wine_system_rip(address: u64) -> bool {
    (WINE_SYSTEM_RIP_MIN..WINE_SYSTEM_RIP_MAX).contains(&address)
}

/// The address range [`is_wine_system_rip`] accepts.
pub const fn wine_system_rip_range() -> (u64, u64) {
    (WINE_SYSTEM_RIP_MIN, WINE_SYSTEM_RIP_MAX)
}

#[derive(Debug)]
pub struct ActiveVendor(AtomicU8);

impl ActiveVendor {
    pub const fn new() -> Self {
        Self(AtomicU8::new(Vendor::Unknown as u8))
    }

    pub fn load(&self) -> Vendor {
        Vendor::from_raw(self.0.load(Ordering::Acquire))
    }

    pub fn store(&self, vendor: Vendor) {
        self.0.store(vendor as u8, Ordering::Release);
    }
}

impl Default for ActiveVendor {
    fn default() -> Self {
        Self::new()
    }
}
