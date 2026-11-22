//! The `WINEDLLOVERRIDES` string manipulation pingu-hook needs to force native
//! DLL overrides for a detected game process: which DLLs to override, and
//! how to parse/extend the existing `;`-delimited value without duplicating
//! an entry. Pure byte-slice logic so it can be unit tested without libc;
//! `runtime/src/environment.rs` owns reading/writing the actual environment
//! variable and deciding whether the current process is a game process.
use crate::path::HookPath;
use core::ffi::CStr;

/// The Reflex path also forces the Reflex and Denuvo helper DLLs native.
pub const REFLEX_OVERRIDES: [&CStr; 16] = [
    c"winmm",
    c"version",
    c"reflex",
    c"reflex64",
    c"DenuvOwO",
    c"artifact",
    c"d3d9",
    c"d3d10",
    c"d3d11",
    c"d3d12",
    c"dinput8",
    c"dsound",
    c"dxgi",
    c"hid",
    c"wininet",
    c"winhttp",
];

pub const ARTIFACT_OVERRIDES: [&CStr; 13] = [
    c"winmm",
    c"version",
    c"artifact",
    c"d3d9",
    c"d3d10",
    c"d3d11",
    c"d3d12",
    c"dinput8",
    c"dsound",
    c"dxgi",
    c"hid",
    c"wininet",
    c"winhttp",
];

/// The DLL overrides forced native for a game process on `path`.
pub const fn overrides(path: HookPath) -> &'static [&'static CStr] {
    match path {
        HookPath::Reflex => &REFLEX_OVERRIDES,
        HookPath::Artifact => &ARTIFACT_OVERRIDES,
    }
}

pub fn already_present(existing: &[u8], dll: &[u8]) -> bool {
    dll.is_empty()
        || existing
            .split(|&byte| byte == b';')
            .any(|entry| entry.split(|&byte| byte == b'=').next() == Some(dll))
}

pub fn override_capacity(existing: Option<usize>, dll_length: usize) -> Option<usize> {
    let prefix = match existing {
        Some(length) => length.checked_add(1)?,
        None => 0,
    };
    prefix.checked_add(dll_length)?.checked_add(5)
}

/// Artifact presents at most this many processors in the PEB that game code
/// reads, while Wine checks some requests against the host's real count. On
/// larger hosts the two disagree: Wine's `SystemFunction036` asks for random
/// bytes sized for 16 CPUs and Wine rejects the request, so `rand_s` and
/// `std::random_device` fail (Planet Zoo 2's DirectStorage stops at startup).
pub const ARTIFACT_MAX_CPUS: usize = 16;

/// `"16:"`, up to 16 four-digit CPU numbers with separators, and a NUL.
pub const CPU_TOPOLOGY_CAPACITY: usize = 3 + ARTIFACT_MAX_CPUS * 5 + 1;

/// Builds a NUL-terminated `WINE_CPU_TOPOLOGY` value that limits Wine to the
/// first `ARTIFACT_MAX_CPUS` of `cpus` (ascending host CPU numbers). Returns
/// the value length without the NUL, or `None` when no cap is needed or a
/// CPU number does not fit.
pub fn cpu_topology(
    cpus: impl IntoIterator<Item = usize>,
    output: &mut [u8; CPU_TOPOLOGY_CAPACITY],
) -> Option<usize> {
    let mut chosen = [0usize; ARTIFACT_MAX_CPUS];
    for (count, cpu) in cpus.into_iter().enumerate() {
        if count == ARTIFACT_MAX_CPUS {
            return write_topology(&chosen, output);
        }
        chosen[count] = cpu;
    }
    None
}

fn write_topology(cpus: &[usize], output: &mut [u8; CPU_TOPOLOGY_CAPACITY]) -> Option<usize> {
    let mut position = 0;
    let mut push = |byte: u8| {
        *output.get_mut(position)? = byte;
        position += 1;
        Some(())
    };
    push_decimal(&mut push, cpus.len())?;
    push(b':')?;
    for (index, &cpu) in cpus.iter().enumerate() {
        if cpu > 9999 {
            return None;
        }
        if index > 0 {
            push(b',')?;
        }
        push_decimal(&mut push, cpu)?;
    }
    push(0)?;
    Some(position - 1)
}

fn push_decimal(push: &mut impl FnMut(u8) -> Option<()>, value: usize) -> Option<()> {
    let mut digits = [0u8; 20];
    let mut length = 0;
    let mut rest = value;
    loop {
        digits[length] = b'0' + (rest % 10) as u8;
        length += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    digits[..length]
        .iter()
        .rev()
        .try_for_each(|&digit| push(digit))
}

#[cfg(test)]
mod tests {
    use super::{ARTIFACT_OVERRIDES, CPU_TOPOLOGY_CAPACITY, REFLEX_OVERRIDES, cpu_topology};

    struct Topology([u8; CPU_TOPOLOGY_CAPACITY], usize);

    impl Topology {
        fn bytes(&self) -> &[u8] {
            &self.0[..self.1]
        }
    }

    fn topology(cpus: impl IntoIterator<Item = usize>) -> Option<Topology> {
        let mut output = [0xff; CPU_TOPOLOGY_CAPACITY];
        let length = cpu_topology(cpus, &mut output)?;
        assert_eq!(output[length], 0);
        Some(Topology(output, length))
    }

    #[test]
    fn artifact_is_forced_native_for_game_processes() {
        for table in [&REFLEX_OVERRIDES[..], &ARTIFACT_OVERRIDES[..]] {
            assert!(table.iter().any(|dll| dll.to_bytes() == b"artifact"));
        }
    }

    #[test]
    fn hosts_with_sixteen_or_fewer_cpus_are_left_alone() {
        assert!(topology(0..12).is_none());
        assert!(topology(0..16).is_none());
        assert!(topology([]).is_none());
    }

    #[test]
    fn larger_hosts_are_capped_to_the_first_sixteen_cpus() {
        assert_eq!(
            topology(0..32).as_ref().map(Topology::bytes),
            Some(b"16:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15".as_slice())
        );
        assert_eq!(
            topology(0..17).as_ref().map(Topology::bytes),
            Some(b"16:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15".as_slice())
        );
    }

    #[test]
    fn sparse_affinity_masks_keep_their_cpu_numbers() {
        assert_eq!(
            topology((0..40).map(|cpu| cpu * 2 + 1))
                .as_ref()
                .map(Topology::bytes),
            Some(b"16:1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31".as_slice())
        );
    }

    #[test]
    fn four_digit_cpu_numbers_fit_and_larger_ones_are_rejected() {
        let value = topology(9980..10000).expect("four-digit CPUs fit");
        assert_eq!(value.bytes().len(), 3 + 16 * 4 + 15);
        assert!(topology(9990..10010).is_none());
    }
}
