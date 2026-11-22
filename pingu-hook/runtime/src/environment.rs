//! Runs at `.init_array.00201`, after the debug and Gamescope setup and
//! before every module that depends on it. Decides whether this process is
//! the game's own `.exe` (not a Steam/Wine/launcher helper) and, if so,
//! forces the native DLL overrides pingu-hook needs. `game_process()` is the
//! flag every other module that behaves differently for the game process vs.
//! its helpers reads.
//! String parsing for the `WINEDLLOVERRIDES` value lives in the safe core
//! (`protocol/environment.rs`); this file owns argv inspection, the actual
//! `getenv`/`setenv` calls, and triggering `registry.rs`'s `HwProfileGuid`
//! write.
use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use pingu_protocol::environment::{
    CPU_TOPOLOGY_CAPACITY, already_present, cpu_topology, override_capacity, overrides,
};
use pingu_protocol::path::HookPath;

unsafe extern "C" {
    fn debug_log(message: *const c_char);
}

static GAME_PROCESS: AtomicBool = AtomicBool::new(false);

pub(crate) fn game_process() -> bool {
    GAME_PROCESS.load(Ordering::Acquire)
}

unsafe fn add_override(dll: &CStr) {
    let pointer = unsafe { libc::getenv(c"WINEDLLOVERRIDES".as_ptr()) };
    let existing = if pointer.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(pointer) })
    };
    if existing.is_some_and(|value| already_present(value.to_bytes(), dll.to_bytes())) {
        return;
    }
    let Some(capacity) = override_capacity(
        existing.map(|value| value.to_bytes().len()),
        dll.to_bytes().len(),
    ) else {
        unsafe { *libc::__errno_location() = libc::ENOMEM };
        return;
    };
    let output = unsafe { libc::malloc(capacity).cast::<c_char>() };
    if output.is_null() {
        return;
    }
    unsafe {
        fill_override(output, existing, dll);
        libc::setenv(c"WINEDLLOVERRIDES".as_ptr(), output, 1);
        libc::free(output.cast());
    }
}

unsafe fn fill_override(output: *mut c_char, existing: Option<&CStr>, dll: &CStr) {
    let prefix = existing.map_or(b"".as_slice(), CStr::to_bytes);
    unsafe {
        let mut position = 0;
        if !prefix.is_empty() {
            ptr::copy_nonoverlapping(prefix.as_ptr().cast(), output, prefix.len());
            position = prefix.len();
            output.add(position).write(b';' as c_char);
            position += 1;
        }
        ptr::copy_nonoverlapping(dll.as_ptr(), output.add(position), dll.to_bytes().len());
        position += dll.to_bytes().len();
        ptr::copy_nonoverlapping(c"=n,b".as_ptr(), output.add(position), 5);
    }
}

fn equal_name(actual: &[u8], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(&left, &right)| left.eq_ignore_ascii_case(&right))
}

fn is_exe(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && equal_name(&bytes[bytes.len() - 4..], b".exe")
}

fn is_helper_basename(executable: &[u8]) -> bool {
    let basename = executable
        .rsplit(|&byte| byte == b'/' || byte == b'\\')
        .next()
        .unwrap_or(executable);
    const HELPERS: [&[u8]; 10] = [
        b"steam.exe",
        b"steamwebhelper.exe",
        b"crashhandler.exe",
        b"winecfg.exe",
        b"start.exe",
        b"rundll32.exe",
        b"dllhost.exe",
        b"conhost.exe",
        b"explorer.exe",
        b"xalia.exe",
    ];
    HELPERS.iter().any(|name| equal_name(basename, name))
}

fn is_system32_helper(executable: &[u8]) -> bool {
    let mut lowered = [0u8; 512];
    if executable.len() >= lowered.len() {
        return false;
    }
    for (index, &byte) in executable.iter().enumerate() {
        lowered[index] = if byte == b'\\' {
            b'/'
        } else {
            byte.to_ascii_lowercase()
        };
    }
    let path = &lowered[..executable.len()];
    path.windows(b"/windows/system32/".len())
        .any(|window| window == b"/windows/system32/")
        || path
            .windows(b"/windows/syswow64/".len())
            .any(|window| window == b"/windows/syswow64/")
}

fn argv0_is_unix_loader(bytes: &[u8]) -> bool {
    bytes
        .windows(b"wine-preloader".len())
        .any(|window| window == b"wine-preloader")
        || bytes
            .windows(b"wine64-preloader".len())
            .any(|window| window == b"wine64-preloader")
        || bytes
            .windows(b"wineserver".len())
            .any(|window| window == b"wineserver")
        || bytes
            .windows(b"pressure-vessel".len())
            .any(|window| window == b"pressure-vessel")
}

fn game_executable_argument(argc: c_int, argv: *const *const c_char) -> Option<*const c_char> {
    if argc < 1 || argv.is_null() {
        return None;
    }
    let argv0 = unsafe { *argv };
    if !argv0.is_null() && argv0_is_unix_loader(unsafe { CStr::from_ptr(argv0) }.to_bytes()) {
        // Preloader/wineserver may mention the game path without being the PE.
        // Only count a Windows-drive .exe that is not a system helper.
        let mut windows_game = None;
        for index in 1..argc as usize {
            let candidate = unsafe { *argv.add(index) };
            if candidate.is_null() {
                continue;
            }
            let bytes = unsafe { CStr::from_ptr(candidate) }.to_bytes();
            if !is_exe(bytes) {
                continue;
            }
            if bytes.len() < 2 || bytes[1] != b':' {
                continue;
            }
            if is_system32_helper(bytes) || is_helper_basename(bytes) {
                return None;
            }
            windows_game = Some(candidate);
        }
        return windows_game;
    }
    let mut windows_game = None;
    let mut unix_game = None;
    let mut windows_helper = false;
    for index in 0..argc as usize {
        let candidate = unsafe { *argv.add(index) };
        if candidate.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr(candidate) }.to_bytes();
        if !is_exe(bytes) {
            continue;
        }
        if is_system32_helper(bytes) || is_helper_basename(bytes) {
            windows_helper = true;
            continue;
        }
        if bytes.len() >= 2 && bytes[1] == b':' {
            windows_game = Some(candidate);
        } else if bytes.starts_with(b"/") {
            unix_game = Some(candidate);
        }
    }
    windows_game.or(if windows_helper { None } else { unix_game })
}

/// Limits Wine to Artifact's processor count on larger hosts unless the user
/// already chose a `WINE_CPU_TOPOLOGY` (see `ARTIFACT_MAX_CPUS`).
unsafe fn cap_cpu_topology() {
    let value = unsafe { libc::getenv(c"WINE_CPU_TOPOLOGY".as_ptr()) };
    if !value.is_null() && unsafe { value.read() } != 0 {
        return;
    }
    let mut set: libc::cpu_set_t = unsafe { core::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &mut set) } != 0
    {
        return;
    }
    let cpus = (0..libc::CPU_SETSIZE as usize).filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) });
    let mut topology = [0u8; CPU_TOPOLOGY_CAPACITY];
    if cpu_topology(cpus, &mut topology).is_some() {
        // Overwrite: an exported empty value must not keep the cap off.
        unsafe { libc::setenv(c"WINE_CPU_TOPOLOGY".as_ptr(), topology.as_ptr().cast(), 1) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pingu_setup_environment(
    argc: c_int,
    argv: *const *const c_char,
    _envp: *const *const c_char,
) {
    unsafe {
        crate::registry::init_registry();
        let game_process = game_executable_argument(argc, argv).is_some();
        GAME_PROCESS.store(game_process, Ordering::Release);
        debug_log(match crate::path::active() {
            HookPath::Reflex => c"hook path: reflex".as_ptr(),
            HookPath::Artifact => c"hook path: artifact".as_ptr(),
        });
        if libc::getenv(c"PINGU_HOOK".as_ptr()).is_null() {
            libc::setenv(c"PINGU_HOOK".as_ptr(), c"1".as_ptr(), 0);
            let value = libc::getenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr());
            if value.is_null() || value.read() == 0 {
                libc::setenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr(), c"1".as_ptr(), 0);
            }
            if crate::path::is_artifact() {
                cap_cpu_topology();
            }
        }
        if game_process {
            for dll in overrides(crate::path::active()) {
                add_override(dll);
            }
        }
    }
}

#[used]
#[unsafe(link_section = ".init_array.00201")]
static INITIALIZE: unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) =
    pingu_setup_environment;
