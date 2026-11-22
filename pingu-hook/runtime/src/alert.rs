//! Fails loud when a game loads Denuvo's `artifact.dll` on the reflex path:
//! the launcher never detected Artifact mode, so the launch was passed
//! through unwrapped and the XCR0 restriction was never armed. The game then
//! dies at Denuvo's environment check — within a millisecond of the CPUID
//! profile flip, so [`fire`] does everything synchronously, from the fault
//! handler: an always-on stderr line and a debug-log line (both plain
//! `write`s, already used from this context) and, when `PINGU_LAUNCHER`
//! names the launcher binary, a detached `pingu-launcher notify` message
//! box. The spawn uses raw syscalls only: `SYS_fork` (no pthread_atfork
//! handlers, so no allocator/loader locks can deadlock the child), and only
//! `setsid`/`fork`/`execve`/`_exit` before the exec, with every argument
//! prepared beforehand. The notifier runs in a new session re-parented to
//! init, so the box survives the game's exit. Under gamescope it may not
//! present; the stderr line stays the authoritative channel.

use core::ffi::{CStr, c_char};
use core::sync::atomic::{AtomicBool, Ordering};

static FIRED: AtomicBool = AtomicBool::new(false);

const STDERR_LINE: &[u8] = b"[pingu-hook] artifact.dll detected without Artifact mode: the launch was not wrapped, so XCR0 stays unrestricted and Denuvo will likely kill the game. Relaunch with `pingu-launcher --mode artifact`, or point the shortcut at the game's real executable (the one next to artifact.dll).\n";

const TITLE: &CStr = c"Artifact mode needed";
const BODY: &CStr = c"Denuvo's artifact.dll was loaded in a game launched without Artifact mode, so the XCR0 restriction was never armed and the game will most likely fail to start.\n\nRelaunch it with:\n    pingu-launcher --mode artifact\n\nOr point the shortcut at the game's real executable (the one that sits next to artifact.dll).";

/// Environment passed to the notifier: the desktop session, nothing of the
/// game, Wine or the hook (LD_PRELOAD would load pingu-hook into it).
const KEEP: &[&[u8]] = &[
    b"PATH=",
    b"HOME=",
    b"USER=",
    b"LOGNAME=",
    b"DISPLAY=",
    b"WAYLAND_DISPLAY=",
    b"XDG_RUNTIME_DIR=",
    b"XDG_CURRENT_DESKTOP=",
    b"DBUS_SESSION_BUS_ADDRESS=",
    b"XAUTHORITY=",
    b"DESKTOP_SESSION=",
    b"LANG=",
    b"LC_",
];

unsafe extern "C" {
    fn debug_log(message: *const c_char);
    static mut environ: *const *const c_char;
}

/// Fires the alert once per process; every call it makes is safe from the
/// CPUID fault handler's signal context.
pub(crate) fn fire() {
    if FIRED.swap(true, Ordering::AcqRel) {
        return;
    }
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            STDERR_LINE.as_ptr().cast(),
            STDERR_LINE.len(),
        );
        debug_log(c"artifact.dll detected without Artifact mode (unwrapped launch); the game will likely die".as_ptr());
    }
    let launcher = unsafe { libc::getenv(c"PINGU_LAUNCHER".as_ptr()) };
    if launcher.is_null() || unsafe { libc::access(launcher, libc::X_OK) } != 0 {
        return;
    }
    spawn_notify(launcher);
}

fn keep(entry: &[u8]) -> bool {
    KEEP.iter().any(|prefix| entry.starts_with(prefix))
}

fn entry_bytes(entry: *const c_char) -> &'static [u8] {
    let mut len = 0usize;
    unsafe {
        while *entry.add(len) != 0 {
            len += 1;
        }
        core::slice::from_raw_parts(entry.cast(), len)
    }
}

/// `fork(2)` through the syscall interface: the libc wrapper runs
/// pthread_atfork handlers, which can deadlock in a child that inherits a
/// malloc or loader lock held by another thread. The child here never
/// allocates, but it also never runs those handlers this way.
fn raw_fork() -> libc::pid_t {
    unsafe { libc::syscall(libc::SYS_fork) as libc::pid_t }
}

/// Spawns `pingu-launcher notify` detached (new session, reaped by init).
/// Everything the children need is prepared before the forks.
fn spawn_notify(launcher: *const c_char) {
    let mut envp: [*const c_char; 64] = [core::ptr::null(); 64];
    let mut count = 0usize;
    unsafe {
        let mut cursor = environ;
        while count + 1 < envp.len() {
            let entry = *cursor;
            if entry.is_null() {
                break;
            }
            if keep(entry_bytes(entry)) {
                envp[count] = entry;
                count += 1;
            }
            cursor = cursor.add(1);
        }
    }
    let argv: [*const c_char; 5] = [
        launcher,
        c"notify".as_ptr(),
        TITLE.as_ptr(),
        BODY.as_ptr(),
        core::ptr::null(),
    ];
    let first = raw_fork();
    if first < 0 {
        return;
    }
    if first == 0 {
        unsafe {
            libc::setsid();
            let second = raw_fork();
            if second > 0 {
                // The grandchild is re-parented to init; this child exits at
                // once so the waitpid below returns immediately.
                libc::_exit(0);
            }
            if second == 0 {
                libc::execve(launcher, argv.as_ptr(), envp.as_ptr());
            }
            libc::_exit(127);
        }
    }
    unsafe {
        let mut status = 0 as core::ffi::c_int;
        while libc::waitpid(first, &raw mut status, 0) < 0
            && *libc::__errno_location() == libc::EINTR
        {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_notifier_environment_keeps_only_the_desktop_session() {
        for kept in [
            &b"PATH=/usr/bin"[..],
            b"HOME=/home/u",
            b"WAYLAND_DISPLAY=wayland-1",
            b"DBUS_SESSION_BUS_ADDRESS=unix:path=/run",
            b"LC_ALL=C",
        ] {
            assert!(keep(kept), "{kept:?}");
        }
        for dropped in [
            &b"LD_PRELOAD=/x.so"[..],
            b"WINEDLLOVERRIDES=a=n,b",
            b"PINGU_LAUNCHER=/usr/bin/pingu-launcher",
            b"STEAM_COMPAT_DATA_PATH=/x",
            b"WINEPREFIX=/x",
            b"AVX2_POLICY=0",
        ] {
            assert!(!keep(dropped), "{dropped:?}");
        }
    }

    #[test]
    fn the_notifier_spawn_detaches_a_grandchild() {
        // /bin/true proves the fork/setsid/fork/execve chain completes; a
        // failing spawn would hang the waitpid or crash the test.
        spawn_notify(c"/bin/true".as_ptr());
    }
}
