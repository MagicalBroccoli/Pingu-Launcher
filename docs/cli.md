# Command Line Usage

Everything the launcher window does is also available from a terminal, which helps
on machines without a graphical session and for scripting. The window is described
in the [README](../README.md); `pingu-launcher --help` lists every option and tool.

The launcher keeps its data (the hook, runtimes and companion Protons) in
`~/.local/share/pingu-runtime`, or in `$XDG_DATA_HOME/pingu-runtime`. `--data-dir`
and `PINGU_RUNTIME_DIR` override it. Wine prefixes may retain absolute paths into
that directory, so do not move it after setting up games.

## Check The Machine

```sh
pingu-launcher --check --mode artifact
```

prints every requirement with the exact steps for what is missing and exits with 0
when everything is ready. `--mode legacy` checks for games that only need the hook.
Without `--mode` the launcher scans the game directory for `artifact.dll`. Kernel and
boot changes need a reboot.

## Build And Select A Runtime

Only on hosts with AVX-512 packages. The window's **Generate runtime** button does
this, or:

```sh
pingu-launcher runtime provision            # or --gpu amd / --gpu intel
```

The builder verifies package signatures and hashes, resolves/audits libraries
and creates a new immutable generation in `runtime-generations/` without changing
host packages, then selects it through `<gpu>-current`. If the locked glibc no
longer matches your host, it resolves current packages instead and records the
new lock in `locks/`. If the mirror's glibc is ahead of your host, pass a
matching Arch Linux Archive snapshot:

```sh
pingu-launcher runtime update --gpu nvidia --mirror https://archive.archlinux.org/repos/YYYY/MM/DD
pingu-launcher runtime select ~/.local/share/pingu-runtime/runtime-generations/nvidia-<id>
```

When the selected generation is older than the lock in effect, for example after a
launcher update added packages, games still start, and the window and `--check` offer
**Upgrade runtime**. The window's **Regenerate runtime** rebuilds a working generation
from its lock. See [runtime.md](runtime.md) for rebuilding exact inputs and updating.

## Install The Module (pingu-policy)

Skip installation if this module version is already installed and ready. Do not
try to unload an older loaded version. Reboot without autoloading it before
upgrading, or prepare the new module for a different installed kernel and boot
that kernel. The module takes no required parameters: remove
`/etc/modprobe.d/pingu-policy.conf` of version 0.3.0 first, because `modprobe`
refuses to load the module with its options. When an older version is loaded,
`pingu-launcher --check` lists the update steps.

The module does three jobs, each only where the machine needs it: the exact XCR0
restriction (CPUs whose XCR0 is wider than 7), the real `SGDT`/`SIDT` limits while UMIP
is active (no `clearcpuid=umip`), and CPUID faulting on AMD CPUs without it. It is the
module that `--check` asks for whenever one of these is needed, in Legacy mode too.

The window's **Install DKMS module** button on the pingu-policy card (it needs `dkms`
and polkit's `pkexec`, and asks for your password once) runs the same work as:

```sh
sudo pingu-launcher module install
```

It removes the options file, an older DKMS version and the deprecated
`cpuid_fault_emulation` package with its loading at boot, exports the sources, builds and
tests the module through DKMS, loads it, runs the self test and enables loading on
future boots. An older loaded version keeps running until you reboot.

On SteamOS there is no DKMS. The release binary carries modules that were built and
VM-tested against Valve's kernels, and the button reads **Install prebuilt module**
(`sudo pingu-launcher module install` does the same, and a Deck needs a password set
with `passwd` first). It installs them with a loader service that survives system
updates. A kernel that is newer than the launcher needs a newer launcher release. The
manual steps for other distributions are:

```sh
sudo pingu-launcher module export /usr/src/pingu-policy-0.5.0
sudo dkms add -m pingu-policy -v 0.5.0
sudo dkms install -m pingu-policy -v 0.5.0 -k "$(uname -r)"
```

DKMS automatically runs static checks and, when QEMU and KVM are available, the full VM
suite before installation (otherwise it warns that the module is untested). Do not
continue after a failure. Kernel package upgrades themselves are not rolled
back by a failed DKMS hook; retain a bootable fallback. `module export` refuses to
overwrite sources of an installed version with different content.

For the first native test, stop games and load explicitly:

```sh
sudo modprobe pingu_policy
cat /sys/module/pingu_policy/parameters/ready
pingu-launcher selftest
```

Readiness must be `Y`. If it is `N`, inspect the kernel log and reboot; do not
force removal. If `modprobe` reports "No such device" and the `ready` file is
missing, the module declined to load without patching anything (the kernel release
does not match the build). Secure Boot requires a module-signing key
trusted by your kernel; use your distribution's DKMS/MOK signing workflow. This
project does not disable Secure Boot, enroll keys or bypass lockdown.

After successful native testing, optionally enable loading on future boots:

```sh
sudo install -Dm644 /usr/src/pingu-policy-0.5.0/modules-load.d/pingu-policy.conf /etc/modules-load.d/pingu-policy.conf
```

See [kernel-module.md](kernel-module.md) for recovery and validation limits. What each
feature did is readable under `/sys/module/pingu_policy/parameters/`: `xcr0_policy`,
`umip_fixup` and `cpuid_fault` (`native`, `emulated` or `unavailable`).

## CPUID Faulting And UMIP

Both are handled by `pingu_policy` now; nothing needs a separate module or a boot
parameter. On an AMD CPU with SVM (AMD-V) enabled in the firmware that cannot fault
CPUID, loading the module starts a minimal hypervisor under the kernel, so it cannot
start while `kvm_amd` or another SVM user is active (`cpuid_fault` then reads
`unavailable`, and `--check` says so). Save work and keep a recovery kernel before the
first load on such a CPU. Other CPUs are not virtualized.

## Migrating From cpuid_fault_emulation And clearcpuid=umip

The separate `cpuid_fault_emulation` module and `clearcpuid=umip` (also `fred=off` and
`ibt=off`, which `pingu_policy` no longer needs) still work, so a machine that has them
stays usable, but `pingu-launcher --check` adds a "Deprecated setup" card with the steps.
By hand:

```sh
sudo pingu-launcher module install    # also removes the cpuid_fault_emulation package and its autoload
sudo modprobe -r cpuid_fault_emulation   # optional, only while no game runs
```

Then delete `clearcpuid=umip` (and `fred=off ibt=off`) from the kernel command line of
your bootloader and reboot. When both modules are loaded the new one leaves CPUID faulting
to the old one (`cpuid_fault` reads `native`), and when `pingu_policy` loads first the old
module refuses to start ("SVM already enabled"). `module export-cpuid` and
`module install-cpuid` no longer exist.

## Starting Games

The launcher is a command prefix: it receives the game's command, wraps it and runs it.

- **Lutris** starts the game through `umu-run`. Set the prefix to the full path of
  `pingu-launcher` and do not append `%command%`. The launcher finds the original Proton
  in `AVX2_PROTON_PATH` or `PROTONPATH`.
- **Faugus Launcher** builds `ENV... <launch arguments> [gamemoderun] [mangohud] umu-run <exe>`,
  so it behaves like Lutris. Enter the full path of `pingu-launcher` as a row of the game's
  **Launch Arguments** (Settings tab, Tools dropdown). Anything in front of `umu-run`
  (Faugus's `gamemoderun` and `mangohud`) stays there inside the launcher's namespace, so
  those checkboxes can stay on. Faugus passes the selected
  Proton as `PROTONPATH`. Use the native package, not the Flatpak.
- **Steam** passes its expanded command. Put `/path/to/pingu-launcher %command%` in the
  launch options (one line, and shell-quote paths with spaces). The launcher keeps
  Steam's outer reaper/runtime command, verifies the selected Proton is inside a
  container-runtime boundary and inserts the static launcher immediately before Proton.
  It does not launch the whole Steam client under the CPU restriction, replace the
  game's executable or create a custom compatibility tool.

The launcher sets `LD_PRELOAD` to `pingu-hook.so` itself (existing entries stay behind
it). Unknown command layouts, native Linux games without Proton, disabled container
runtimes and recursive companions are refused rather than guessed. Flatpak launchers
and every third-party wrapper chain are not supported. Use a new test prefix when
changing setups, and back up the old prefix and saves: this project does not delete,
reset or migrate your existing prefix.

## Settings

| Variable | Effect |
|---|---|
| `AVX2_POLICY` | `xcr0-only` (default), `1`, `runtime-only`, or `0` to bypass the restriction, the wrapper and its private libraries |
| `AVX2_RUNTIME` | A generation directory to use, or `none` to skip the private runtime |
| `AVX2_GPU` | `nvidia`, `amd` or `intel`; detected from the DRM devices otherwise |
| `AVX2_PROTON_PATH` | The original Proton directory (Lutris: `PROTONPATH` works too) |
| `PINGU_RUNTIME_DIR` | Data directory instead of `~/.local/share/pingu-runtime` |
| `PINGU_HOOK_VARIANT` | Use `variants/pingu-hook.<name>.so` of the data directory instead of the built-in library |

The launcher sets `PINGU_ARTIFACT_PROTOCOL=1` in Artifact mode when XCR0 is or will be 7.
`pingu-hook` reads these variables itself (they work without the launcher):

| Variable | Effect |
|---|---|
| `PINGU_ARTIFACT_PROTOCOL` | `1` enables the Artifact protocol and its loader adaptations; needs XCR0 = 7 |
| `PINGU_ARTIFACT_VARIANT` | `3` selects Artifact variant 3 (November SimpleSvm presentation). Variant 1 (`0x1337` bypass, Anno 117, F1 25) is detected from the game's handler, variant 2 is the default |
| `PINGU_LEGACY_PROFILE` | `1` forces the legacy CPU and KUSER presentation |
| `PINGU_DEBUG`, `PINGU_LOG` | Debug logging and its log file |
| `PINGU_SYSCALL_HACK` | Legacy syscall routing (only TopSpin needs it) |
| `PINGU_WIN32U_FREE_GUARD` | `1` works around a Wine `win32u` double free |

## Update, Disable And Recover

- Runtime: `runtime update` builds a candidate without selecting it. Try it with
  `AVX2_RUNTIME=<generation>` in a game's settings, then `runtime select` it.
  Stop and relaunch games after switching.
- Kernel: normal DKMS hooks rebuild and VM-test the module for new compatible
  kernels. Changed unsupported private APIs/instructions fail closed.
- Module: never force-unload. Remove its modules-load configuration and reboot
  to disable it. Do not replace an installed version's source directory with
  different code; upgrade to a new version.
- Uninstall: the **Uninstall** button at the bottom left of the window (it asks to confirm
  and for your password) or `sudo pingu-launcher module uninstall` removes the DKMS
  modules, their sources in `/usr/src`, the boot loading and the old options file (on
  SteamOS the service and `/var/lib/pingu-runtime`). A loaded module stays until the next
  reboot. The data directory (`~/.local/share/pingu-runtime`: hook, runtimes, companion
  Protons) and the launcher itself are not touched; delete them by hand.
- Game opt-out: remove the launch option/prefix. `AVX2_POLICY=0` keeps only the
  hook; it does not make the affected game compatible with an unrestricted CPU.
- `AVX2_POLICY=runtime-only` retains the private runtime but skips CPU restriction
  for diagnosis. It cannot remove an inherited active policy.
