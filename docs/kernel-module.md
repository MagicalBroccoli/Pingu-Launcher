# Kernel Module Design

The module restores full XCR0 when entering kernel code and applies exact XCR0=7
at the selected task's user return. Kernel FPU allocation/layout stays canonical;
restricted user xfeatures and permissions expose x87, SSE and AVX/YMM only.
Unrelated processes retain their normal AVX-512 state.

Ten entry hooks cover syscalls, IRQs, NMIs, user debug/breakpoint exceptions,
compat syscalls and user machine checks. Most use the kernel's synchronized
INT3-assisted text patcher. The breakpoint handler itself uses a checked aligned
eight-byte store under stop_machine plus CPU synchronization, because using an
INT3 patch there would recurse. NMI restoration is keyed by the interrupted
register frame and records only actual XCR0 changes.

Ftrace lifecycle hooks cover native/compat arch_prctl, fork initialization, first
child return and final task destruction. A successful-exec callback activates
pending policies. A fixed 1024-bucket/eight-slot table avoids allocation or locking
on final user return. If a new task cannot be recorded, opt-in/fork fails rather
than silently dropping restriction. Records are removed when tasks are freed,
through every final-release path: compilers may inline `free_task()` into
`__put_task_struct()` and the delayed-free callback, so those are hooked too.

## Kernel Updates

`pingu-module-tool profile` (`module-tool/src/profile.rs`) reads the new kernel's symbols and code and plans every patch itself.
At each hook it decodes whole instructions (after the ENDBR; including it for the
breakpoint handler) until the jump fits, five bytes or eight for the atomic
breakpoint patch. Only side-effect-free, position-independent forms are accepted:
register pushes and moves, stack adjustments and spills, tests and compares of
`[reg+disp]`, RIP-relative global/per-CPU loads and read-modify-writes, and one
direct call. RIP-relative operands and calls are replayed through a scratch pointer
(`r11`, dead at a C function entry) that the module fills from kallsyms at load
time, so no unexported symbol is linked. Nops, branches, prefixed or privileged
instructions, windows that other code of the function branches into, and windows
that already use `r11` are rejected, which keeps jump-label, ftrace and alternative
sites out of the patch. Runtime bytes, resolved displacements and build identity are
checked again before any patch is installed.

API differences between kernel generations are resolved from the kernel being
built for rather than from a version number: the text-patching functions
(`smp_text_poke_single`/`text_poke_bp`, `__text_poke` or plain `text_poke` when
the compiler renamed it), the entry name for 32-bit `int $0x80`, LASS and the task
FPU layout, the compat `arch_prctl` entry that older kernels (6.12 and before)
use, the encoding the kernel uses to seal unused ENDBRs, and the return type of
`do_syscall_64`/`do_fast_syscall_32`. Both GCC and Clang kernels build with their
own compiler.

Symbols and code are read from the first source that works: a `vmlinux` with
symbols (kernel header packages on Arch, or the distribution's debug package under
`/usr/lib/debug`), otherwise the installed boot image plus its `System.map` (Fedora,
Ubuntu and openSUSE ship both). Debian's `System.map` is a stub, so Debian needs the
`linux-image-*-dbg` package. The kernel ELF inside the boot image carries the same
build ID and code, and both sources produce identical profiles on every kernel
where both exist. `XCR0_IMAGE`, `XCR0_SYSTEM_MAP` and `XCR0_SOURCE=vmlinux|image`
override the discovery.

The actual DKMS build then boots that new kernel/module in a diskless QEMU/KVM
guest (skipped with a warning when QEMU or KVM is missing; the test itself is
mandatory for the SteamOS builds and for `make module-check`). It checks exec/fork/thread inheritance, exact XCR0, CPUID delivery, signals,
XSAVE/XSAVEC, ptrace, breakpoints, migration, real 32-bit syscall entry and
unrestricted vector/PKRU preservation. The guest boots with `ibt=off fred=off`,
so an IBT or FRED host is tested in the configuration it must run in. Stress
includes 512 installation-time NMI requests, another 40 during execution and
10,000 inherited children; tracked records must drain to zero. Timeouts/failures kill the owned test process group
and prevent the module from being marked built.

Version 0.3.0 (0.4.0 only removed the load parameters) passed this VM suite on the kernels below (2026-11-12, QEMU/KVM on
an AMD host with the guest presenting an Intel CPU model). Distribution rows were
built inside the distribution's own container with its toolchain and headers, and the
DKMS flow itself (`dkms add/build/install`, including the VM gate) was exercised on
Ubuntu, Fedora and openSUSE.

| Kernel | Compiler | Symbols from |
|---|---|---|
| CachyOS 7.3.3 | Clang 23, ThinLTO | vmlinux |
| Arch 7.2.15 | GCC 16 | vmlinux and boot image |
| Arch zen 7.2.15 (-O3) | GCC 16 | vmlinux |
| Arch hardened 7.2.15 | GCC 16 | vmlinux |
| Arch LTS 6.18.63, 6.12.75, 6.6.72 | GCC 14-16 | vmlinux |
| Fedora 45 7.3.3 | GCC | boot image |
| openSUSE Tumbleweed 7.3.3 (separate source/build trees) | GCC | boot image |
| Debian sid 7.3.4 (`CONFIG_X86_DEBUG_FPU`) | GCC 16 | debug vmlinux |
| Debian 13 6.12.107 | GCC 14 | debug vmlinux |
| Ubuntu 24.04 6.8.0-149-generic | GCC 13 | boot image |

Kernels before 6.6 (including 6.1 LTS) are not supported: their entry code differs
structurally (assembly `ret_from_fork`, older kernel helper APIs), and the build
rejects them. Also refused: a CPU reporting FRED or IBT, `CONFIG_CFI`, randomized
structure layout and kernels already carrying the built-in policy. Not covered
by the VM suite: bare-metal Intel hosts, suspend/hotplug and long-running
stability. A vendor kernel that rewrites its entry code can still fail the
build; it fails closed with a message naming the unsupported instruction.

Earlier releases also passed on CachyOS 7.4.0-rc1. Native/game success was
user-reported for the earlier module releases. AMD/Intel GPU profiles do not
imply that every CPU/kernel variation has been validated. Passing stress does
not prove all instruction races or hardware fault paths.

## FRED And IBT

The load check reads the CPU feature flags the kernel reports. `fred=off` and
`ibt=off` clear them early in boot, and neither changes anything userspace can
observe. User shadow stack (`user_shstk`) is a separate feature that the module
neither checks nor touches.

If the flags are missing on a later boot, `pingu_policy` fails its first check and
returns `ENODEV` before it looks up a symbol or patches kernel text. Nothing is
patched, so the boot continues; `systemd-modules-load` logs the failed load and
the wrapper's `arch_prctl` arming fails, so a game launch stops with
"Cannot arm AVX-512 restriction" instead of running unrestricted. Add the flags
to the boot entry and reboot.

## SteamOS

SteamOS (Steam Deck, Steam Machine) has a read-only root, no DKMS and no compiler, and
an update replaces `/usr`, the kernel and everything in `/etc` except a keep list. The
module is therefore built ahead of time against the exact kernel packages Valve ships
(`linux-neptune-*` and their headers, which carry the symbol-bearing `vmlinux`,
`System.map` and boot image) and embedded into the release launcher, which installs
them.

`make steamos-modules` (`tools/steamos-prebuilt.py`) downloads the current packages of
each series from Valve's mirror, checks them against the SHA-256 in the repository
database, builds `pingu_policy` and `cpuid_fault_emulation` with the kernel's compiler,
strips debug information, and runs the normal VM gate on the stripped module against
the real SteamOS boot image. Each release gets `build/steamos/releases/<release>/`
with both modules, the validation receipt and checksums. `make launcher-dist` runs
it first and embeds the result (the launcher build reads the directory named by
`PINGU_STEAMOS_DIR`; a plain `make launcher` embeds none). The embedded set is
about 150 KB per kernel build. `STEAMOS_ARGS="--series 618 --repo jupiter-beta"` selects
series and channel. The script needs only Python's standard library, `tar` with zstd
support, `make` and the kernel's compiler, plus QEMU/KVM for the VM gate.

Version 0.3.0 (0.4.0 only removed the load parameters) passed the VM gate on the current `jupiter-main` kernels
(2026-11-19, QEMU/KVM on an AMD host with the guest presenting an Intel CPU model):
neptune 6.8.12, 6.11.11, 6.15.11, 6.16.12, 6.18.53, 7.2.15 and 7.3.1 (GCC 14 to 16,
IBT and FRED compiled in except IBT only on 6.8, lockdown not forced).
`cpuid_fault_emulation` builds for them but has no VM gate.

On the device the launcher offers an **Install prebuilt module** button when it carries
a module for the running kernel build (a Deck needs a password set with `passwd` first,
because the button asks for it through polkit). `sudo pingu-launcher module install`
does the same from a terminal. It checks the checksums, replaces the modules below
`/var/lib/pingu-runtime/modules/` with the launcher's set, writes `pingu-modules-load`
there, installs and enables `pingu-modules.service`, restarts it and runs the self test.
SteamOS copies `/var` to the other slot on every update and keeps
`/etc/systemd/system/*.service` and `*.wants`, so the install survives updates and a
rollback to the previous slot. At boot the service loads the modules in the directory
named by `uname -r` with `insmod`, so no `depmod` index is needed, and the kernel's
vermagic and the module's build identity check refuse a module for any other kernel.
`pingu_policy` loads only on a CPU with AVX-512; a Steam Deck (Zen 2) has none and needs
no restriction. `cpuid_fault_emulation` loads only after
`sudo pingu-launcher module install-cpuid` (or its button), which also enables it at boot.

A SteamOS update that changes the kernel release leaves the loader without modules
(`journalctl -u pingu-modules.service` says so, and `pingu-launcher --check` reports that
the launcher has no module for the build ID) until a launcher release that includes that
kernel is installed and its button is used. Build new releases before Valve's kernels
reach users, and keep old builds in the set for rollbacks. Not tested on a device: the
unit and the installation, Secure Boot or lockdown (they would reject the unsigned
module), and the Steam Machine itself.

## CPUID Fault Emulation

`cpuid_fault_emulation` (sources in `cpuid-fault/`, embedded into the launcher and
written by `pingu-launcher module export-cpuid DIR`) is a separate module from
`pingu_policy` and is independent of the XCR0 hooks. It only supplies CPUID
faulting, which `pingu-hook` needs, on AMD CPUs that lack it.

On load it checks for an AMD CPU with SVM enabled in the firmware and no SVM user
already active, then starts a thin SVM hypervisor on every online CPU with the
running kernel as its guest. The hypervisor intercepts CPUID and the MSR that
holds the faulting control bit (`HWCR` or `MISC_FEATURES_ENABLES` on older
kernels), injects `#GP` for user-mode CPUID while faulting is enabled, and sets
`X86_FEATURE_CPUID_FAULT` so the kernel exposes `arch_prctl(ARCH_SET_CPUID)`.
Otherwise it returns `ENODEV` without changes: unsupported CPU, SVM disabled in
the firmware, or SVM already enabled (`kvm_amd`). `ignore_svm_enabled=1` skips
the last check and is not supported.

Differences from `pingu_policy`:

- It patches no kernel text and has no hooks, but runs the whole kernel as a guest,
  so a bug is a machine crash rather than a rejected build.
- It has no profile planning and no VM gate. DKMS builds it against the headers
  for each new kernel, using the compiler the kernel was built with, and installs
  it without tests, so a kernel update that builds can still misbehave.
- It exits cleanly (`modprobe -r`), devirtualizing every CPU, and handles suspend
  and hibernation by devirtualizing before and virtualizing after. Neither path
  is validated here, and KVM guests cannot be started while it is loaded.
- Autoload is configured by the owner in `/etc/modules-load.d/` and is not
  installed by DKMS.

To check it, load it and run `pingu-launcher --check`; the CPUID faulting entry
must name the module. `dmesg | grep -i virtualized` shows one line per CPU. To
disable it, remove its `modules-load.d` file, reboot or unload it, and use
`pingu-launcher --check` to confirm what is reported afterwards.

## Recovery

The module cannot be safely unloaded while arbitrary syscalls may have return
addresses in its code. It is pinned until reboot and must never be force-removed.
Late hook-registration failures leave it pinned but inactive (`ready=N`) rather
than freeing potentially referenced code. Reboot before retrying.

Remove `/etc/modules-load.d/pingu-policy.conf`, then reboot to disable autoload.
Use a recovery boot if normal startup fails. For a version upgrade, either reboot
without loading the old module first, or install the new version for another
installed kernel and boot that kernel. Installing files for a different kernel
does not replace a currently running module. Do not delete the recovery kernel.

Do not use exact mode for applications requiring higher XSAVE components or
their signal-state ABI. Machine-check recovery, privileged exec, CPU hotplug,
suspend/resume, arbitrary future kernels and performance require further testing.
