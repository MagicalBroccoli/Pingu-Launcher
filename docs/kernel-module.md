# Kernel Module Design

`pingu_policy` bundles three features: the exact XCR0 restriction, which this part of the
document describes, the UMIP limit fixup and the CPUID faulting emulation (sections below).

The module restores full XCR0 when entering kernel code and applies exact XCR0=7
at the selected task's user return. Kernel FPU allocation/layout stays canonical;
restricted user xfeatures and permissions expose x87, SSE and AVX/YMM only.
Unrelated processes retain their normal AVX-512 state.

Ten entry hooks cover syscalls, IRQs, NMIs, user debug/breakpoint exceptions,
compat syscalls and user machine checks. On a FRED boot the debug, `int $0x80` and
machine check hooks move to their FRED entry points (see FRED And IBT below); the
other seven are shared by both entry mechanisms. Most use the kernel's synchronized
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
unrestricted vector/PKRU preservation. The guest runs with the CPU features that
`-cpu host` exposes, so on a host with IBT or FRED the module is tested with them
active. Stress
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
rejects them. Also refused: `CONFIG_CFI`, randomized
structure layout and kernels already carrying the built-in policy. Not covered
by the VM suite: bare-metal Intel hosts, suspend/hotplug and long-running
stability. A vendor kernel that rewrites its entry code can still fail the
build; it fails closed with a message naming the unsupported instruction.

Earlier releases also passed on CachyOS 7.4.0-rc1. Native/game success was
user-reported for the earlier module releases. AMD/Intel GPU profiles do not
imply that every CPU/kernel variation has been validated. Passing stress does
not prove all instruction races or hardware fault paths.

## FRED And IBT

Neither needs a kernel command line change.

**IBT.** A kernel built with `CONFIG_X86_KERNEL_IBT` on a CPU with IBT makes the CPU
fault (`#CP`) on an indirect branch to anything but an `ENDBR`. The module breaks that
rule in two ways: the trampolines return into the middle of a hooked function through an
indirect jump, and it calls kernel functions through pointers (`kallsyms_lookup_name`,
the original lifecycle functions) whose `ENDBR` the kernel has sealed. Before it looks up
any symbol, the module clears `ENDBR_EN` in the supervisor CET MSR (`0x6a2`) on every
online CPU. A CPU hotplug callback repeats this on CPUs that come online later, and a
syscore resume handler on the boot CPU after suspend or hibernation. If the load fails
afterwards the bit is set again. `ibt_disabled` in `/sys/module/pingu_policy/parameters/`
reads `Y` when the module switched IBT off, and the kernel stays without IBT until
reboot. Kernels without `CONFIG_X86_KERNEL_IBT`, with `ibt=off` or on CPUs without IBT
are not touched. The `ibt` flag in `/proc/cpuinfo` only says that the CPU supports it,
not that the kernel enforces it.

**FRED.** The module selects its hooks from the CPU feature the kernel runs with. FRED
dispatches to the same functions as the IDT entry code for system calls, interrupts, NMIs
and `int3`, so those seven hooks serve both. The debug, `int $0x80` and machine check
hooks are replaced by `fred_exc_debug`, `fred_int80_emulation` and
`fred_exc_machine_check`. The FRED debug and machine check entry points also handle
kernel events, so they put back the XCR0 of the interrupted code after those. The planner
only emits the FRED hooks when all three exist and can be planned; on a FRED boot without
them `pingu_policy` returns `ENODEV` before it patches anything and logs that `fred=off`
is needed. The `fred` parameter reads `Y` when the FRED hooks are in use.

Verification: the VM suite passes on real Intel hardware (an i7-13700H, KVM guest with
IBT, 512 NMIs while loading and 40 while running, 10,000 inherited children). The FRED
path ran in the Bochs 3.1 emulator (CPU model `wildcat_lake`, with kernel IBT and FRED
both active) with the same suite. There it passes except for the checks Bochs cannot
serve (CPUID faulting, NMI injection) and two that also fail in a FRED guest without the
module: single-stepping over `cpuid` with `ptrace` and the 32-bit ELF test. No FRED
hardware has run it, and NMIs on the FRED path have not been exercised. KVM hosts that
already run guests when the module loads are untested.

User shadow stack (`user_shstk`) is a separate feature that the module neither checks nor
touches.

## SteamOS

SteamOS (Steam Deck, Steam Machine) has a read-only root, no DKMS and no compiler, and
an update replaces `/usr`, the kernel and everything in `/etc` except a keep list. The
module is therefore built ahead of time against the exact kernel packages Valve ships
(`linux-neptune-*` and their headers, which carry the symbol-bearing `vmlinux`,
`System.map` and boot image) and embedded into the release launcher, which installs
them.

`make steamos-modules` (`tools/steamos-prebuilt.py`) downloads the current packages of
each series from Valve's mirror, checks them against the SHA-256 in the repository
database, builds `pingu_policy` with the kernel's compiler,
strips debug information, and runs the normal VM gate on the stripped module against
the real SteamOS boot image. Each release gets `build/steamos/releases/<release>/`
with the module, the validation receipt and checksums. `make launcher-dist` runs
it first and embeds the result (the launcher build reads the directory named by
`PINGU_STEAMOS_DIR`; a plain `make launcher` embeds none). The embedded set is
about 150 KB per kernel build. `STEAMOS_ARGS="--series 618 --repo jupiter-3.10"` selects
series and channel (`jupiter-3.9` is stable, `jupiter-3.10` beta, `jupiter-main` the development channel; all three are built by default). The script needs only Python's standard library, `tar` with zstd
support, `make` and the kernel's compiler, plus QEMU/KVM for the VM gate.

Version 0.3.0 (0.4.0 only removed the load parameters) passed the VM gate on the current `jupiter-main` kernels
(2026-11-19, QEMU/KVM on an AMD host with the guest presenting an Intel CPU model):
neptune 6.8.12, 6.11.11, 6.15.11, 6.16.12, 6.18.53, 7.2.15 and 7.3.1 (GCC 14 to 16,
IBT and FRED compiled in except IBT only on 6.8, lockdown not forced). The module of
version 0.5.0 merges the former `cpuid_fault_emulation` and has not been through this
suite on those kernels yet.

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
`pingu_policy` loads on every machine, because UMIP and the CPUID faulting emulation
may need it where the XCR0 restriction does not (a Steam Deck has no AVX-512). The
features that a CPU does not need stay off: `cat /sys/module/pingu_policy/parameters/*`
shows what is active. A `enable-cpuid-fault` file of the former setup is removed by the
installation.

A SteamOS update that changes the kernel release leaves the loader without modules
(`journalctl -u pingu-modules.service` says so, and `pingu-launcher --check` reports that
the launcher has no module for the build ID) until a launcher release that includes that
kernel is installed and its button is used. Build new releases before Valve's kernels
reach users, and keep old builds in the set for rollbacks. Not tested on a device: the
unit and the installation, Secure Boot or lockdown (they would reject the unsigned
module), and the Steam Machine itself.

## Ostree images (Bazzite, Silverblue)

`/usr` is read-only, so DKMS could build the module but not install it, and the kernels
change every few days (Bazzite ships its own `-ogc` kernels per image variant and channel),
which rules out a prebuilt set. The module is built on the machine instead:
`pingu-launcher module install` exports the sources below `/var/lib/pingu-runtime/build`,
runs the same `dkms-validated-build` target as the DKMS package against
`/lib/modules/<release>/build` (static checks and VM test), signs the result with
`/var/lib/pingu-runtime/mok/MOK.{priv,der}` when the kernel demands signatures, and stores
it with its version in `modules/<kernel build ID>/`. The loader of the SteamOS section
loads it with `insmod`. When the directory for the running kernel is missing at boot and
the launcher copy exists, the loader starts `pingu-launcher module rebuild` in the
transient unit `pingu-modules-rebuild`, which then restarts the loader. The layered
packages are part of each new deployment, so the headers of the new kernel are there at
that boot.

Not tested on a device: the whole path on a real Bazzite image, the layering of
`kernel-devel` for a Bazzite kernel, SELinux (the installation labels the files with
`chcon` on a best effort basis), Secure Boot enrollment and the rebuild at boot.

## UMIP

With UMIP active the kernel emulates `SGDT` and `SIDT` for user space and stores a zero
limit, which the programs that needed `clearcpuid=umip` do not accept. A kretprobe on
`fixup_umip_exception()` (no kernel text is patched) decodes the memory operand of the
64-bit instruction on entry and overwrites the stored limit after a successful
emulation with the limits of a system without UMIP: `0x7f` for `SGDT` and `0xfff` for
`SIDT`. It applies to every process, needs no opt-in and no IBT change, and exists only
when the CPU feature is active; `umip_fixup` reads `Y` then, `umip_fixups` counts the
rewrites. 32-bit code is not rewritten. The idea follows the UMIP fixup of Artitux; the
code is written independently.

## CPUID Fault Emulation

The sources of the former `cpuid_fault_emulation` module are part of `pingu_policy` now
(`cpuid_fault.c`, `svm_run_vm.S`, `svm_capture_context.S`, `inc/`). The feature only
is offered on an AMD CPU with SVM enabled in the firmware and NRIP save, when the kernel does
not already have `X86_FEATURE_CPUID_FAULT` (natively, or from the deprecated module).
Loading the module starts nothing (`cpuid_fault` reads `on_demand`). The thin SVM
hypervisor, with the running kernel as its guest on every online CPU, starts inside
`arch_prctl(ARCH_SET_CPUID, 0)`, which the module hooks together with the other
`arch_prctl` entry points (also on kernels that need no XCR0 policy), and only while no
other SVM user is active: otherwise the call fails with `ENODEV` and `cpuid_fault` reads
`busy`. `arch_prctl(ARCH_SET_CPUID, 1)` reports success without starting it, because
enabling CPUID needs no hypervisor. The hypervisor intercepts CPUID and the
MSR that holds the faulting control bit (`HWCR` or `MISC_FEATURES_ENABLES` on older
kernels), injects `#GP` for user-mode CPUID while faulting is enabled, and sets
`X86_FEATURE_CPUID_FAULT` so the kernel exposes `arch_prctl(ARCH_SET_CPUID)`.
Every three seconds a work item looks for a thread with `TIF_NOCPUID` set; after two
scans without one, and with no `ARCH_SET_CPUID` call under way, it devirtualizes all CPUs
and clears the feature bit again, so KVM can claim SVM. CPUs that go offline or come
online while it runs are devirtualized and virtualized by a hotplug callback. The
`cpuid_fault` parameter reads `native`, `emulated` (running), `on_demand`, `busy` or
`unavailable`; the load parameter `emulate_cpuid_fault=0` turns the emulation off.

KVM has to leave SVM alone while no virtual machine exists: since Linux 6.16 it claims
SVM at load unless `kvm.enable_virt_at_load=0`, which the launcher's install writes to
`/etc/modprobe.d/pingu-kvm-lazy.conf` on such CPUs. Starting a virtual machine while the
hypervisor runs fails cleanly (`KVM_CREATE_VM` returns `EIO`, the kernel log says
`kvm: enabling virtualization on CPU0 failed`), and loading the hypervisor while a virtual
machine runs is refused (`busy`); neither crashes.

Two defects of the standalone module were fixed on the way: the instruction length came
from a fixed two bytes, which broke prefixed encodings such as `66 0f a2` (the CPU's
saved next RIP is used now, which is why NRIP save is required), and a CPUID with the
trap flag set did not trap after the emulation (the single-step `#DB` is injected now,
which `ptrace` single-stepping needs).

Both modules together: if `cpuid_fault_emulation` is loaded first, `pingu_policy` sees
the feature, starts nothing and reports `native`; if `pingu_policy` loads first, the old
module refuses with "SVM already enabled". Removing the old module later takes the
feature with it until the next reboot, so migrate by reinstalling and rebooting.

The hypervisor part has no hooks to reject: it patches no kernel text, but runs the
whole kernel as a guest while it is on, so a bug is a machine crash. Suspend and
hibernation devirtualize before and virtualize after (not validated), KVM virtual machines
cannot be started while it runs, and the module itself stays loaded until reboot.

Verification: the whole VM suite, with NMI injection, passed in a KVM guest on a Ryzen
9 7950X (nested SVM, the guest without CPUID faulting), where the emulation was active
(before it became on demand). The on-demand lifecycle was exercised in a nested Bazzite
guest on the same host (KVM paravirtualization hidden from the guest: the hypervisor
cannot forward the `VMMCALL` of paravirtualized KVM guests): repeated start and stop, the
self test, a KVM virtual machine while idle and while running, and a CPU taken offline
and online while it ran. The repository's VM gate itself presents an Intel CPU and so
skips the emulation. Other AMD CPUs and bare metal are untested.

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
