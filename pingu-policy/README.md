# pingu-policy Module

Version 0.5.0; module `pingu_policy`, DKMS package `pingu-policy`.

See the installation guide in `../docs/cli.md` and the kernel design and
recovery notes in `../docs/kernel-module.md`. Those paths refer to the source
repository; the package that `pingu-launcher module export` writes includes this
module README as a self-contained summary.

The module does three jobs, each only where the machine needs it:

- **XCR0:** real userspace XCR0 is exactly 7 for tasks that arm private
  `arch_prctl(0x6001, 3)` before exec (skipped when the kernel already runs with XCR0 7).
  `arch_prctl(0x6002, 0)` returns 0 off, 3 pending or 4 active. Active policy survives
  fork, threads and exec and cannot be dropped. CPUID is left untouched for
  `pingu-hook`.
- **UMIP:** with UMIP active, `SGDT` and `SIDT` report `0x7f` and `0xfff` instead of the
  zero limit of the kernel's emulation, so `clearcpuid=umip` is not needed.
- **CPUID faulting:** on an AMD CPU with SVM that cannot fault CPUID, a thin hypervisor
  provides it (the former `cpuid_fault_emulation` module). It does nothing when the
  feature exists, whoever provides it, or when SVM is in use (`kvm_amd`).

Read-only parameters under `/sys/module/pingu_policy/parameters/`: `ready`,
`xcr0_policy`, `umip_fixup`, `cpuid_fault` (`native`, `emulated`, `unavailable`), `fred`,
`ibt_disabled`. The only load parameter, `emulate_cpuid_fault` (default `Y`), turns the
hypervisor off.

The build requires, for the kernel it targets: its header package, the compiler
that built that kernel (GCC or Clang; the build picks it from the kernel
configuration) and DKMS, plus QEMU/KVM for the VM test (optional, see below). The patch planner and the VM test runner are the
static `validation/pingu-module-tool`, so no Python, Node.js or cpio is needed.
Kernels 6.6 and newer are supported; see `../docs/kernel-module.md` for the
verified list. The kernel's symbols and code come from a symbol-bearing `vmlinux`
or, failing that, from the installed boot image plus `System.map`:

| Distribution | Packages to install |
|---|---|
| Arch, CachyOS | headers package, `dkms qemu-system-x86` (`clang llvm lld` for Clang kernels) |
| Debian | `dkms linux-headers-$(uname -r) linux-image-$(uname -r)-dbg qemu-system-x86 gcc make libelf-dev` |
| Ubuntu | the same without `-dbg` (the kernel package ships `System.map`) |
| Fedora | `dkms kernel-devel qemu-system-x86-core gcc make elfutils-libelf-devel` |
| openSUSE | `dkms kernel-default-devel qemu-x86 gcc make libelf-devel` |

Debian's `System.map` is only a stub, so its debug package is required. The
kernel image must be readable at its usual place (`/boot/vmlinuz-<release>` or
`/lib/modules/<release>/vmlinuz`); `XCR0_IMAGE`, `XCR0_SYSTEM_MAP` and
`XCR0_SOURCE=vmlinux|image` override the search.
The bundled static test programs allow offline VM validation without rebuilding
a kernel or downloading a compiler during each kernel update.

DKMS compiles via `dkms-validated-build`: static profile checks, module compile,
then VM tests against the newly installed kernel. A failing test makes the build
fail. When QEMU or `/dev/kvm` is missing, the tests are skipped with a warning in the
DKMS build log (`/var/lib/dkms/pingu-policy/<version>/<kernel>/x86_64/log/make.log`),
`pingu-launcher --check` points it out, and only the static checks ran. Install QEMU
and rebuild with `dkms install --force` to get the test. `AUTOINSTALL=yes` enables normal kernel-update rebuilding. There
is no manual per-kernel profile approval. A failure does not roll back the kernel
package; retain a recovery kernel.

First installation after extraction to `/usr/src/pingu-policy-0.4.0`:

```sh
dkms add -m pingu-policy -v 0.4.0
dkms install -m pingu-policy -v 0.4.0 -k "$(uname -r)"
modprobe pingu_policy
cat /sys/module/pingu_policy/parameters/ready
```

Installation/loading commands require administrator privileges. Readiness must
be `Y`; `N` means the module is inactive and a reboot is required before retrying.
The included `modules-load.d` file can be installed
by the owner after native validation to enable future boot loading; builds do not
write it. Version 0.3.0 needed `experiment=1 allow_host=1` in a `modprobe.d` file,
which must be removed because `modprobe` refuses the module with those options. Secure Boot requires normal trusted-key module signing.

The module pins itself until reboot. **Never force-unload it.** Remove autoload
configuration and reboot to disable it or before replacing a loaded module.
Do not overwrite source of an installed version with different code.

This is experimental runtime kernel patching, not standard livepatch and not a
security boundary. Unsupported kernel instructions/configuration are rejected.
FRED needs no boot parameter: on a FRED boot the module hooks the FRED entry points.
Kernel IBT is switched off for as long as the module is loaded (`ibt_disabled` reads
`Y` in `/sys/module/pingu_policy/parameters/`), because the hook trampolines are not
valid indirect branch targets. If a FRED kernel's entry points cannot be hooked, the
module returns `ENODEV` before reading symbols or patching anything, so the boot is
unaffected and the module simply stays unloaded; boot with `fred=off` then. The VM
gate boots its guest with the features of the build host. A VM pass does not prove
hardware error recovery, suspend/hotplug, performance, or protected-game compatibility.
Preserve the exact-XCR0-compatible userspace runtime and the game's existing settings.