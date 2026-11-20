# cpuid_fault_emulation Module

Version 0.1; module `cpuid_fault_emulation`, DKMS package `cpuid_fault_emulation`.

See the installation guide in `../docs/cli.md` and the notes in
`../docs/kernel-module.md`. Those paths refer to the source repository; the package
that `pingu-launcher module export-cpuid` writes includes this README as a
self-contained summary.

Some AMD CPUs cannot fault CPUID natively, which `pingu-hook` needs. This module
emulates the feature: it starts a minimal SVM hypervisor under the running kernel
on every CPU, intercepts the CPUID-faulting control bit and injects `#GP` for
CPUID in user mode when a task asks for faulting. It then reports
`X86_FEATURE_CPUID_FAULT` to the kernel. CPUs that fault CPUID natively do not
need it.

It requires an AMD CPU with SVM (AMD-V) enabled in the firmware. It refuses to
load with `ENODEV` before changing anything when the CPU is not supported or SVM is
already in use (for example by a loaded `kvm_amd`), so it cannot run together with
KVM guests. `ignore_svm_enabled=1` overrides the SVM check, which is not
supported: nested virtualization is not handled and may crash the machine.

The build needs, for the kernel it targets, its header package, DKMS, `make` and
the compiler that built the kernel (GCC, or Clang with LLVM; the Makefile picks
it from the kernel configuration). Unlike `pingu_policy`, there is no VM
validation gate.

First installation after `pingu-launcher module export-cpuid
/usr/src/cpuid_fault_emulation-0.1`:

```sh
dkms add -m cpuid_fault_emulation -v 0.1
dkms install -m cpuid_fault_emulation -v 0.1 -k "$(uname -r)"
modprobe cpuid_fault_emulation
dmesg | grep -i 'virtualized'
```

Each CPU logs `Processor N virtualized`. Autoload on future boots with
`echo cpuid_fault_emulation > /etc/modules-load.d/cpuid_fault_emulation.conf`.
`AUTOINSTALL=yes` rebuilds it for new kernels. Secure Boot requires normal
trusted-key module signing.

This is experimental code that runs the whole system as a hypervisor guest. Save
work before the first load and keep a recovery kernel. Suspend and hibernation are
handled by devirtualizing before and virtualizing after; this has not been
validated here. Unload with `modprobe -r cpuid_fault_emulation` only while no
program depends on CPUID faulting, and never while a KVM guest is running.
