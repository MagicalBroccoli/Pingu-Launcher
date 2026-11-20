# Runtime Maintenance

The runtime is generic Arch userspace layered read-only above host libraries.
Only library and graphics-data directories are overlaid; host packages and
`/usr/bin` are unchanged. NVIDIA's proprietary driver remains host-supplied to
match its kernel module. AMD and Intel use Mesa/RADV or Mesa/ANV profiles.

`pingu-launcher runtime` uses a private pacman database to resolve complete
package dependencies, then verifies package signatures and SHA-256 hashes.
Its ELF audit adds missing optional dependency providers from repository file
indexes during `update`. For example, it automatically adds Tcl/Tk for Python's
optional Tkinter module. Ambiguous providers fail instead of being guessed.
The builder needs Arch Linux or CachyOS with `pacman`, `curl`, `gpg`/`gpgv`
(with `archlinux-keyring`) and `bsdtar`.

Everything lives in the data directory (`~/.local/share/pingu-runtime`, see the
README): `runtime-generations/` holds the generations and the per-GPU
`*-current` links, `runtime-builder/` holds downloads and scratch space and
`locks/` holds lock files written by `update`. A lock in `locks/` takes
precedence over the one built into the launcher (`runtime/*.lock.json`).

## Rebuild Exact Inputs

```sh
pingu-launcher runtime build --gpu nvidia
pingu-launcher runtime build --gpu nvidia --offline
```

Offline mode needs the archives and signatures in
`runtime-builder/downloads`. Preserve this cache for long-term rebuilding;
live mirrors can drop old packages (`--work DIR` selects another cache).
Lockfiles also record Arch package-archive fallback URLs. `build` never changes
versions or the lock, and prints the generation directory. The directory name
is derived from the lock, so the same lock always gives the same name.

## Update A Working Runtime

The launcher compares the selected generation with the lock in effect. When they
differ, or when the built-in lock lists roots that a lock from an older launcher
lacks, the runtime counts as outdated: games still start, the window and
`--check` offer **Upgrade runtime**, and `runtime provision` does it. A lock that
lacks built-in roots is resolved again with its extra packages kept.

```sh
generation=$(pingu-launcher runtime update --gpu nvidia)
```

Stop on failure. With the kernel module loaded, try the candidate with a game
before changing the stable selection by adding this to the game's environment:

```text
AVX2_RUNTIME=<generation>
```

The launcher's checks do not need the candidate: it only has to be selected, or
named in `AVX2_RUNTIME`, when a game starts. Only select after the game runs:

```sh
pingu-launcher runtime select "$generation"
```

Selection changes the per-GPU `*-current` link atomically; running processes keep
their existing mappings. Stop and relaunch games to use the new selection. Old
generations remain available for rollback. Neither update nor select changes
Lutris/Steam configuration. `pingu-launcher runtime provision` does build, update
and select in one step, which is what the window's button runs.

Host glibc and the private glibc version must match. If the mirror is ahead of your
host, use a matching historical repository snapshot, for example
`--mirror https://archive.archlinux.org/repos/YYYY/MM/DD`. Do not downgrade host
packages solely to satisfy this project.

## Hosts Without AVX-512 Packages

The private runtime only matters when host packages contain unconditional AVX-512
code (x86-64-v4 or znver4 repositories). On other hosts, `AVX2_RUNTIME=none` runs
the CPU policy wrapper without the library overlay or GPU manifest overrides;
pressure-vessel then uses the host graphics stack as it is. The launcher sets this
itself when it detects such a host.

## Optional Packages And GPUs

Use `--gpu amd` or `--gpu intel` for the other profiles. All profiles share
one dependency resolver; selection comes from the generation manifest.
NVIDIA startup was hardware-tested. AMD/Intel generation and static audit pass,
but those GPU hardware paths were not available for testing. Intel targets ANV,
not a separately validated legacy HasVK profile.

Add known plugin families as roots, without listing their dependencies manually:

```sh
pingu-launcher runtime update --gpu nvidia --add libpulse --add lib32-libpulse
```

`runtime audit PATH` rechecks ELF providers and explicit ISA requirements. The audit
matches DT_NEEDED names and bitness, but does not model every loader search path
or dynamically constructed dlopen name. ISA notes can reject explicit
x86-64-v4 requirements; they cannot prove unannotated code never executes AVX-512.
The overlay is not a hermetic operating system: host-only plugins and preloads
remain visible. Try every update with a game before selecting it.
