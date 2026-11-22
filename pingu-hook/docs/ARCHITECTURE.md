# Architecture

A map of how this codebase is put together, for anyone starting fresh. See
[`docs/protocol/`](protocol/README.md) for the Reflex *protocol* this code
implements (what Reflex/Denuvo expect, per-title differences); this document
is about the *code*.

## Two paths, one library

`pingu-hook.so` carries two independent compatibility implementations and
picks one per process at load time from `PINGU_HOOK_PATH`:

| Path | Value | Origin | Games |
| --- | --- | --- | --- |
| Reflex | `reflex` (default) | LinUwUx runtime (`brcly/linuwux-runtime`) | Reflex/Denuvo titles (`reflex64.dll`, early `artifact.dll`) |
| Artifact | `artifact` | Artifact releases (needs XCR0 = 7) |

The launcher sets `PINGU_HOOK_PATH=artifact` for Artifact games; the variable
is inherited by the whole Wine/Proton process tree. Each path owns its CPUID
trap handler, KUSER handling and syscall interception. Everything the two
share (signal and allocator hooks, logging, Gamescope, environment, faketime,
`INT 2E` emulation, `/proc` helpers) exists once.

## The three crates

| Crate | Directory | What it is |
| --- | --- | --- |
| `pingu-hook-protocol` (`pingu_protocol`) | `protocol/` | The safe core: `no_std`, `#![forbid(unsafe_code)]`, unit-tested. Pure decision logic: CPUID reply tables, KUSER patch recipes, the Reflex registration/routing state machine, the Artifact handshake and profiles, string parsing for environment/gamescope detection. No libc, no signals, no process memory. |
| `pingu-hook-runtime` | `runtime/` | The unsafe shell. Drives `protocol/`'s logic, owns every signal handler, every libc interposition, every `mprotect`/`process_vm_readv` call. |
| `xtask` | `xtask/` | The build tool. Links `pingu-hook-runtime` into `pingu-hook.so` with an explicit export map and linker hardening, then verifies the result (exported symbols, ELF properties, `.init_array` constructor order). A bad rename or a dropped `#[no_mangle]` fails the build, not just a review. |

Why the split: code that never touches a raw pointer or a syscall can be
tested with plain `cargo test`, reasoned about without thinking about signal
reentrancy, and kept `#![forbid(unsafe_code)]` to guarantee it stays that way.
Everything that genuinely needs `unsafe` lives in `runtime/`, as thin as each
module allows.

### `protocol/`

| Module | Content |
| --- | --- |
| `path` | `HookPath` and the parsing of `PINGU_HOOK_PATH` |
| `cpuid` | Shared `Registers`, `Vendor`, host vendor detection, Wine system RIP bounds |
| `debug`, `faketime`, `gamescope`, `environment` | Shared string and number logic. `environment` holds the per-path DLL override tables and the Artifact CPU topology cap |
| `reflex` | The `Host` trait and `State` machine (`state`, `control`), CPUID identities (`cpuid`), KUSER recipes (`kuser`), per-title reference data (`quirks`) |
| `artifact` | The PID-first handshake and syscall resume contract, with `cpu` (Intel/AMD CPUID tables), `profile` (VBS 1.9/2.0 profiles, Wine view rules) and `kuser` (identity writes) |

## `runtime/`'s modules

Shared modules (`runtime/src/*.rs`). Each `.init_array` constructor owns one
concern and runs at process start; the priority number fixes the relative
order, which `xtask` verifies:

| Constructor | Module | Concern |
| --- | --- | --- |
| `00100` | `path.rs` | Reads `PINGU_HOOK_PATH`. Every other module reads the result through `path::active()` |
| `00102` | `debug.rs` | `PINGU_DEBUG`/`PINGU_LOG`; every other module's logging goes through its C ABI |
| `00103` | `gamescope.rs` | Detects a Gamescope session and keeps `LD_PRELOAD` alive across its re-exec; interposes `setenv`/`unsetenv` |
| `00201` | `environment.rs` | Decides whether this process is the game's own `.exe`, forces the native DLL overrides of the active path, triggers `registry.rs`. On the Artifact path it also sets `PROTON_DISABLE_LSTEAMCLIENT` and caps `WINE_CPU_TOPOLOGY` |
| `00202` | `faketime.rs` | The `gettimeofday` clock offset |
| `00203` | `hooks.rs` | Signal interposition that keeps the active path's `SIGSEGV`/`SIGSYS` (and, on the Artifact path, `SIGILL`) handlers ahead of Wine's own, the post-fork recovery, and the opt-in `win32u` duplicate-`free` guard (`hooks/pending_frees.rs`) |

Support modules without a constructor: `int2e.rs` (emulates Windows' `int 2e`
gate, called from either path's CPUID handler), `maps.rs`, `procmem.rs`,
`page_guard.rs`, `errno.rs`, `clock.rs`, `registry.rs`.

`interpose.rs` exports the libc functions the paths interpose and forwards
each call to the active path; a path that has no use for a function hands the
call to the next definition:

| Function | Reflex | Artifact |
| --- | --- | --- |
| `mmap` | PE stub layout fixups, file-mapping tracking | Loader/resolver observer, CPUID Wine-view invalidation, file-mapping tracking |
| `read`, `pread` | PE stub tail normalization | passed through |
| `mprotect` | passed through | Loader/resolver observer |

`sigaction`, `malloc`, `free`, `setenv`, `unsetenv` and `gettimeofday` serve
both paths and are exported by the shared modules above. These ten symbols
are the whole export surface; everything else stays hidden.

### Reflex path (`runtime/src/reflex/`)

- **`cpuid.rs`**: the SIGSEGV/CPUID trap handler: per-caller Reflex-image
  detection, native CPUID pass-through, reply selection via
  `protocol/reflex/cpuid.rs`.
- **`session.rs`**: the C ABI into `protocol/reflex/state.rs::State`, and
  `RuntimeHost`, the seam where the safe core's decisions become real
  `mprotect`/logging/presentation side effects.
- **`kuser.rs`** (constructor `00204`) with **`kuser/shared_time.rs`**: owns
  the live `KUSER_SHARED_DATA` page, applies patch recipes from
  `protocol/reflex/kuser.rs`, and (legacy, see
  `docs/protocol/topspin-investigation.md`) the `PINGU_SYSCALL_HACK` flag.
- **`config.rs`**: `PINGU_LEGACY_PROFILE`.
- **`syscall/`**: the SIGSYS boundary, below.

#### The Reflex syscall boundary (`reflex/syscall/`)

This is the part `docs/protocol/syscall-routing.md` describes in protocol
terms; in source it is three independent stages plus fixups:

1. **`kuser_dispatch.rs`**: installs the handler in Wine's KUSER dispatcher
   slot (a hand-written naked-asm trampoline, `dispatcher_bridge`, with a
   private stack per Windows thread id) and classifies every call that arrives
   through it: Reflex's own copied syscall stub (found by scanning the main PE
   image's IAT), or an ordinary Wine call. That rule is `should_replay_raw`, a
   small pure function pinned by the unit tests.
2. **`markers.rs`**: the Route/Replay marker lifecycle connecting stage 1's
   decision to stage 3's trap, plus `is_registered_target_process` for direct
   syscalls from a process that completed Reflex's registration handshake.
3. **`sigsys_router.rs`**: the `SIGSYS` handler (`syscallhook`). Decides
   Wine-forward vs. `State::route_syscall` vs. bypass-replay, and restores
   caller-visible state (XMM4/5, R11, EFLAGS) exactly once per marker.

Fixups unrelated to routing: **`pe_stub_layout.rs`** rewrites syscall thunk
tails in whole-file/mmap'd reads of system DLLs to Windows' real layout,
**`unixlib_repair.rs`** repairs two Wine-only data exports Reflex mistakes for
code, **`win32u_zero_list.rs`** is a narrow window-list fix (it resolves syscall
numbers through **`pe_export.rs`**), **`mem.rs`** decodes the trampolines Reflex
writes into IAT and export slots, **`diagnostics.rs`** keeps a bounded syscall
history for null-fault reports.

### Artifact path (`runtime/src/artifact/`)

`artifact.rs` coordinates the session (registration, handler, readiness);
its submodules:

- **`cpuid.rs`**: the CPUID trap handler: Artifact handshake and profile
  replies, Wine-view caching, native pass-through, host vendor detection.
- **`kuser.rs`**: the process-private view of Wine's shared user data
  (prepare, commit, rollback, profile writes).
- **`loader.rs`**: stock-Wine loader support, so the Artifact DLL can replace
  `PEB->Ldr` and import resolution with only `LD_PRELOAD`.
- **`resolver.rs`** (+ `resolver.S`): the resolver re-entry bridge
  (`SIGILL`, `PINGU_RESOLVER_BRIDGE`).
- **`peb_heaps.rs`**: publishes `PEB.ProcessHeaps` for stock Wine.
- **`seccomp.rs`**: traps Windows syscalls that slip past Wine's syscall user
  dispatch.
- **`entry.rs`**: the native entry used to prepare Artifact from Wine PE
  context.
- **`config.rs`**: `PINGU_VBS20`, `PINGU_RESOLVER_BRIDGE`,
  `PINGU_SYSCALL_LEAK_TRAP`.
- **`syscall/`**: `kuser_dispatch.rs` (dispatcher bridge for a registered
  Artifact process), `sigsys_router.rs` (`SYS_USER_DISPATCH` routing and leak
  repair), `flags.rs` (per-thread bypass flags), `pe_stub_layout.rs` (the
  `mmap` observer).

## Where to look for what

- **Adding a title-specific quirk (Reflex)?** `docs/protocol/game-quirks.md`
  and `protocol/reflex/quirks.rs`, not a new `if` in `kuser_dispatch.rs` or
  `sigsys_router.rs`.
- **Changing Reflex routing behavior?** Start from
  `docs/protocol/syscall-routing.md`'s invariants, then the stage above that
  owns the decision.
- **An Artifact release that fails?** The module headers under
  `runtime/src/artifact/` describe each mechanism; `PINGU_DEBUG=1 PINGU_LOG=...`
  logs the handshake (`ART ...` lines).
- **Something both paths need?** A shared module, not a copy in each path.
  Anything that has to differ per path branches on `path::active()` in the
  shared module.
- **Build or release process?** `xtask/src/main.rs` and `.github/workflows/`.
