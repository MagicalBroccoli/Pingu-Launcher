# pingu-hook

`LD_PRELOAD` library that keeps the CPU profile, Windows shared system data,
clocks, signal handling and Wine environment consistent for a game and its child
processes. `pingu-launcher` embeds the built `pingu-hook.so` and installs it into
`~/.local/share/pingu-runtime`.

This is derived from the LinUwUx Rust runtime (upstream: `brcly/linuwux-runtime`,
version 26.9.16, AGPL-3.0, see [LICENSE](LICENSE)). The packages, the built file,
the exported setup functions and the environment variables use the `pingu-hook`
and `PINGU_*` names; the launcher's README lists the variables. The design notes
are in [docs](docs). The upstream installer, wrapper and compatibility list do not
apply here.

## Build

```sh
cargo xtask build [--debug] [--output PATH]
```

Needs Rust 1.98 or newer, a C linker (`CC`, default `cc`) and GNU binutils
(`nm`, `readelf`, `strip`). The default output is `target/runtime/pingu-hook.so`.
The build verifies the exported symbols, constructor order and ELF hardening.
`pingu-launcher` runs this build itself, so a manual build is only for working
on the hook.
