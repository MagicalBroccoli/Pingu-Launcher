CC ?= cc
CFLAGS ?= -O2 -g
JOBS ?= 12
BUILD_DIR := build
WORK_DIR := $(abspath .work)
TOOLS_PREFIX := $(WORK_DIR)/toolchain
MUSL_CC := $(TOOLS_PREFIX)/bin/musl-gcc
BASE_CFLAGS := -std=gnu11 -Wall -Wextra -Werror -march=x86-64 -mtune=generic -fcf-protection=none -ffile-prefix-map=$(CURDIR)=/src
MODULE_KERNEL_RELEASE ?= $(shell uname -r)
MODULE_HEADERS ?= /usr/lib/modules/$(MODULE_KERNEL_RELEASE)/build
MODULE_LLVM ?= $(shell grep -qx CONFIG_CC_IS_CLANG=y $(MODULE_HEADERS)/.config 2>/dev/null && echo LLVM=1)
LAUNCHER_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' launcher/Cargo.toml | head -n 1)
DIST_ENGINE ?= podman
DIST_IMAGE ?= pingu-launcher-dist
DIST_DIR := $(BUILD_DIR)/dist
# The prebuilt SteamOS modules (`make steamos-modules`) that the release builds embed.
STEAMOS_RELEASES := $(BUILD_DIR)/steamos/releases
# The static helper of the module build (needs `rustup target add x86_64-unknown-linux-musl`).
MODULE_TOOL := pingu-policy/validation/pingu-module-tool
MODULE_TOOL_TARGET := x86_64-unknown-linux-musl
MODULE_TOOL_BUILT := module-tool/target/$(MODULE_TOOL_TARGET)/release/pingu-module-tool
export TMPDIR := $(WORK_DIR)/tmp


# Local paths must not end up in a release binary: the checkout and the Cargo and Rustup homes.
CARGO_HOME_DIR := $(or $(CARGO_HOME),$(HOME)/.cargo)
RUSTUP_HOME_DIR := $(or $(RUSTUP_HOME),$(HOME)/.rustup)
remap_rust = --remap-path-prefix=$(1)=/src --remap-path-prefix=$(2)=/cargo --remap-path-prefix=$(3)=/rustup
HOST_REMAP := $(call remap_rust,$(CURDIR),$(CARGO_HOME_DIR),$(RUSTUP_HOME_DIR))
HOST_C_REMAP := -ffile-prefix-map=$(CURDIR)=/src -ffile-prefix-map=$(CARGO_HOME_DIR)=/cargo
# Rust lives in /root of the Debian container, and the checkout is mounted at /src.
CONTAINER_REMAP := $(call remap_rust,/src,/root/.cargo,/root/.rustup)

# Fails when the checkout or the home directory of the builder shows up in a file.
define check_anonymous
	@if strings -a $(1) | grep -qF -e '$(CURDIR)' -e '$(HOME)'; then \
		echo "$(1) contains local paths:" >&2; \
		strings -a $(1) | grep -F -e '$(CURDIR)' -e '$(HOME)' | head -5 >&2; \
		exit 1; \
	fi
endef

.DEFAULT_GOAL := all
.PHONY: all bootstrap test-binaries module-validation-assets
.PHONY: launcher launcher-check launcher-dist
.PHONY: test module-profile-check module-probe module-check
.PHONY: steamos-modules

all: launcher

# The launcher embeds the hook, both module packages, the helper programs and the locks.
EMBEDDED := pingu-policy/validation/manifest.json \
	$(wildcard pingu-policy/*.c pingu-policy/*.h pingu-policy/*.S pingu-policy/Makefile pingu-policy/dkms.conf \
		pingu-policy/README.md pingu-policy/modules-load.d/*) $(MODULE_TOOL) \
	$(shell find cpuid-fault -type f) \
	$(wildcard runtime/*.lock.json)
LAUNCHER_SOURCES := launcher/Cargo.toml launcher/Cargo.lock launcher/build.rs \
	$(wildcard launcher/src/*.rs launcher/ui/*.slint) \
	pingu-hook/Cargo.toml pingu-hook/Cargo.lock pingu-hook/xtask/Cargo.toml \
	$(shell find pingu-hook/protocol pingu-hook/runtime pingu-hook/xtask/src -type f)

launcher: $(BUILD_DIR)/pingu-launcher

$(BUILD_DIR)/pingu-launcher: $(LAUNCHER_SOURCES) $(EMBEDDED)
	mkdir -p $(BUILD_DIR) $(TMPDIR)
	cargo build --release --locked --manifest-path launcher/Cargo.toml
	install -m 755 launcher/target/release/pingu-launcher $@

launcher-check: pingu-policy/validation/manifest.json
	mkdir -p $(TMPDIR)
	cargo test --locked --manifest-path launcher/Cargo.toml

# A release for other distributions: built on Debian 11, so it needs glibc 2.31 or newer.
# It embeds the SteamOS modules, which `make steamos-modules` builds and tests first, and
# carries no local paths: the build remaps them and the result is checked.
DIST_BINARY := $(DIST_DIR)/target/release/pingu-launcher
launcher-dist: pingu-policy/validation/manifest.json steamos-modules
	$(DIST_ENGINE) build -t $(DIST_IMAGE) -f dist/Containerfile dist
	mkdir -p $(DIST_DIR)
	$(DIST_ENGINE) run --rm -v $(CURDIR):/src:Z -v pingu-cargo-registry:/root/.cargo/registry \
		-w /src -e CARGO_TARGET_DIR=/src/$(DIST_DIR)/target \
		-e RUSTFLAGS='$(CONTAINER_REMAP)' -e PINGU_HOOK_RUSTFLAGS='$(CONTAINER_REMAP)' \
		-e PINGU_STEAMOS_DIR=/src/$(STEAMOS_RELEASES) $(DIST_IMAGE) \
		cargo build --release --locked --manifest-path launcher/Cargo.toml
	$(call check_anonymous,$(DIST_BINARY))

bootstrap: $(MUSL_CC)

$(WORK_DIR)/downloads/musl-1.2.5.tar.gz:
	mkdir -p $(dir $@) $(TMPDIR)
	curl -fL --max-time 120 -o $@.part https://musl.libc.org/releases/musl-1.2.5.tar.gz
	printf '%s  %s\n' a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 $@.part | sha256sum -c -
	mv $@.part $@

$(MUSL_CC): $(WORK_DIR)/downloads/musl-1.2.5.tar.gz
	mkdir -p $(TMPDIR)
	printf '%s  %s\n' a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 $< | sha256sum -c -
	tar -xzf $< -C $(WORK_DIR)
	cd $(WORK_DIR)/musl-1.2.5 && ./configure --prefix=$(TOOLS_PREFIX) --disable-shared CC=$(CC) CFLAGS='-O2 -march=x86-64 -mtune=generic'
	$(MAKE) -C $(WORK_DIR)/musl-1.2.5 -j$(JOBS)
	$(MAKE) -C $(WORK_DIR)/musl-1.2.5 install

test-binaries: $(BUILD_DIR)/avx2-run-static $(BUILD_DIR)/xstate-probe-static $(BUILD_DIR)/policy-test-static $(BUILD_DIR)/xstate-compat32

$(BUILD_DIR)/avx2-run-static: tools/avx2-run.c tools/avx512-policy.h $(MUSL_CC)
	mkdir -p $(BUILD_DIR) $(TMPDIR)
	$(MUSL_CC) $(CFLAGS) $(BASE_CFLAGS) -static -o $@ $<

$(BUILD_DIR)/xstate-probe-static: tools/xstate-probe.c tools/avx512-policy.h $(MUSL_CC)
	mkdir -p $(BUILD_DIR) $(TMPDIR)
	$(MUSL_CC) $(CFLAGS) $(BASE_CFLAGS) -static -o $@ $<

$(BUILD_DIR)/policy-test-static: tests/policy-test.c tools/avx512-policy.h $(MUSL_CC)
	mkdir -p $(BUILD_DIR) $(TMPDIR)
	$(MUSL_CC) $(CFLAGS) $(BASE_CFLAGS) -Itools -static -pthread -o $@ $<

$(BUILD_DIR)/xstate-compat32: tests/xstate-compat32.S
	mkdir -p $(BUILD_DIR) $(TMPDIR)
	clang -m32 -nostdlib -static -fuse-ld=lld -o $@ $<

module-profile-check:
	mkdir -p $(TMPDIR)
	cargo test --locked --manifest-path module-tool/Cargo.toml

test: module-profile-check launcher-check

# The C parts of the tool (Capstone, liblzma, zstd) are built with musl so the binary is static.
$(MODULE_TOOL_BUILT): $(wildcard module-tool/Cargo.toml module-tool/Cargo.lock module-tool/src/*.rs) $(MUSL_CC)
	mkdir -p $(TMPDIR)
	CC_x86_64_unknown_linux_musl=$(MUSL_CC) CFLAGS_x86_64_unknown_linux_musl='$(HOST_C_REMAP)' \
		RUSTFLAGS='$(HOST_REMAP)' cargo build --release --locked --target $(MODULE_TOOL_TARGET) --manifest-path module-tool/Cargo.toml

$(MODULE_TOOL): $(MODULE_TOOL_BUILT)
	mkdir -p $(dir $@)
	install -m 755 $< $@
	$(call check_anonymous,$@)

module-probe: $(MODULE_TOOL)
	$(MAKE) -C $(MODULE_HEADERS) M=$(abspath pingu-policy) XCR0_HEADERS=$(MODULE_HEADERS) $(MODULE_LLVM) -j$(JOBS) modules

# The VM gate's fixtures (also embedded into the launcher), regenerated when a fixture changes.
pingu-policy/validation/manifest.json: $(BUILD_DIR)/avx2-run-static $(BUILD_DIR)/xstate-probe-static $(BUILD_DIR)/policy-test-static $(BUILD_DIR)/xstate-compat32 $(MODULE_TOOL)
	$(MODULE_TOOL) prepare --package pingu-policy --fixtures $(abspath $(BUILD_DIR))
	mkdir -p pingu-policy/validation/src/tests pingu-policy/validation/src/tools
	cp tests/policy-test.c tests/xstate-compat32.S pingu-policy/validation/src/tests/
	cp tools/xstate-probe.c tools/avx2-run.c tools/avx512-policy.h pingu-policy/validation/src/tools/

module-validation-assets: pingu-policy/validation/manifest.json

# SteamOS has no DKMS: build and VM-validate the modules for Valve's current kernels (STEAMOS_ARGS="--series 618").
# The launcher embeds the result when it is built with PINGU_STEAMOS_DIR (launcher-dist does).
steamos-modules: pingu-policy/validation/manifest.json
	/usr/bin/python3 tools/steamos-prebuilt.py --jobs $(JOBS) $(STEAMOS_ARGS)

module-check: module-probe module-validation-assets
	$(MODULE_TOOL) validate --package pingu-policy --headers $(MODULE_HEADERS) --kernel-release $(MODULE_KERNEL_RELEASE)
