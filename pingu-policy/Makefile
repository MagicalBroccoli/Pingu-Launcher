obj-m += pingu_policy.o
pingu_policy-y := probe.o policy.o trampoline.o umip.o cpuid_fault.o svm_capture_context.o svm_run_vm.o
CFLAGS_policy.o += -fno-optimize-sibling-calls
ccflags-y += -I$(obj) -I$(src)/inc
asflags-y += -I$(src)/inc

XCR0_HEADERS ?= $(srctree)
# A static helper that plans the patches and runs the VM gate; `make` puts it in validation/.
XCR0_TOOL ?= $(or $(src),$(CURDIR))/validation/pingu-module-tool
quiet_cmd_xcr0_profile = PROFILE $@
	cmd_xcr0_profile = $(XCR0_TOOL) profile --package $(src) --headers $(XCR0_HEADERS) --kernel-source $(abspath $(srctree)) --output $@ --metadata $(obj)/profile.generated.json $(if $(XCR0_APPROVALS),--approvals $(XCR0_APPROVALS)) $(if $(XCR0_IMAGE),--image $(XCR0_IMAGE)) $(if $(XCR0_SYSTEM_MAP),--system-map $(XCR0_SYSTEM_MAP)) $(if $(XCR0_SOURCE),--source $(XCR0_SOURCE))

$(obj)/profile.generated.h: $(XCR0_TOOL) FORCE
	$(call cmd,xcr0_profile)

$(obj)/probe.o $(obj)/policy.o $(obj)/trampoline.o: $(obj)/profile.generated.h
targets += profile.generated.h

# Build with the compiler that built the target kernel (kbuild refuses mixed toolchains on some trees).
XCR0_LLVM ?= $(shell grep -qx CONFIG_CC_IS_CLANG=y $(XCR0_HEADERS)/.config 2>/dev/null && echo LLVM=1)
XCR0_RELEASE ?= $(or $(KERNELRELEASE),$(shell cat $(XCR0_HEADERS)/include/config/kernel.release 2>/dev/null))

.PHONY: dkms-validated-build
dkms-validated-build:
	$(MAKE) -C $(XCR0_HEADERS) M=$(CURDIR) XCR0_HEADERS=$(XCR0_HEADERS) $(XCR0_LLVM) modules
	$(XCR0_TOOL) validate --optional --package $(CURDIR) --headers $(XCR0_HEADERS) --kernel-release $(XCR0_RELEASE)