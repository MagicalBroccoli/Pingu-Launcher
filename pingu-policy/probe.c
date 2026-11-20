#include <linux/atomic.h>
#include <linux/init.h>
#if __has_include(<linux/irq-entry-common.h>)
#include <linux/irq-entry-common.h>
#else
#include <linux/entry-common.h>
#endif
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/stop_machine.h>
#include <linux/utsname.h>
#include <asm/cpufeature.h>
#include <asm/fpu/types.h>
#include <asm/fpu/xcr.h>
#include <asm/smap.h>
#include <asm/text-patching.h>

#include "policy.h"
#include "profile.generated.h"

static atomic_long_t entry_hits = ATOMIC_LONG_INIT(0);
static struct mutex *kernel_text_mutex;
static void (*kernel_text_poke_single)(void *, const void *, size_t, const void *);
#if XCR0_TEXT_POKE_ATOMIC_CUSTOM
static void *(*kernel_text_poke_custom)(void (*)(void *, const void *, size_t), void *, const void *, size_t);
#else
static void *(*kernel_text_poke)(void *, const void *, size_t);
#endif
static void (*kernel_text_sync)(void);
static unsigned long (*kernel_lookup)(const char *);
static bool policy_ready;
module_param_named(ready, policy_ready, bool, 0444);
static u64 normal_xcr0;
struct nmi_states {
	struct pt_regs *frames[16];
	u64 xcr0[16];
};
static DEFINE_PER_CPU(struct nmi_states, nmi_states);
unsigned long xcr0_probe_continuations[ARRAY_SIZE(xcr0_profile_names)];
/* Runtime addresses of the kernel symbols that replayed instructions refer to. */
unsigned long xcr0_probe_targets[XCR0_PROFILE_TARGET_COUNT];

extern irqentry_state_t xcr0_probe_original(struct pt_regs *regs);
/* Return types differ by kernel version (void, bool or long); forwarding all of rax is valid for each. */
extern long xcr0_probe_original_syscall(struct pt_regs *regs, long number);
extern void xcr0_probe_original_exit(struct pt_regs *regs, irqentry_state_t state);
extern irqentry_state_t xcr0_probe_original_nmi_enter(struct pt_regs *regs);
extern void xcr0_probe_original_nmi_exit(struct pt_regs *regs, irqentry_state_t state);
extern void xcr0_probe_original_debug(struct pt_regs *regs);
extern void xcr0_probe_original_breakpoint(struct pt_regs *regs);
extern void xcr0_probe_original_int80(struct pt_regs *regs);
extern long xcr0_probe_original_fast32(struct pt_regs *regs);
extern void xcr0_probe_original_mce(struct pt_regs *regs);

static __always_inline void restore_kernel_xcr0(void)
{
	if (xgetbv(XCR_XFEATURE_ENABLED_MASK) != normal_xcr0)
		xsetbv(XCR_XFEATURE_ENABLED_MASK, normal_xcr0);
}

static __always_inline void restrict_user_xcr0(void)
{
	if (xcr0_task_active(current))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, 7);
}

static int get_entry_hits(char *buffer, const struct kernel_param *parameter)
{
	return scnprintf(buffer, PAGE_SIZE, "%ld\n", atomic_long_read(&entry_hits));
}

static const struct kernel_param_ops hits_ops = { .get = get_entry_hits };
module_param_cb(entry_hits, &hits_ops, NULL, 0444);

static noinstr irqentry_state_t xcr0_probe_entry(struct pt_regs *regs)
{
	restore_kernel_xcr0();
	raw_atomic_long_inc(&entry_hits);
	return xcr0_probe_original(regs);
}

static noinstr long xcr0_probe_syscall(struct pt_regs *regs, long number)
{
	long result;

	restore_kernel_xcr0();
	result = xcr0_probe_original_syscall(regs, number);
	restrict_user_xcr0();
	return result;
}

static noinstr void xcr0_probe_exit_user(struct pt_regs *regs, irqentry_state_t state)
{
	xcr0_probe_original_exit(regs, state);
	if (user_mode(regs))
		restrict_user_xcr0();
}

static noinstr void xcr0_probe_debug_user(struct pt_regs *regs)
{
	restore_kernel_xcr0();
	xcr0_probe_original_debug(regs);
	restrict_user_xcr0();
}

static noinstr void xcr0_probe_breakpoint(struct pt_regs *regs)
{
	u64 previous = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	restore_kernel_xcr0();
	xcr0_probe_original_breakpoint(regs);
	if (user_mode(regs))
		restrict_user_xcr0();
	else
		xsetbv(XCR_XFEATURE_ENABLED_MASK, previous);
}

static noinstr void xcr0_probe_int80(struct pt_regs *regs)
{
	restore_kernel_xcr0();
	xcr0_probe_original_int80(regs);
	restrict_user_xcr0();
}

static noinstr long xcr0_probe_fast32(struct pt_regs *regs)
{
	long result;

	restore_kernel_xcr0();
	result = xcr0_probe_original_fast32(regs);
	restrict_user_xcr0();
	return result;
}

static noinstr void xcr0_probe_mce_user(struct pt_regs *regs)
{
	restore_kernel_xcr0();
	xcr0_probe_original_mce(regs);
	restrict_user_xcr0();
}

static noinstr irqentry_state_t xcr0_probe_nmi_enter(struct pt_regs *regs)
{
	struct nmi_states *states = this_cpu_ptr(&nmi_states);
	u64 previous = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	unsigned int slot;

	restore_kernel_xcr0();
	if (previous != normal_xcr0) {
		for (slot = 0; slot < ARRAY_SIZE(states->frames); slot++) {
			if (!READ_ONCE(states->frames[slot]))
				break;
		}
		BUG_ON(slot == ARRAY_SIZE(states->frames));
		states->xcr0[slot] = previous;
		WRITE_ONCE(states->frames[slot], regs);
	}
	return xcr0_probe_original_nmi_enter(regs);
}

static noinstr void xcr0_probe_nmi_exit(struct pt_regs *regs, irqentry_state_t state)
{
	struct nmi_states *states = this_cpu_ptr(&nmi_states);
	unsigned int slot;

	xcr0_probe_original_nmi_exit(regs, state);
	for (slot = 0; slot < ARRAY_SIZE(states->frames); slot++) {
		if (READ_ONCE(states->frames[slot]) == regs) {
			u64 previous = states->xcr0[slot];

			WRITE_ONCE(states->frames[slot], NULL);
			xsetbv(XCR_XFEATURE_ENABLED_MASK, previous);
			break;
		}
	}
}

struct entry_patch {
	void *replacement;
	unsigned int length;
	unsigned char expected[XCR0_PROFILE_WINDOW];
	unsigned char *site;
	unsigned char original[XCR0_PROFILE_WINDOW];
	unsigned char branch[XCR0_PROFILE_WINDOW];
	bool atomic_entry;
};

/* Same order as HOOKS in module-tool/src/profile.rs. */
static struct entry_patch patches[] = {
	{ .replacement = xcr0_probe_entry },
	{ .replacement = xcr0_probe_syscall },
	{ .replacement = xcr0_probe_exit_user },
	{ .replacement = xcr0_probe_nmi_enter },
	{ .replacement = xcr0_probe_nmi_exit },
	{ .replacement = xcr0_probe_debug_user },
	{ .replacement = xcr0_probe_breakpoint, .atomic_entry = true },
	{ .replacement = xcr0_probe_int80 },
	{ .replacement = xcr0_probe_fast32 },
	{ .replacement = xcr0_probe_mce_user },
};

#if XCR0_TEXT_POKE_ATOMIC_CUSTOM
static void write_atomic_text(void *destination, const void *source, size_t length)
{
	u64 value;

	BUG_ON(length != sizeof(value) || !IS_ALIGNED((unsigned long)destination, sizeof(value)));
	memcpy(&value, source, sizeof(value));
#if XCR0_HAVE_LASS
	lass_stac();
#endif
	__asm__ volatile("movq %1, (%0)" : : "r"(destination), "r"(value) : "memory");
#if XCR0_HAVE_LASS
	lass_clac();
#endif
}
#endif

static int __nocfi install_atomic_entry(void *data)
{
	struct entry_patch *patch = data;

#if XCR0_TEXT_POKE_ATOMIC_CUSTOM
	kernel_text_poke_custom(write_atomic_text, patch->site, patch->branch, sizeof(u64));
#else
	/* The custom helper is unavailable; all other CPUs are stopped, so a plain poke is equivalent. */
	kernel_text_poke(patch->site, patch->branch, sizeof(u64));
#endif
	return 0;
}

static int __nocfi install_patches(void)
{
	unsigned int index;
	int result;

	mutex_lock(kernel_text_mutex);
	for (index = 0; index < ARRAY_SIZE(patches); index++) {
		struct entry_patch *patch = &patches[index];

		if (memcmp(patch->site, patch->original, patch->length)) {
			mutex_unlock(kernel_text_mutex);
			return -EBUSY;
		}
	}
	for (index = 0; index < ARRAY_SIZE(patches); index++) {
		struct entry_patch *patch = &patches[index];

		if (!patch->atomic_entry)
			continue;
		result = stop_machine(install_atomic_entry, patch, NULL);
		if (result) {
			mutex_unlock(kernel_text_mutex);
			return result;
		}
		kernel_text_sync();
	}
	for (index = 0; index < ARRAY_SIZE(patches); index++) {
		struct entry_patch *patch = &patches[index];

		if (!patch->atomic_entry)
			kernel_text_poke_single(patch->site, patch->branch, JMP32_INSN_SIZE, NULL);
	}
	mutex_unlock(kernel_text_mutex);
	return 0;
}

static const unsigned char endbr[] = { 0xf3, 0x0f, 0x1e, 0xfa };
/* Kernels without hardware IBT overwrite unreferenced ENDBRs; the encoding changed over time. */
static const unsigned char sealed_endbr[][4] = {
	{ 0x0f, 0x1f, 0x40, 0xd6 }, { 0x66, 0x0f, 0x1f, 0x00 },
};

static int __init __nocfi xcr0_probe_init(void)
{
	const void *build_id;
	struct kprobe lookup_probe = { .symbol_name = "kallsyms_lookup_name" };
	long displacement;
	s32 relative;
	int result;
	unsigned int index;

	BUILD_BUG_ON(offsetof(struct pt_regs, cs) != 0x88);
	BUILD_BUG_ON(ARRAY_SIZE(patches) != ARRAY_SIZE(xcr0_profile_entries));
	if (strcmp(utsname()->release, XCR0_PROFILE_RELEASE) ||
	    !boot_cpu_has(X86_FEATURE_XSAVE) || !boot_cpu_has(X86_FEATURE_OSXSAVE) ||
#ifdef X86_FEATURE_FRED
	    boot_cpu_has(X86_FEATURE_FRED) ||
#endif
	    boot_cpu_has(X86_FEATURE_IBT))
		return -ENODEV;
	result = register_kprobe(&lookup_probe);
	if (result)
		return result;
	kernel_lookup = (void *)lookup_probe.addr;
	unregister_kprobe(&lookup_probe);
	build_id = (void *)kernel_lookup("vmlinux_build_id");
	if (!build_id || memcmp(build_id, xcr0_profile_build_id, sizeof(xcr0_profile_build_id))) {
		pr_err("xcr0_probe: unsupported kernel build ID (running %*phN, module built for %*phN)\n",
		       build_id ? (int)sizeof(xcr0_profile_build_id) : 0, build_id,
		       (int)sizeof(xcr0_profile_build_id), xcr0_profile_build_id);
		return -ENOEXEC;
	}
	kernel_text_mutex = (void *)kernel_lookup("text_mutex");
	kernel_text_poke_single = (void *)kernel_lookup(XCR0_SYM_TEXT_POKE_SINGLE);
#if XCR0_TEXT_POKE_ATOMIC_CUSTOM
	kernel_text_poke_custom = (void *)kernel_lookup(XCR0_SYM_TEXT_POKE_ATOMIC);
	if (!kernel_text_poke_custom)
		return -ENOENT;
#else
	kernel_text_poke = (void *)kernel_lookup(XCR0_SYM_TEXT_POKE_ATOMIC);
	if (!kernel_text_poke)
		return -ENOENT;
#endif
	kernel_text_sync = (void *)kernel_lookup(XCR0_SYM_TEXT_POKE_SYNC);
	if (!kernel_text_mutex || !kernel_text_poke_single || !kernel_text_sync)
		return -ENOENT;
	for (index = 0; index < ARRAY_SIZE(xcr0_profile_target_names); index++) {
		if (!xcr0_profile_target_names[index][0])
			continue;
		xcr0_probe_targets[index] = kernel_lookup(xcr0_profile_target_names[index]);
		if (!xcr0_probe_targets[index])
			return -ENOENT;
		xcr0_probe_targets[index] += xcr0_profile_target_addends[index];
	}
	normal_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	if ((normal_xcr0 & 7) != 7)
		return -ENODEV;
	for (index = 0; index < ARRAY_SIZE(patches); index++) {
		struct entry_patch *patch = &patches[index];
		const char *name = xcr0_profile_names[index];
		unsigned int reloc;

		if (xcr0_profile_lengths[index] < (patch->atomic_entry ? 8 : JMP32_INSN_SIZE) ||
		    xcr0_profile_lengths[index] > sizeof(patch->expected))
			return -ENOEXEC;
		patch->length = xcr0_profile_lengths[index];
		memcpy(patch->expected, xcr0_profile_entries[index], sizeof(patch->expected));
		patch->site = (void *)kernel_lookup(name);
		if (!patch->site)
			return -ENOENT;
		patch->site += xcr0_profile_skips[index];
		if (patch->atomic_entry && !IS_ALIGNED((unsigned long)patch->site, sizeof(u64)))
			return -ENOEXEC;
		for (reloc = 0; reloc < XCR0_PROFILE_RELOC_COUNT; reloc++) {
			const struct xcr0_profile_reloc *item = &xcr0_profile_relocs[reloc];

			if (item->hook != index)
				continue;
			relative = xcr0_probe_targets[item->target] - (unsigned long)(patch->site + item->end);
			memcpy(patch->expected + item->disp, &relative, sizeof(relative));
		}
		if (patch->atomic_entry && !memcmp(patch->expected, endbr, sizeof(endbr))) {
			unsigned int seal;

			for (seal = 0; seal < ARRAY_SIZE(sealed_endbr); seal++) {
				if (!memcmp(patch->site, sealed_endbr[seal], sizeof(endbr))) {
					memcpy(patch->expected, sealed_endbr[seal], sizeof(endbr));
					break;
				}
			}
		}
		if (memcmp(patch->site, patch->expected, patch->length)) {
			pr_err("xcr0_probe: unexpected %s entry: %*ph\n",
			       name, patch->length, patch->site);
			return -ENOEXEC;
		}
		displacement = (long)patch->replacement - (long)(patch->site + 5);
		if (displacement < S32_MIN || displacement > S32_MAX)
			return -ERANGE;
		relative = displacement;
		memcpy(patch->original, patch->site, patch->length);
		memset(patch->branch, 0x90, patch->length);
		patch->branch[0] = JMP32_INSN_OPCODE;
		memcpy(patch->branch + 1, &relative, sizeof(relative));
		xcr0_probe_continuations[index] = (unsigned long)(patch->site + patch->length);
	}
	result = xcr0_policy_prepare(kernel_lookup);
	if (result)
		return result;
	result = install_patches();
	if (result) {
		xcr0_policy_abort();
		return result;
	}
	__module_get(THIS_MODULE);
	if (xcr0_policy_start())
		return 0;
	xcr0_policy_enable();
	smp_store_release(&policy_ready, true);
	pr_info("xcr0_probe: exact-XCR0 process-tree policy ready\n");
	return 0;
}

module_init(xcr0_probe_init);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.4.0");
MODULE_INFO(xcr0_build_id, XCR0_PROFILE_BUILD_ID);
MODULE_INFO(xcr0_vm_validated, XCR0_PROFILE_VALIDATED_TEXT);
MODULE_DESCRIPTION("Experimental per-process exact-XCR0 policy for a verified stock kernel");