#include <linux/atomic.h>
#include <linux/cpuhotplug.h>
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
#include <linux/syscore_ops.h>
#include <linux/utsname.h>
#include <asm/cpufeature.h>
#include <asm/fpu/types.h>
#include <asm/fpu/xcr.h>
#include <asm/msr.h>
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
static bool ibt_disabled;
module_param_named(ibt_disabled, ibt_disabled, bool, 0444);
static bool fred_hooks;
module_param_named(fred, fred_hooks, bool, 0444);
static bool xcr0_policy_active;
module_param_named(xcr0_policy, xcr0_policy_active, bool, 0444);
static bool umip_fixup_active;
module_param_named(umip_fixup, umip_fixup_active, bool, 0444);
static bool emulate_cpuid_fault = true;
module_param(emulate_cpuid_fault, bool, 0444);
MODULE_PARM_DESC(emulate_cpuid_fault, "Start the SVM based CPUID faulting emulation when the CPU lacks the feature (default: Y)");
static int cpuid_fault_state = CPUID_FAULT_UNAVAILABLE;

static int get_cpuid_fault(char *buffer, const struct kernel_param *parameter)
{
	static const char *const names[] = {
		[CPUID_FAULT_UNAVAILABLE] = "unavailable",
		[CPUID_FAULT_NATIVE] = "native",
		[CPUID_FAULT_EMULATED] = "emulated",
		[CPUID_FAULT_ON_DEMAND] = "on_demand",
		[CPUID_FAULT_BUSY] = "busy",
	};
	int state = cpuid_fault_state;

	if (state == CPUID_FAULT_ON_DEMAND)
		state = pingu_cpuid_fault_status();
	return scnprintf(buffer, PAGE_SIZE, "%s\n", names[state]);
}

static const struct kernel_param_ops cpuid_fault_ops = { .get = get_cpuid_fault };
module_param_cb(cpuid_fault, &cpuid_fault_ops, NULL, 0444);
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
extern void xcr0_probe_original_fred_debug(struct pt_regs *regs);
extern void xcr0_probe_original_fred_int80(struct pt_regs *regs);
extern void xcr0_probe_original_fred_mce(struct pt_regs *regs);

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

/* The FRED entry points serve user and kernel events, so the caller's XCR0 is put back for the latter. */
#define XCR0_FRED_EXCEPTION(name, original)				\
static noinstr void name(struct pt_regs *regs)				\
{									\
	u64 previous = xgetbv(XCR_XFEATURE_ENABLED_MASK);		\
									\
	restore_kernel_xcr0();						\
	original(regs);							\
	if (user_mode(regs))						\
		restrict_user_xcr0();					\
	else								\
		xsetbv(XCR_XFEATURE_ENABLED_MASK, previous);		\
}

XCR0_FRED_EXCEPTION(xcr0_probe_fred_debug, xcr0_probe_original_fred_debug)
XCR0_FRED_EXCEPTION(xcr0_probe_fred_mce, xcr0_probe_original_fred_mce)

static noinstr void xcr0_probe_fred_int80(struct pt_regs *regs)
{
	restore_kernel_xcr0();
	xcr0_probe_original_fred_int80(regs);
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
	/* Not patched on this boot: the other entry mechanism (IDT or FRED) owns the event. */
	bool unused;
};

/* Slots of patches[], in the order of HOOKS in module-tool/src/profile.rs. */
enum {
	HOOK_DEBUG = 5,
	HOOK_INT80 = 7,
	HOOK_MCE = 9,
	HOOK_FRED_DEBUG = 10,
	HOOK_FRED_INT80 = 11,
	HOOK_FRED_MCE = 12,
};

static bool hook_used(unsigned int index, bool fred)
{
	switch (index) {
	case HOOK_DEBUG:
	case HOOK_INT80:
	case HOOK_MCE:
		return !fred;
	case HOOK_FRED_DEBUG:
	case HOOK_FRED_INT80:
	case HOOK_FRED_MCE:
		return fred;
	default:
		return true;
	}
}

/* Same order as HOOKS and FRED_HOOKS in module-tool/src/profile.rs. */
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
	{ .replacement = xcr0_probe_fred_debug },
	{ .replacement = xcr0_probe_fred_int80 },
	{ .replacement = xcr0_probe_fred_mce },
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

		if (patch->unused)
			continue;
		if (memcmp(patch->site, patch->original, patch->length)) {
			mutex_unlock(kernel_text_mutex);
			return -EBUSY;
		}
	}
	for (index = 0; index < ARRAY_SIZE(patches); index++) {
		struct entry_patch *patch = &patches[index];

		if (patch->unused || !patch->atomic_entry)
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

		if (!patch->unused && !patch->atomic_entry)
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

/*
 * The trampolines return into the middle of a hooked function through an indirect jump, which
 * an IBT-enforcing CPU rejects. Kernel IBT is therefore switched off (ENDBR_EN in the
 * supervisor CET MSR) on every CPU, including ones that come online or resume later.
 */
#define POLICY_S_CET_MSR 0x6a2
#define POLICY_ENDBR_EN BIT(2)

static enum cpuhp_state ibt_state;

static void ibt_set_current(bool enable)
{
	u32 low, high;

	if (rdmsr_safe(POLICY_S_CET_MSR, &low, &high))
		return;
	if (enable)
		low |= POLICY_ENDBR_EN;
	else
		low &= ~POLICY_ENDBR_EN;
	wrmsr_safe(POLICY_S_CET_MSR, low, high);
}

static int ibt_cpu_online(unsigned int cpu)
{
	ibt_set_current(false);
	return 0;
}

static void ibt_enable_on_cpu(void *unused)
{
	ibt_set_current(true);
}

#if XCR0_HAVE_SYSCORE_STRUCT
static void ibt_syscore_resume(void *data)
{
	ibt_set_current(false);
}

static const struct syscore_ops ibt_syscore_ops = { .resume = ibt_syscore_resume };
static struct syscore ibt_syscore = { .ops = &ibt_syscore_ops };
#define ibt_syscore_register() register_syscore(&ibt_syscore)
#define ibt_syscore_unregister() unregister_syscore(&ibt_syscore)
#else
static void ibt_syscore_resume(void)
{
	ibt_set_current(false);
}

static struct syscore_ops ibt_syscore_ops = { .resume = ibt_syscore_resume };
#define ibt_syscore_register() register_syscore_ops(&ibt_syscore_ops)
#define ibt_syscore_unregister() unregister_syscore_ops(&ibt_syscore_ops)
#endif

static int policy_ibt_off(void)
{
	int result;

	if (!cpu_feature_enabled(X86_FEATURE_IBT))
		return 0;
	ibt_syscore_register();
	/* Runs the callback on every online CPU now and on each CPU that comes online later. */
	result = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/pingu_policy:ibt", ibt_cpu_online, NULL);
	if (result < 0) {
		ibt_syscore_unregister();
		return result;
	}
	ibt_state = result;
	ibt_disabled = true;
	pr_info("xcr0_probe: kernel IBT is switched off while the policy is loaded\n");
	return 0;
}

static void policy_ibt_back_on(void)
{
	if (!ibt_disabled)
		return;
	cpuhp_remove_state_nocalls(ibt_state);
	ibt_syscore_unregister();
	on_each_cpu(ibt_enable_on_cpu, NULL, 1);
	ibt_disabled = false;
}

static int __init __nocfi xcr0_probe_lookup_init(void)
{
	struct kprobe lookup_probe = { .symbol_name = "kallsyms_lookup_name" };
	int result;

	if (kernel_lookup)
		return 0;
	result = register_kprobe(&lookup_probe);
	if (result)
		return result;
	kernel_lookup = (void *)lookup_probe.addr;
	unregister_kprobe(&lookup_probe);
	return 0;
}

static int __init __nocfi xcr0_probe_setup(void)
{
	const void *build_id;
	long displacement;
	s32 relative;
	int result;
	unsigned int index;

	BUILD_BUG_ON(offsetof(struct pt_regs, cs) != 0x88);
	BUILD_BUG_ON(ARRAY_SIZE(patches) != ARRAY_SIZE(xcr0_profile_entries));
#ifdef X86_FEATURE_FRED
	fred_hooks = cpu_feature_enabled(X86_FEATURE_FRED);
#endif
	if (fred_hooks && !XCR0_PROFILE_FRED) {
		pr_err("xcr0_probe: this kernel boots with FRED but its FRED entry points cannot be hooked; boot with fred=off\n");
		return -ENODEV;
	}
	result = xcr0_probe_lookup_init();
	if (result)
		return result;
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

		if (!hook_used(index, fred_hooks)) {
			patch->unused = true;
			continue;
		}
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
	result = xcr0_policy_prepare(kernel_lookup, true);
	if (result)
		return result;
	result = install_patches();
	if (result) {
		xcr0_policy_abort();
		return result;
	}
	if (xcr0_policy_start())
		return 0;
	xcr0_policy_enable();
	smp_store_release(&policy_ready, true);
	pr_info("xcr0_probe: exact-XCR0 process-tree policy ready\n");
	return 0;
}

/* CPUID faulting on demand hooks arch_prctl even where the kernel needs no XCR0 policy. */
static void __init __nocfi cpuid_hooks_start(void)
{
	int result = xcr0_probe_lookup_init();

	if (!result)
		result = xcr0_policy_prepare(kernel_lookup, false);
	if (!result)
		result = xcr0_policy_start();
	if (result) {
		pr_err("xcr0_probe: cannot hook arch_prctl: %d; CPUID faulting is not available\n", result);
		pingu_cpuid_fault_stop();
		cpuid_fault_state = CPUID_FAULT_UNAVAILABLE;
	}
}

static void __init stop_features(void)
{
	if (cpuid_fault_state == CPUID_FAULT_ON_DEMAND)
		pingu_cpuid_fault_stop();
	if (umip_fixup_active)
		pingu_umip_stop();
	umip_fixup_active = false;
	cpuid_fault_state = CPUID_FAULT_UNAVAILABLE;
}

/*
 * The features that can be undone start first and the kernel patches last. IBT goes off before
 * those: even the kallsyms lookup is an indirect call into a function whose ENDBR is sealed.
 */
static int __init __nocfi xcr0_probe_init(void)
{
	int result;

	if (strcmp(utsname()->release, XCR0_PROFILE_RELEASE) ||
	    !boot_cpu_has(X86_FEATURE_XSAVE) || !boot_cpu_has(X86_FEATURE_OSXSAVE))
		return -ENODEV;
	normal_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);
	if ((normal_xcr0 & 7) != 7)
		return -ENODEV;
	if (cpu_feature_enabled(X86_FEATURE_UMIP))
		umip_fixup_active = !pingu_umip_start();
	result = pingu_cpuid_fault_start(emulate_cpuid_fault);
	if (result < 0) {
		stop_features();
		return result;
	}
	cpuid_fault_state = result;
	/* A kernel that already runs with XCR0 7 has nothing to restrict. */
	if (normal_xcr0 != 7) {
		result = policy_ibt_off();
		if (!result) {
			result = xcr0_probe_setup();
			if (result)
				policy_ibt_back_on();
		}
		if (result) {
			stop_features();
			return result;
		}
		xcr0_policy_active = policy_ready;
	} else {
		if (cpuid_fault_state == CPUID_FAULT_ON_DEMAND)
			cpuid_hooks_start();
		smp_store_release(&policy_ready, true);
	}
	__module_get(THIS_MODULE);
	return 0;
}

module_init(xcr0_probe_init);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.5.0");
MODULE_INFO(xcr0_build_id, XCR0_PROFILE_BUILD_ID);
MODULE_INFO(xcr0_vm_validated, XCR0_PROFILE_VALIDATED_TEXT);
MODULE_DESCRIPTION("Experimental exact-XCR0 policy, UMIP limit fixup and CPUID faulting emulation for a verified stock kernel");