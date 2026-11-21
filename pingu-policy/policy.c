#include <linux/binfmts.h>
#include <linux/ftrace.h>
#include <linux/hash.h>
#include <linux/module.h>
#include <linux/sched/task.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <asm/fpu/types.h>
#include <asm/fpu/xcr.h>
#include <asm/prctl.h>

#include "policy.h"
#define XCR0_PROFILE_FEATURES_ONLY
#include "profile.generated.h"

#define POLICY_SET 0x6001
#define POLICY_GET 0x6002
#define POLICY_PENDING 3
#define POLICY_ACTIVE 4
#define POLICY_BUCKET_BITS 10
#define POLICY_BUCKET_SLOTS 8

struct task_policy {
	struct task_struct *task;
	unsigned int state;
};

static struct task_policy task_policies[1 << POLICY_BUCKET_BITS][POLICY_BUCKET_SLOTS];
static DEFINE_RAW_SPINLOCK(task_policy_lock);
static bool policy_enabled;
static atomic_t tracked_tasks = ATOMIC_INIT(0);
static struct tracepoint *exec_tracepoint;
static bool exec_registered;
static long (*original_arch_prctl)(const struct pt_regs *);
static long (*original_arch_prctl32)(const struct pt_regs *);
static long (*original_arch_prctl32_compat)(const struct pt_regs *);
static int (*original_copy_thread)(struct task_struct *, const struct kernel_clone_args *);
static void (*original_free_task)(struct task_struct *);
static void (*original_put_task)(struct task_struct *);
static void (*original_delayed_free)(struct rcu_head *);
static void (*original_ret_from_fork)(struct task_struct *, struct pt_regs *, int (*)(void *), void *);

static int get_tracked_tasks(char *buffer, const struct kernel_param *parameter)
{
	return scnprintf(buffer, PAGE_SIZE, "%d\n", atomic_read(&tracked_tasks));
}

static const struct kernel_param_ops tracked_ops = { .get = get_tracked_tasks };
module_param_cb(tracked_tasks, &tracked_ops, NULL, 0444);

static __always_inline unsigned int task_state(struct task_struct *task)
{
	struct task_policy *bucket = task_policies[hash_ptr(task, POLICY_BUCKET_BITS)];
	unsigned int index;

	for (index = 0; index < POLICY_BUCKET_SLOTS; index++) {
		if (smp_load_acquire(&bucket[index].task) == task)
			return READ_ONCE(bucket[index].state);
	}
	return 0;
}

bool noinstr xcr0_task_active(struct task_struct *task)
{
	return task_state(task) == POLICY_ACTIVE;
}

static int set_task_state(struct task_struct *task, unsigned int state)
{
	struct task_policy *bucket = task_policies[hash_ptr(task, POLICY_BUCKET_BITS)];
	struct task_policy *available = NULL;
	unsigned long flags;
	unsigned int index;
	int result = 0;

	raw_spin_lock_irqsave(&task_policy_lock, flags);
	for (index = 0; index < POLICY_BUCKET_SLOTS; index++) {
		if (bucket[index].task == task) {
			available = &bucket[index];
			break;
		}
		if (!bucket[index].task && !available)
			available = &bucket[index];
	}
	if (!state) {
		if (available && available->task == task) {
			smp_store_release(&available->task, NULL);
			atomic_dec(&tracked_tasks);
		}
	} else if (available) {
		if (!available->task)
			atomic_inc(&tracked_tasks);
		WRITE_ONCE(available->state, state);
		smp_store_release(&available->task, task);
	} else {
		result = -ENOMEM;
	}
	raw_spin_unlock_irqrestore(&task_policy_lock, flags);
	return result;
}

static void restrict_task_state(struct task_struct *task)
{
#if XCR0_HAVE_TASK_FPU
	/* x86_task_fpu() is an unexported function with CONFIG_X86_DEBUG_FPU; this is its non-debug body. */
	struct fpu *fpu = (struct fpu *)((void *)task + sizeof(*task));
#else
	struct fpu *fpu = &task->thread.fpu;
#endif

	fpu->fpstate->user_xfeatures &= 7;
	fpu->perm.__state_perm &= 7;
}

static bool apply_arch_prctl(int option, unsigned long argument, long *result)
{
	struct task_struct *task = current;
	unsigned int state;

	if (!smp_load_acquire(&policy_enabled))
		return false;
	state = task_state(task);
	if (option == POLICY_GET) {
		*result = state;
		return true;
	}
	if (option == POLICY_SET) {
		if (argument && argument != POLICY_PENDING)
			*result = -EINVAL;
		else if (state == POLICY_ACTIVE)
			*result = argument == POLICY_PENDING ? 0 : -EPERM;
		else
			*result = set_task_state(task, argument);
		return true;
	}
	if (state == POLICY_ACTIVE) {
		if (option == ARCH_GET_XCOMP_SUPP || option == ARCH_GET_XCOMP_PERM) {
			*result = put_user(7ULL, (u64 __user *)argument);
			return true;
		}
		if (option == ARCH_REQ_XCOMP_PERM) {
			*result = -EOPNOTSUPP;
			return true;
		}
	}
	return false;
}

static long __nocfi call_arch_prctl(int option, unsigned long argument,
		long (*original)(const struct pt_regs *), const struct pt_regs *regs)
{
	long result;
	int request;

	if (apply_arch_prctl(option, argument, &result))
		return result;
	if (option != ARCH_SET_CPUID)
		return original(regs);
	/* Starts the CPUID faulting hypervisor if this is the first process that wants it. */
	request = pingu_cpuid_fault_request(!argument);
	if (request < 0)
		return request;
	if (request > 0)
		return 0;
	result = original(regs);
	pingu_cpuid_fault_release();
	return result;
}

static long __nocfi policy_arch_prctl(const struct pt_regs *regs)
{
	return call_arch_prctl(regs->di, regs->si, original_arch_prctl, regs);
}

static long __nocfi policy_arch_prctl32(const struct pt_regs *regs)
{
	return call_arch_prctl((unsigned int)regs->bx, (unsigned int)regs->cx, original_arch_prctl32, regs);
}

/* Older kernels (6.12 and before) route 32-bit arch_prctl through the compat entry. */
static long __nocfi policy_arch_prctl32_compat(const struct pt_regs *regs)
{
	return call_arch_prctl((unsigned int)regs->bx, (unsigned int)regs->cx, original_arch_prctl32_compat, regs);
}

static int __nocfi policy_copy_thread(struct task_struct *task, const struct kernel_clone_args *arguments)
{
	unsigned int state = task_state(current);
	int result = original_copy_thread(task, arguments);

	if (result || !state || (task->flags & (PF_KTHREAD | PF_USER_WORKER)))
		return result;
	result = set_task_state(task, state);
	if (!result && state == POLICY_ACTIVE)
		restrict_task_state(task);
	return result;
}

static void __nocfi policy_free_task(struct task_struct *task)
{
	set_task_state(task, 0);
	original_free_task(task);
}

/* Compilers may inline free_task() into its callers, so the final-put paths are hooked too. */
static void __nocfi policy_put_task(struct task_struct *task)
{
	set_task_state(task, 0);
	original_put_task(task);
}

static void __nocfi policy_delayed_free(struct rcu_head *head)
{
	set_task_state(container_of(head, struct task_struct, rcu), 0);
	original_delayed_free(head);
}

static void noinstr __nocfi policy_ret_from_fork(struct task_struct *previous,
		struct pt_regs *regs, int (*function)(void *), void *argument)
{
	instrumentation_begin();
	original_ret_from_fork(previous, regs, function, argument);
	instrumentation_end();
	if (xcr0_task_active(current))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, 7);
}

static void policy_exec(void *data, struct task_struct *task, pid_t old_pid,
		struct linux_binprm *bprm)
{
	unsigned int state = task_state(task);

	if (state == POLICY_PENDING || state == POLICY_ACTIVE) {
		restrict_task_state(task);
		WARN_ON_ONCE(set_task_state(task, POLICY_ACTIVE));
	}
}

struct lifecycle_hook {
	const char *name;
	void *replacement;
	void **original;
	bool optional;
	/* Needed by the XCR0 policy only, not by CPUID faulting on demand. */
	bool lifecycle;
	unsigned long address;
	struct ftrace_ops operations;
	bool registered;
};

static struct lifecycle_hook lifecycle_hooks[] = {
	{ .name = "__x64_sys_arch_prctl", .replacement = policy_arch_prctl, .original = (void **)&original_arch_prctl },
	{ .name = "__ia32_sys_arch_prctl", .replacement = policy_arch_prctl32, .original = (void **)&original_arch_prctl32 },
	{ .name = "__ia32_compat_sys_arch_prctl", .replacement = policy_arch_prctl32_compat,
	  .original = (void **)&original_arch_prctl32_compat, .optional = true },
	{ .name = "copy_thread", .replacement = policy_copy_thread, .original = (void **)&original_copy_thread,
	  .lifecycle = true },
	{ .name = "free_task", .replacement = policy_free_task, .original = (void **)&original_free_task,
	  .lifecycle = true },
	{ .name = "__put_task_struct", .replacement = policy_put_task, .original = (void **)&original_put_task,
	  .lifecycle = true },
	{ .name = "__delayed_free_task", .replacement = policy_delayed_free, .original = (void **)&original_delayed_free,
	  .optional = true, .lifecycle = true },
	{ .name = "ret_from_fork", .replacement = policy_ret_from_fork, .original = (void **)&original_ret_from_fork,
	  .lifecycle = true },
};

static void notrace lifecycle_redirect(unsigned long instruction, unsigned long parent,
		struct ftrace_ops *operations, struct ftrace_regs *registers)
{
	struct lifecycle_hook *hook = container_of(operations, struct lifecycle_hook, operations);

	if (!within_module(parent, THIS_MODULE))
		ftrace_regs_set_instruction_pointer(registers, (unsigned long)hook->replacement);
}

static void find_exec_tracepoint(struct tracepoint *tracepoint, void *data)
{
	if (!strcmp(tracepoint->name, "sched_process_exec"))
		exec_tracepoint = tracepoint;
}

void xcr0_policy_abort(void)
{
	unsigned int index;

	if (exec_registered) {
		tracepoint_probe_unregister(exec_tracepoint, policy_exec, NULL);
		tracepoint_synchronize_unregister();
		exec_registered = false;
	}
	for (index = 0; index < ARRAY_SIZE(lifecycle_hooks); index++)
		ftrace_free_filter(&lifecycle_hooks[index].operations);
}

int xcr0_policy_prepare(unsigned long (*lookup)(const char *), bool lifecycle)
{
	unsigned int index;
	int result;

	if (lifecycle) {
		for_each_kernel_tracepoint(find_exec_tracepoint, NULL);
		if (!exec_tracepoint)
			return -ENOENT;
	}
	for (index = 0; index < ARRAY_SIZE(lifecycle_hooks); index++) {
		struct lifecycle_hook *hook = &lifecycle_hooks[index];

		if (hook->lifecycle && !lifecycle)
			continue;
		hook->address = lookup(hook->name);
		if (!hook->address && hook->optional)
			continue;
		if (!hook->address) {
			result = -ENOENT;
			goto fail;
		}
		*hook->original = (void *)hook->address;
		hook->operations.func = lifecycle_redirect;
		hook->operations.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
			FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_PERMANENT;
		result = ftrace_set_filter_ip(&hook->operations, hook->address, 0, 0);
		if (result)
			goto fail;
	}
	if (lifecycle) {
		result = tracepoint_probe_register(exec_tracepoint, policy_exec, NULL);
		if (result)
			goto fail;
		exec_registered = true;
	}
	return 0;
fail:
	xcr0_policy_abort();
	return result;
}

int xcr0_policy_start(void)
{
	unsigned int index;
	int result;

	for (index = 0; index < ARRAY_SIZE(lifecycle_hooks); index++) {
		struct lifecycle_hook *hook = &lifecycle_hooks[index];

		if (!hook->address)
			continue;
		result = register_ftrace_function(&hook->operations);
		if (result) {
			pr_err("xcr0_probe: cannot activate %s: %d; module stays pinned and inactive\n",
			       hook->name, result);
			return result;
		}
		hook->registered = true;
	}
	return 0;
}

void xcr0_policy_enable(void)
{
	smp_store_release(&policy_enabled, true);
}