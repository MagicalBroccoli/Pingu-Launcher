#ifndef XCR0_MODULE_POLICY_H
#define XCR0_MODULE_POLICY_H

#include <linux/types.h>

struct task_struct;

bool xcr0_task_active(struct task_struct *task);
/* With lifecycle false only the arch_prctl hooks are installed (CPUID faulting on demand, no XCR0 policy). */
int xcr0_policy_prepare(unsigned long (*lookup)(const char *), bool lifecycle);
int xcr0_policy_start(void);
void xcr0_policy_abort(void);
void xcr0_policy_enable(void);

enum cpuid_fault_state {
	CPUID_FAULT_UNAVAILABLE,
	CPUID_FAULT_NATIVE,
	/* The hypervisor runs now. */
	CPUID_FAULT_EMULATED,
	/* It starts when a process asks for CPUID faulting. */
	CPUID_FAULT_ON_DEMAND,
	/* On demand, but SVM is in use right now (a KVM guest runs). */
	CPUID_FAULT_BUSY,
};

/* Returns the resulting enum cpuid_fault_state, or a negative error with nothing changed. */
int pingu_cpuid_fault_start(bool emulate);
void pingu_cpuid_fault_stop(void);
/* The current state of an on-demand emulation. */
int pingu_cpuid_fault_status(void);
/* Around arch_prctl(ARCH_SET_CPUID): request returns 0 to run the call (then release), <0 to fail it, 1 to skip it with success. */
int pingu_cpuid_fault_request(bool disable);
void pingu_cpuid_fault_release(void);

/* Returns 0 once SGDT and SIDT report the limits of a system without UMIP. */
int pingu_umip_start(void);
void pingu_umip_stop(void);

#endif
