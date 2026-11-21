#ifndef XCR0_MODULE_POLICY_H
#define XCR0_MODULE_POLICY_H

#include <linux/types.h>

struct task_struct;

bool xcr0_task_active(struct task_struct *task);
int xcr0_policy_prepare(unsigned long (*lookup)(const char *));
int xcr0_policy_start(void);
void xcr0_policy_abort(void);
void xcr0_policy_enable(void);

enum cpuid_fault_state {
	CPUID_FAULT_UNAVAILABLE,
	CPUID_FAULT_NATIVE,
	CPUID_FAULT_EMULATED,
};

/* Returns the resulting enum cpuid_fault_state, or a negative error with nothing changed. */
int pingu_cpuid_fault_start(bool emulate);
void pingu_cpuid_fault_stop(void);

/* Returns 0 once SGDT and SIDT report the limits of a system without UMIP. */
int pingu_umip_start(void);
void pingu_umip_stop(void);

#endif
