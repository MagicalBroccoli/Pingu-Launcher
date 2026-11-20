#ifndef XCR0_MODULE_POLICY_H
#define XCR0_MODULE_POLICY_H

#include <linux/types.h>

struct task_struct;

bool xcr0_task_active(struct task_struct *task);
int xcr0_policy_prepare(unsigned long (*lookup)(const char *));
int xcr0_policy_start(void);
void xcr0_policy_abort(void);
void xcr0_policy_enable(void);

#endif