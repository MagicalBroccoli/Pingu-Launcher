#include <linux/linkage.h>
#include <asm/nospec-branch.h>
#include <asm/percpu.h>
#include <asm/unwind_hints.h>
#include "profile.generated.h"

.section .noinstr.text, "ax"
SYM_CODE_START(xcr0_probe_original)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_IRQENTRY_ENTER
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations(%rip)
	int3
SYM_CODE_END(xcr0_probe_original)

SYM_CODE_START(xcr0_probe_original_syscall)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_DO_SYSCALL_64
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+8(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_syscall)

SYM_CODE_START(xcr0_probe_original_exit)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_IRQENTRY_EXIT
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+16(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_exit)

SYM_CODE_START(xcr0_probe_original_nmi_enter)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_IRQENTRY_NMI_ENTER
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+24(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_nmi_enter)

SYM_CODE_START(xcr0_probe_original_nmi_exit)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_IRQENTRY_NMI_EXIT
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+32(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_nmi_exit)

SYM_CODE_START(xcr0_probe_original_debug)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_NOIST_EXC_DEBUG
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+40(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_debug)

SYM_CODE_START(xcr0_probe_original_breakpoint)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_EXC_INT3
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+48(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_breakpoint)

SYM_CODE_START(xcr0_probe_original_int80)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_DO_INT80_EMULATION
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+56(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_int80)

SYM_CODE_START(xcr0_probe_original_fast32)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_DO_FAST_SYSCALL_32
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+64(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_fast32)

SYM_CODE_START(xcr0_probe_original_mce)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_NOIST_EXC_MACHINE_CHECK
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+72(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_mce)

SYM_CODE_START(xcr0_probe_original_fred_debug)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_FRED_EXC_DEBUG
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+80(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_fred_debug)

SYM_CODE_START(xcr0_probe_original_fred_int80)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_FRED_INT80_EMULATION
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+88(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_fred_int80)

SYM_CODE_START(xcr0_probe_original_fred_mce)
	UNWIND_HINT_FUNC
	ENDBR
	XCR0_PROLOGUE_FRED_EXC_MACHINE_CHECK
	ANNOTATE_RETPOLINE_SAFE
	jmp *xcr0_probe_continuations+96(%rip)
	int3
SYM_CODE_END(xcr0_probe_original_fred_mce)