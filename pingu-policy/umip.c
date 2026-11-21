// SPDX-License-Identifier: GPL-2.0
/*
 * With UMIP active the kernel emulates SGDT and SIDT for user space and stores a zero limit.
 * The games that used to need `clearcpuid=umip` expect the limits of a system without UMIP, so
 * the stored limit is replaced after the emulation. Nothing is patched: a kretprobe on
 * fixup_umip_exception() decodes the operand address on entry and writes the limit on return.
 */
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <asm/msr.h>
#include <asm/ptrace.h>

#include "policy.h"

/* The values SGDT and SIDT return on a kernel without UMIP: 16 GDT entries, 256 IDT gates. */
#define SGDT_LIMIT 0x007f
#define SIDT_LIMIT 0x0fff
#define MAX_INSN_LENGTH 15

static atomic_long_t umip_fixups = ATOMIC_LONG_INIT(0);
static bool umip_probe_registered;

static int get_umip_fixups(char *buffer, const struct kernel_param *parameter)
{
	return scnprintf(buffer, PAGE_SIZE, "%ld\n", atomic_long_read(&umip_fixups));
}

static const struct kernel_param_ops umip_fixups_ops = { .get = get_umip_fixups };
module_param_cb(umip_fixups, &umip_fixups_ops, NULL, 0444);

struct umip_operand {
	unsigned long address;
	u16 limit;
};

static unsigned long general_register(const struct pt_regs *regs, unsigned int number)
{
	switch (number) {
	case 0: return regs->ax;
	case 1: return regs->cx;
	case 2: return regs->dx;
	case 3: return regs->bx;
	case 4: return regs->sp;
	case 5: return regs->bp;
	case 6: return regs->si;
	case 7: return regs->di;
	case 8: return regs->r8;
	case 9: return regs->r9;
	case 10: return regs->r10;
	case 11: return regs->r11;
	case 12: return regs->r12;
	case 13: return regs->r13;
	case 14: return regs->r14;
	default: return regs->r15;
	}
}

static unsigned long segment_base(u32 msr)
{
	u32 low, high;

	if (rdmsr_safe(msr, &low, &high))
		return 0;
	return ((u64)high << 32) | low;
}

/* Finds the memory operand of a 64-bit `sgdt m` or `sidt m` at the user instruction pointer. */
static bool decode_operand(struct pt_regs *regs, struct umip_operand *operand)
{
	unsigned char code[MAX_INSN_LENGTH];
	unsigned int position = 0;
	unsigned int rex = 0;
	unsigned long address;
	unsigned long segment = 0;
	bool short_address = false;
	unsigned char modrm, mod, reg, rm;

	if (!user_64bit_mode(regs) ||
	    copy_from_user_nofault(code, (const void __user *)regs->ip, sizeof(code)))
		return false;
	for (; position < sizeof(code); position++) {
		unsigned char byte = code[position];

		if (byte == 0x66 || byte == 0xf2 || byte == 0xf3 || byte == 0x26 || byte == 0x2e ||
		    byte == 0x36 || byte == 0x3e)
			continue;
		if (byte == 0x67)
			short_address = true;
		else if (byte == 0x64)
			segment = MSR_FS_BASE;
		else if (byte == 0x65)
			segment = MSR_KERNEL_GS_BASE;
		else
			break;
	}
	/* A REX prefix only counts directly in front of the opcode. */
	if (position < sizeof(code) && (code[position] & 0xf0) == 0x40)
		rex = code[position++];
	if (position + 3 > sizeof(code) || code[position] != 0x0f || code[position + 1] != 0x01)
		return false;
	modrm = code[position + 2];
	mod = modrm >> 6;
	reg = (modrm >> 3) & 7;
	rm = modrm & 7;
	if (mod == 3 || reg > 1)
		return false;
	position += 3;

	if (rm == 4) {
		unsigned char sib;
		unsigned int base, index;

		if (position >= sizeof(code))
			return false;
		sib = code[position++];
		base = (sib & 7) | ((rex & 1) << 3);
		index = ((sib >> 3) & 7) | ((rex & 2) << 2);
		address = (mod == 0 && (sib & 7) == 5) ? 0 : general_register(regs, base);
		if (index != 4)
			address += general_register(regs, index) << (sib >> 6);
		if (mod == 0 && (sib & 7) == 5) {
			s32 displacement;

			if (position + 4 > sizeof(code))
				return false;
			memcpy(&displacement, code + position, sizeof(displacement));
			position += 4;
			address += (long)displacement;
		}
	} else if (mod == 0 && rm == 5) {
		s32 displacement;

		if (position + 4 > sizeof(code))
			return false;
		memcpy(&displacement, code + position, sizeof(displacement));
		position += 4;
		address = regs->ip + position + (long)displacement;
	} else {
		address = general_register(regs, rm | ((rex & 1) << 3));
	}
	if (mod == 1) {
		if (position >= sizeof(code))
			return false;
		address += (long)(s8)code[position];
	} else if (mod == 2) {
		s32 displacement;

		if (position + 4 > sizeof(code))
			return false;
		memcpy(&displacement, code + position, sizeof(displacement));
		address += (long)displacement;
	}
	if (short_address)
		address = (u32)address;
	if (segment)
		address += segment_base(segment);
	operand->address = address;
	operand->limit = reg ? SIDT_LIMIT : SGDT_LIMIT;
	return true;
}

static int umip_entry(struct kretprobe_instance *instance, struct pt_regs *regs)
{
	struct umip_operand *operand = (struct umip_operand *)instance->data;
	struct pt_regs *user = (struct pt_regs *)regs_get_kernel_argument(regs, 0);

	operand->address = 0;
	/* A non-zero return skips the return handler for this call. */
	return !user || !decode_operand(user, operand);
}

static int umip_return(struct kretprobe_instance *instance, struct pt_regs *regs)
{
	const struct umip_operand *operand = (const struct umip_operand *)instance->data;

	/* fixup_umip_exception() returns bool: only the low byte is defined. */
	if ((u8)regs_return_value(regs) && operand->address &&
	    !copy_to_user_nofault((u16 __user *)operand->address, &operand->limit,
				  sizeof(operand->limit)))
		atomic_long_inc(&umip_fixups);
	return 0;
}

static struct kretprobe umip_probe = {
	.kp.symbol_name = "fixup_umip_exception",
	.entry_handler = umip_entry,
	.handler = umip_return,
	.data_size = sizeof(struct umip_operand),
};

int pingu_umip_start(void)
{
	int result = register_kretprobe(&umip_probe);

	if (result) {
		pr_warn("xcr0_probe: UMIP fixup is unavailable: %d\n", result);
		return result;
	}
	umip_probe_registered = true;
	pr_info("xcr0_probe: SGDT and SIDT report the limits of a system without UMIP\n");
	return 0;
}

void pingu_umip_stop(void)
{
	if (umip_probe_registered)
		unregister_kretprobe(&umip_probe);
	umip_probe_registered = false;
}
