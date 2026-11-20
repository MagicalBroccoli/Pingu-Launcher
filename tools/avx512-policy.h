#ifndef XGETBV_AVX512_POLICY_H
#define XGETBV_AVX512_POLICY_H

#define ARCH_GET_CPUID 0x1011
#define ARCH_SET_CPUID 0x1012
#define ARCH_SET_AVX512_POLICY 0x6001
#define ARCH_GET_AVX512_POLICY 0x6002
#define ARCH_AVX512_POLICY_NEXT_EXEC 1UL
#define ARCH_AVX512_POLICY_ACTIVE 2UL
#define ARCH_AVX512_POLICY_XCR0_NEXT_EXEC 3UL
#define ARCH_AVX512_POLICY_XCR0_ACTIVE 4UL

#include <cpuid.h>
#include <stdbool.h>
#include <stddef.h>

/* CPUID.(7,0):EBX bit 16 (AVX512F); the XCR0-only policy leaves CPUID native, so this is the host's. */
static inline bool host_has_avx512(void)
{
	unsigned int eax, ebx, ecx, edx;

	if (__get_cpuid_max(0, NULL) < 7)
		return false;
	__cpuid_count(7, 0, eax, ebx, ecx, edx);
	return ebx & (1U << 16);
}

#endif