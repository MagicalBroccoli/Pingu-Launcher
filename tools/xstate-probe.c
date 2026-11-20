#define _GNU_SOURCE
#include "avx512-policy.h"
#include <cpuid.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t read_xcr(unsigned int index)
{
	unsigned int low, high;

	__asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(index));
	return ((uint64_t)high << 32) | low;
}

static void execute_avx2(void)
{
	__asm__ volatile("vpxor %%ymm0, %%ymm0, %%ymm0\n\tvzeroupper"
			 : : : "xmm0");
}

static void execute_avx512(void)
{
	__asm__ volatile("vpxord %%zmm0, %%zmm0, %%zmm0\n\tvzeroupper"
			 : : : "xmm0");
}

static void execute_disabled_cpuid(void)
{
	unsigned int eax, ebx, ecx, edx;

	if (syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0UL) < 0)
		_exit(errno == ENODEV ? 77 : 1);
	__cpuid_count(0, 0, eax, ebx, ecx, edx);
}

static int run_instruction(void (*instruction)(void))
{
	pid_t child;
	int child_status;

	fflush(NULL);
	child = fork();
	if (child < 0) {
		perror("fork");
		return -1;
	}
	if (child == 0) {
		struct rlimit core_limit = { 0, 0 };

		if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
			_exit(1);
		instruction();
		_exit(0);
	}
	while (waitpid(child, &child_status, 0) < 0) {
		if (errno == EINTR)
			continue;
		perror("waitpid");
		return -1;
	}
	if (WIFSIGNALED(child_status))
		return WTERMSIG(child_status);
	if (WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0)
		return 0;
	if (WIFEXITED(child_status) && WEXITSTATUS(child_status) == 77)
		return 77;
	return -1;
}

static int check_instruction(const char *name, void (*instruction)(void),
			     bool enabled)
{
	int result = run_instruction(instruction);
	int expected = enabled ? 0 : SIGILL;

	printf("%s execution: %s (result=%d, expected=%d)\n", name,
	       result == expected ? "PASS" : "FAIL", result, expected);
	return result == expected ? 0 : 1;
}

int main(int argc, char **argv)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned int max_leaf = __get_cpuid_max(0, NULL);
	unsigned int leaf1_ecx = 0, leaf7_ebx = 0;
	uint64_t xcr0 = 0, xcr0_supported = 7;
	bool expect_restricted = false, expect_unrestricted = false;
	bool expect_xcr0_only = false;
	bool avx2, avx512;
	char vendor[13] = { 0 };
	int failures = 0;

	if (argc == 2 && !strcmp(argv[1], "--expect=avx2"))
		expect_restricted = true;
	else if (argc == 2 && !strcmp(argv[1], "--expect=avx512"))
		expect_unrestricted = true;
	else if (argc == 2 && !strcmp(argv[1], "--expect=xcr0-only"))
		expect_xcr0_only = true;
	else if (argc != 1) {
		fprintf(stderr, "Usage: %s [--expect=avx2|--expect=avx512|--expect=xcr0-only]\n", argv[0]);
		return 2;
	}

	__cpuid_count(0, 0, eax, ebx, ecx, edx);
	memcpy(vendor, &ebx, 4);
	memcpy(vendor + 4, &edx, 4);
	memcpy(vendor + 8, &ecx, 4);
	printf("CPU vendor: %s; maximum basic leaf: 0x%x\n", vendor, max_leaf);

	if (max_leaf >= 1) {
		__cpuid_count(1, 0, eax, ebx, ecx, edx);
		leaf1_ecx = ecx;
	}
	if (max_leaf >= 7) {
		__cpuid_count(7, 0, eax, ebx, ecx, edx);
		leaf7_ebx = ebx;
		printf("CPUID(7,0): %08x %08x %08x %08x\n", eax, ebx, ecx, edx);
	}
	if ((leaf1_ecx & (3U << 26)) == (3U << 26)) {
		xcr0 = read_xcr(0);
		printf("XCR0: 0x%016" PRIx64 "\n", xcr0);
		if (max_leaf >= 0x0d) {
			__cpuid_count(0x0d, 0, eax, ebx, ecx, edx);
			printf("CPUID(D,0): %08x %08x %08x %08x\n", eax, ebx, ecx, edx);
			xcr0_supported = eax;
			__cpuid_count(0x0d, 1, eax, ebx, ecx, edx);
			printf("CPUID(D,1): %08x %08x %08x %08x\n", eax, ebx, ecx, edx);
			if (eax & (1U << 2))
				printf("XGETBV(1): 0x%016" PRIx64 "\n", read_xcr(1));
		}
	} else {
		puts("XGETBV unavailable: XSAVE/OSXSAVE not both advertised");
	}

	avx2 = (leaf1_ecx & (1U << 28)) && (leaf7_ebx & (1U << 5)) &&
	       (xcr0 & 0x6) == 0x6;
	avx512 = (leaf7_ebx & (1U << 16)) && (xcr0 & 0xe6) == 0xe6;
	failures += check_instruction("AVX2", execute_avx2, avx2);
	failures += check_instruction("AVX-512", execute_avx512, avx512);

	if (expect_restricted) {
		bool matches = avx2 && !(xcr0 & 0xe0) && !(leaf7_ebx & (1U << 16));

		printf("AVX2-only policy: %s\n", matches ? "PASS" : "FAIL");
		failures += !matches;
	}
	if (expect_unrestricted) {
		/* Without AVX-512 in the CPU the policy shows as XCR0 being narrowed below what it supports. */
		bool matches = host_has_avx512() ? avx512 : avx2 && (xcr0 != 7 || xcr0_supported == 7);

		printf("Unrestricted AVX-512 policy: %s\n", matches ? "PASS" : "FAIL");
		failures += !matches;
	}
	if (expect_xcr0_only) {
		bool cpuid_native = !!(leaf7_ebx & (1U << 16)) == ((xcr0_supported & 0xe0) == 0xe0);
		bool matches = avx2 && xcr0 == 7 && cpuid_native;

		printf("Exact XCR0=0x7 with native CPUID: %s\n", matches ? "PASS" : "FAIL");
		failures += !matches;
	}
	if (!expect_restricted) {
		int fault_result = run_instruction(execute_disabled_cpuid);

		printf("CPUID faulting: %s (result=%d)\n",
		       fault_result == SIGSEGV ? "supported" :
		       fault_result == 77 ? "unsupported" : "unexpected result",
		       fault_result);
		failures += fault_result != SIGSEGV && fault_result != 77;
	}
	printf("Result: %s (%d failures)\n", failures ? "FAIL" : "PASS", failures);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}