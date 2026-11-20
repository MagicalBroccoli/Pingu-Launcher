#define _GNU_SOURCE
#include "avx512-policy.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s --check | PROGRAM [ARGUMENTS...]\n", argv[0]);
		return 2;
	}
	const char *mode = getenv("AVX2_POLICY");
	int check_only = argc == 2 && !strcmp(argv[1], "--check");
	int runtime_only = !check_only && mode && !strcmp(mode, "runtime-only");
	int xcr0_only = mode && !strcmp(mode, "xcr0-only");
	unsigned long requested = xcr0_only ? ARCH_AVX512_POLICY_XCR0_NEXT_EXEC :
					     ARCH_AVX512_POLICY_NEXT_EXEC;
	long active = syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL);

	if (runtime_only && (active == ARCH_AVX512_POLICY_ACTIVE ||
			     active == ARCH_AVX512_POLICY_XCR0_ACTIVE)) {
		fputs("Cannot remove an inherited CPU policy; start a fresh unrestricted process\n", stderr);
		return 1;
	}
	if (!runtime_only && syscall(SYS_arch_prctl, ARCH_SET_AVX512_POLICY,
		    requested) < 0) {
		perror("Cannot arm AVX-512 restriction (experimental kernel required)");
		return 1;
	}
	if (check_only)
		return 0;
	execvp(argv[1], argv + 1);
	int exec_error = errno;

	perror(argv[1]);
	return exec_error == ENOENT ? 127 : 126;
}