#define _GNU_SOURCE
#include "../tools/avx512-policy.h"
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

static int failures;
static volatile sig_atomic_t signal_count;
static volatile sig_atomic_t signal_failure;
static const char *probe_path = "/xstate-probe";
static bool test_injected_nmis = true;
static long expected_policy = ARCH_AVX512_POLICY_ACTIVE;
static volatile sig_atomic_t cpuid_signal_count;
static volatile sig_atomic_t breakpoint_count;
static volatile sig_atomic_t breakpoint_failure;


static uint64_t read_xcr(unsigned int index)
{
	unsigned int low, high;

	__asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(index));
	return ((uint64_t)high << 32) | low;
}

static uint64_t allowed_xfeatures(void)
{
	return expected_policy == ARCH_AVX512_POLICY_XCR0_ACTIVE ? 7 : ~0xe0ULL;
}

static uint64_t allowed_kernel_xfeatures(void)
{
	return allowed_xfeatures();
}

static bool restricted_xcr0(uint64_t value)
{
	return (value & 7) == 7 && !(value & ~allowed_xfeatures());
}

static unsigned int read_pkru(void)
{
	unsigned int value, high;

	__asm__ volatile("rdpkru" : "=a"(value), "=d"(high) : "c"(0));
	return value;
}

static void check(const char *name, bool success)
{
	printf("%s: %s\n", success ? "PASS" : "FAIL", name);
	failures += !success;
}

static bool child_succeeded(pid_t child)
{
	int child_status;

	if (child < 0)
		return false;
	while (waitpid(child, &child_status, 0) < 0) {
		if (errno != EINTR)
			return false;
	}
	return WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
}

static pid_t start_program(char *const arguments[])
{
	pid_t child = fork();

	if (child == 0) {
		execv(arguments[0], arguments);
		perror(arguments[0]);
		_exit(1);
	}
	return child;
}

static bool preserve_ymm(long number, unsigned long arg1,
			 unsigned long arg2, unsigned long arg3)
{
	uint64_t expected[4], observed[4];
	uint64_t seed = (uint64_t)syscall(SYS_gettid);

	for (unsigned int index = 0; index < 4; index++)
		expected[index] = (seed << 32) | (0x10203040U + index);
	__asm__ volatile("vmovdqu %[expected], %%ymm0\n\t"
			 "syscall\n\t"
			 "vmovdqu %%ymm0, %[observed]\n\tvzeroupper"
			 : "+a"(number), [observed] "=m"(observed)
			 : [expected] "m"(expected), "D"(arg1), "S"(arg2), "d"(arg3)
			 : "rcx", "r11", "memory", "xmm0");
	return number >= 0 && !memcmp(expected, observed, sizeof(expected));
}

static bool preserve_avx2(long number, unsigned long arg1,
			  unsigned long arg2, unsigned long arg3)
{
	return preserve_ymm(number, arg1, arg2, arg3) && restricted_xcr0(read_xcr(0));
}

__attribute__((target("avx512f"), noinline))
static bool preserve_avx512_call(long number, unsigned long arg1,
				unsigned long arg2, unsigned long arg3)
{
	uint64_t expected[8], observed_low[8], observed_high[8];
	uint64_t seed = (uint64_t)getpid();
	uint16_t expected_mask = 0xa53c, observed_mask;

	for (unsigned int index = 0; index < 8; index++)
		expected[index] = (seed << 32) | (0x55667700U + index);
	__asm__ volatile("vmovdqu64 %[expected], %%zmm0\n\t"
			 "vmovdqu64 %[expected], %%zmm16\n\t"
			 "kmovw %[expected_mask], %%k1\n\t"
			 "syscall\n\t"
			 "vmovdqu64 %%zmm0, %[observed_low]\n\t"
			 "vmovdqu64 %%zmm16, %[observed_high]\n\t"
			 "kmovw %%k1, %[observed_mask]\n\tvzeroupper"
			 : "+a"(number), [observed_low] "=m"(observed_low),
			   [observed_high] "=m"(observed_high),
			   [observed_mask] "=m"(observed_mask)
			 : [expected] "m"(expected), [expected_mask] "m"(expected_mask),
			   "D"(arg1), "S"(arg2), "d"(arg3)
			 : "rcx", "r11", "memory", "zmm0", "zmm16", "k1");
	return number == 0 && (read_xcr(0) & 0xe0) == 0xe0 &&
	       observed_mask == expected_mask &&
	       !memcmp(expected, observed_low, sizeof(expected)) &&
	       !memcmp(expected, observed_high, sizeof(expected));
}

static bool preserve_avx512(void)
{
	if (!host_has_avx512())
		return preserve_ymm(SYS_sched_yield, 0, 0, 0);
	return preserve_avx512_call(SYS_sched_yield, 0, 0, 0);
}

static void signal_handler(int number, siginfo_t *info, void *context)
{
	ucontext_t *user_context = context;
	uint64_t features;

	(void)number;
	(void)info;
	memcpy(&features, (char *)user_context->uc_mcontext.fpregs + 472,
	       sizeof(features));
	if (!restricted_xcr0(read_xcr(0)) || (features & ~allowed_kernel_xfeatures()))
		signal_failure = 1;
	__asm__ volatile("vpxor %%ymm0, %%ymm0, %%ymm0" : : : "xmm0");
	signal_count++;
}

static void *thread_test(void *argument)
{
	(void)argument;
	if (syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) !=
	    expected_policy)
		return (void *)1;
	for (unsigned int round = 0; round < 1000; round++) {
		if (!preserve_avx2(SYS_sched_yield, 0, 0, 0))
			return (void *)1;
	}
	return NULL;
}

__attribute__((naked, noinline))
static void traced_cpuid(void)
{
	__asm__ volatile("cpuid\n\tint3");
}

static bool ptrace_test(void)
{
	struct user_regs_struct registers = { 0 };
	unsigned char state[16384] __attribute__((aligned(64)));
	struct iovec vector = { state, sizeof(state) };
	uint64_t features = 0;
	int child_status = 0;
	int step = 0;
	int saved_errno = 0;
	bool success = false;
	pid_t child = fork();

	if (child < 0)
		return false;
	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
			_exit(1);
		raise(SIGSTOP);
		_exit(1);
	}
	step = 1;
	if (waitpid(child, &child_status, 0) != child || !WIFSTOPPED(child_status))
		goto cleanup;
	step = 2;
	if (ptrace(PTRACE_GETREGSET, child, (void *)0x202, &vector) < 0 ||
	    vector.iov_len < 576)
		goto cleanup;
	memcpy(&features, state + 512, sizeof(features));
	step = 3;
	if (features & ~allowed_kernel_xfeatures())
		goto cleanup;
	step = 4;
	if (ptrace(PTRACE_SETREGSET, child, (void *)0x202, &vector) < 0 ||
	    ptrace(PTRACE_GETREGS, child, NULL, &registers) < 0)
		goto cleanup;
	registers.rip = (unsigned long)traced_cpuid;
	registers.rax = 7;
	registers.rcx = 0;
	step = 5;
	if (ptrace(PTRACE_SETREGS, child, NULL, &registers) < 0 ||
	    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) < 0)
		goto cleanup;
	step = 6;
	if (waitpid(child, &child_status, 0) != child ||
	    !WIFSTOPPED(child_status) || WSTOPSIG(child_status) != SIGTRAP ||
	    ptrace(PTRACE_GETREGS, child, NULL, &registers) < 0)
		goto cleanup;
	step = 7;
	success = registers.rip == (unsigned long)traced_cpuid + 2 &&
		  !!(registers.rbx & (1UL << 16)) ==
		  (expected_policy == ARCH_AVX512_POLICY_XCR0_ACTIVE && host_has_avx512());
cleanup:
	saved_errno = errno;
	if (!success)
		printf("ptrace test stopped at step %d: errno=%d xstate_len=%lu features=%#lx allowed=%#lx "
		       "status=%#x rip=%#lx expected_rip=%#lx rbx=%#lx\n",
		       step, saved_errno, (unsigned long)vector.iov_len, (unsigned long)features,
		       (unsigned long)allowed_kernel_xfeatures(), (unsigned int)child_status,
		       (unsigned long)registers.rip, (unsigned long)traced_cpuid + 2,
		       (unsigned long)registers.rbx);
	kill(child, SIGKILL);
	waitpid(child, &child_status, 0);
	return success;
}

static bool generated_code_test(void)
{
	static const unsigned char instructions[] = {
		0x31, 0xc9, 0x0f, 0x01, 0xd0, 0x48, 0xc1, 0xe2, 0x20,
		0x48, 0x09, 0xd0, 0xc3,
		0x53, 0xb8, 0x07, 0x00, 0x00, 0x00, 0x31, 0xc9,
		0x66, 0x0f, 0xa2, 0x89, 0xd8, 0x5b, 0xc3
	};
	void *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	bool success;

	if (code == MAP_FAILED)
		return false;
	memcpy(code, instructions, sizeof(instructions));
	if (mprotect(code, 4096, PROT_READ | PROT_EXEC) < 0) {
		munmap(code, 4096);
		return false;
	}
	success = restricted_xcr0(((uint64_t (*)(void))code)()) &&
		  !!(((unsigned int (*)(void))((char *)code + 13))() & (1U << 16)) ==
		  (expected_policy == ARCH_AVX512_POLICY_XCR0_ACTIVE && host_has_avx512());
	munmap(code, 4096);
	return success;
}

static bool xsave_buffer_test(bool compacted)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned char *area;
	uint64_t features, layout;
	bool success = true;

	__cpuid_count(0x0d, compacted ? 1 : 0, eax, ebx, ecx, edx);
	if (compacted && !(eax & (1U << 1)))
		return true;
	if (ebx < 576 || ebx > 65536 || posix_memalign((void **)&area, 64, ebx + 64))
		return false;
	memset(area, 0, ebx);
	memset(area + ebx, 0xa5, 64);
	if (compacted)
		__asm__ volatile("xsavec (%0)" : : "r"(area), "a"(~0U), "d"(~0U) : "memory");
	else
		__asm__ volatile("xsave (%0)" : : "r"(area), "a"(~0U), "d"(~0U) : "memory");
	memcpy(&features, area + 512, sizeof(features));
	memcpy(&layout, area + 520, sizeof(layout));
	success = !(features & ~allowed_xfeatures());
	if (compacted)
		success &= layout == (read_xcr(0) | (1ULL << 63));
	for (unsigned int index = 0; index < 64; index++)
		success &= area[ebx + index] == 0xa5;
	free(area);
	return success;
}

static long nmi_total(void)
{
	FILE *interrupts = fopen("/proc/interrupts", "r");
	char line[512];
	unsigned long first, second;
	long total = -1;

	if (!interrupts)
		return -1;
	while (fgets(line, sizeof(line), interrupts)) {
		if (sscanf(line, " NMI: %lu %lu", &first, &second) == 2) {
			total = first + second;
			break;
		}
	}
	fclose(interrupts);
	return total;
}

static bool nmi_test(void)
{
	struct timespec started, now;
	long before = nmi_total(), after;
	uint64_t elapsed;
	bool success = true;

	if (before < 0 || clock_gettime(CLOCK_MONOTONIC, &started))
		return false;
	puts("AVX512_POLICY_NMI_READY");
	do {
		for (unsigned int round = 0; round < 1000; round++)
			success &= restricted_xcr0(read_xcr(0));
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			return false;
		elapsed = (uint64_t)(now.tv_sec - started.tv_sec) * 1000000000ULL +
			  now.tv_nsec - started.tv_nsec;
	} while (elapsed < 500000000ULL);
	after = nmi_total();
	printf("Guest NMI count: %ld -> %ld\n", before, after);
	return success && after > before;
}

static void cpuid_handler(int number, siginfo_t *info, void *context)
{
	ucontext_t *user_context = context;
	greg_t *registers = user_context->uc_mcontext.gregs;
	const unsigned char *instruction = (void *)registers[REG_RIP];

	(void)number;
	(void)info;
	if (instruction[0] != 0x0f || instruction[1] != 0xa2 ||
	    !restricted_xcr0(read_xcr(0)))
		_exit(1);
	registers[REG_RAX] = 0x12345678;
	registers[REG_RBX] = 0;
	registers[REG_RCX] = 0;
	registers[REG_RDX] = 0;
	registers[REG_RIP] += 2;
	cpuid_signal_count++;
}

static bool userspace_cpuid_handler_test(void)
{
	struct sigaction action = { .sa_sigaction = cpuid_handler, .sa_flags = SA_SIGINFO };
	struct sigaction previous;
	unsigned int eax, ebx, ecx, edx;
	bool success;

	if (sigaction(SIGSEGV, &action, &previous) < 0)
		return false;
	if (syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0UL) < 0) {
		sigaction(SIGSEGV, &previous, NULL);
		return false;
	}
	__cpuid_count(0, 0, eax, ebx, ecx, edx);
	success = eax == 0x12345678 && !(ebx | ecx | edx) && cpuid_signal_count == 1;
	success &= syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1UL) == 0;
	success &= sigaction(SIGSEGV, &previous, NULL) == 0;
	return success;
}

static bool policy_status_test(void)
{
	if (getenv("AVX2_MODULE_PROBE"))
		return syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) == expected_policy;
	FILE *status_file = fopen("/proc/self/arch_status", "r");
	char line[128];
	long observed;
	bool found = false;

	if (!status_file)
		return false;
	while (fgets(line, sizeof(line), status_file)) {
		if (sscanf(line, "AVX512_policy: %ld", &observed) == 1) {
			found = observed == expected_policy;
			break;
		}
	}
	fclose(status_file);
	return found;
}

static void breakpoint_handler(int number)
{
	if (number != SIGTRAP || !restricted_xcr0(read_xcr(0)))
		breakpoint_failure = 1;
	breakpoint_count++;
}

static bool breakpoint_test(void)
{
	struct sigaction action = { .sa_handler = breakpoint_handler };
	struct sigaction previous;
	bool success;

	if (sigaction(SIGTRAP, &action, &previous))
		return false;
	__asm__ volatile("int3" : : : "memory");
	success = restricted_xcr0(read_xcr(0)) && breakpoint_count == 1 && !breakpoint_failure;
	return sigaction(SIGTRAP, &previous, NULL) == 0 && success;
}

static int restricted_tests(void)
{
	struct sigaction action = { .sa_sigaction = signal_handler, .sa_flags = SA_SIGINFO };
	pthread_t threads[4];
	unsigned int created = 0;
	cpu_set_t original, selected;
	bool success = true;
	unsigned int eax, ebx, ecx, edx;
	uint64_t features = 0;
	bool xcr0_only = expected_policy == ARCH_AVX512_POLICY_XCR0_ACTIVE;
	bool zmm_state = xcr0_only && host_has_avx512();

	check("exec activated policy", syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY,
					       0UL) == expected_policy);
	check("read-only task policy status", policy_status_test());
	check(xcr0_only ? "exact XCR0=0x7" : "restricted XCR0", restricted_xcr0(read_xcr(0)));
	errno = 0;
	if (xcr0_only) {
		check("CPUID remains enabled", syscall(SYS_arch_prctl, ARCH_GET_CPUID, 0UL) == 1);
		check("normal CPUID enable API", syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1UL) == 0);
		check("userspace CPUID handler receives faults", userspace_cpuid_handler_test());
	} else {
		check("cannot re-enable CPUID", syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1UL) == -1 && errno == EPERM);
	}
	errno = 0;
	check("cannot drop active policy", syscall(SYS_arch_prctl, ARCH_SET_AVX512_POLICY, 0UL) == -1 && errno == EPERM);
	__cpuid_count(0x0d, 0, eax, ebx, ecx, edx);
	check("CPUID xstate bitmap", (eax & 0xe0) == (zmm_state ? 0xe0U : 0U) &&
	      (xcr0_only ? ebx == 832 : ebx >= 832));
	__cpuid_count(0x0d, 1, eax, ebx, ecx, edx);
	if (eax & (1U << 2))
		check("XGETBV(1)", !(read_xcr(1) & ~allowed_xfeatures()));
	for (unsigned int component = 5; component <= 7; component++) {
		__cpuid_count(0x0d, component, eax, ebx, ecx, edx);
		/* Without AVX-512 in the CPU the native descriptors are whatever the hypervisor reports. */
		if (xcr0_only)
			success &= !host_has_avx512() || eax > 0;
		else
			success &= !(eax | ebx | ecx | edx);
	}
	check("CPUID state descriptors follow selected mode", success);
	check("xstate support query", syscall(SYS_arch_prctl, 0x1021, &features) == 0 &&
	      restricted_xcr0(features));
	check("xstate permission query", syscall(SYS_arch_prctl, 0x1022, &features) == 0 &&
	      restricted_xcr0(features));
	if (xcr0_only) {
		errno = 0;
		check("cannot request excluded AMX state", syscall(SYS_arch_prctl, 0x1023, 18UL) == -1 &&
		      errno == EOPNOTSUPP);
	}
	check("generated XGETBV and prefixed CPUID", generated_code_test());
	check("XSAVE buffer bounds", xsave_buffer_test(false));
	check("XSAVEC layout and buffer bounds", xsave_buffer_test(true));
	check("install signal handler", sigaction(SIGUSR1, &action, NULL) == 0);
	for (unsigned int round = 0; round < 20; round++)
		success &= preserve_avx2(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
	check("YMM preservation and expected signal frames", success && signal_count == 20 && !signal_failure);
	success = true;
	for (; created < 4; created++) {
		if (pthread_create(&threads[created], NULL, thread_test, NULL)) {
			success = false;
			break;
		}
	}
	for (unsigned int index = 0; index < created; index++) {
		void *result = NULL;

		if (pthread_join(threads[index], &result) || result)
			success = false;
	}
	check("thread inheritance and scheduling preserve YMM", success);
	success = sched_getaffinity(0, sizeof(original), &original) == 0;
	if (success) {
		for (unsigned int round = 0; round < 8; round++) {
			for (unsigned int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
				if (!CPU_ISSET(cpu, &original))
					continue;
				CPU_ZERO(&selected);
				CPU_SET(cpu, &selected);
				success &= preserve_avx2(SYS_sched_setaffinity, 0,
						 sizeof(selected), (unsigned long)&selected);
			}
		}
		success &= sched_setaffinity(0, sizeof(original), &original) == 0;
	}
	check("CPU migration preserves XCR0 and YMM", success);
	if (test_injected_nmis)
		check("injected NMIs preserve restricted XCR0", nmi_test());
	else
		puts("SKIP: deliberate NMI injection is limited to the disposable VM");
	check("ptrace xstate round-trip and CPUID single-step", ptrace_test());
	check("user breakpoint preserves exact policy", breakpoint_test());
	if (getenv("AVX2_MODULE_PROBE")) {
		long process_id;

		__asm__ volatile("int $0x80" : "=a"(process_id) : "a"(20)
				 : "r8", "r9", "r10", "r11", "memory");
		check("compat syscall preserves exact policy", process_id == getpid() && read_xcr(0) == 7);
	}
	check("subsequent exec inherits policy", child_succeeded(start_program(
		(char *const[]){ (char *)probe_path,
			xcr0_only ? "--expect=xcr0-only" : "--expect=avx2", NULL })));
	return failures ? 1 : 0;
}

static int pending_tests(void)
{
	uint64_t original = read_xcr(0);
	unsigned long pending = getenv("AVX2_MODULE_PROBE") ?
		ARCH_AVX512_POLICY_XCR0_NEXT_EXEC : ARCH_AVX512_POLICY_NEXT_EXEC;

	check("arm next exec", syscall(SYS_arch_prctl, ARCH_SET_AVX512_POLICY, pending) == 0);
	check("pending policy does not change XCR0", read_xcr(0) == original);
	check("pending status", syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) == (long)pending);
	execl("/does-not-exist", "/does-not-exist", (char *)NULL);
	check("failed exec leaves policy pending", errno == ENOENT &&
	      syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) == (long)pending && read_xcr(0) == original);
	check("cancel pending policy", syscall(SYS_arch_prctl, ARCH_SET_AVX512_POLICY, 0UL) == 0 &&
	      syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) == 0);
	return failures ? 1 : 0;
}

static int unrestricted_stress(int descriptor)
{
	unsigned long rounds = 0;
	bool has_pkru = (read_xcr(0) & (1ULL << 9)) != 0;
	unsigned int original_pkru = has_pkru ? read_pkru() : 0;
	char value;
	ssize_t result;

	for (;;) {
		result = read(descriptor, &value, 1);
		if (!result)
			break;
		if (result < 0 && errno != EAGAIN && errno != EINTR)
			return 1;
		if (!preserve_avx512() || (has_pkru && read_pkru() != original_pkru))
			return 1;
		rounds++;
	}
	printf("Unrestricted ZMM0/ZMM16/opmask stress: %lu rounds\n", rounds);
	return rounds ? 0 : 1;
}


static int module_probe_tests(void)
{
	uint64_t original_xcr0 = read_xcr(0);
	int descriptor = open("/pingu_policy.ko", O_RDONLY | O_CLOEXEC);
	int result;


	check("stock-kernel module file", descriptor >= 0);
	if (descriptor < 0)
		goto done;
	for (unsigned int round = 0; round < 1; round++) {
		FILE *counter;
		unsigned long hits = 0;
		int descriptors[2];
		pid_t stress;

		if (getenv("AVX2_MODULE_INSTALL_STRESS"))
			puts("MODULE_INSTALL_NMI_READY");
		result = syscall(SYS_finit_module, descriptor, "", 0);
		if (result)
			perror("finit_module");
		check("load VM entry hook", result == 0);
		if (result)
			break;
		check("unrestricted instructions with entry hook", child_succeeded(start_program(
			(char *const[]){ "/xstate-probe", "--expect=avx512", NULL })));
		if (pipe2(descriptors, O_CLOEXEC | O_NONBLOCK) < 0) {
			check("module concurrent stress pipe", false);
			break;
		}
		stress = fork();
		if (stress == 0) {
			close(descriptors[1]);
			_exit(unrestricted_stress(descriptors[0]));
		}
		close(descriptors[0]);
		check("module pending policy lifecycle", child_succeeded(start_program(
			(char *const[]){ "/policy-test", "--pending", NULL })));
		setenv("AVX2_POLICY", "xcr0-only", 1);
		check("module launcher instruction probe", child_succeeded(start_program(
			(char *const[]){ "/avx2-run", "/xstate-probe", "--expect=xcr0-only", NULL })));
		check("module 32-bit ELF and fast syscall", child_succeeded(start_program(
			(char *const[]){ "/avx2-run", "/xstate-compat32", NULL })));
		check("module process-tree regression", child_succeeded(start_program(
			(char *const[]){ "/avx2-run", "/policy-test", "--restricted-xcr0", NULL })));
		check("module repeated process-tree regression", child_succeeded(start_program(
			(char *const[]){ "/avx2-run", "/policy-test", "--restricted-xcr0", NULL })));
		check("module task-table churn", child_succeeded(start_program(
			(char *const[]){ "/avx2-run", "/policy-test", "--module-churn", NULL })));
		unsetenv("AVX2_POLICY");
		close(descriptors[1]);
		check("module preserves concurrent unrestricted AVX-512 and PKRU", child_succeeded(stress));
		{
			struct timespec start, now;
			unsigned long remaining = 1;
			uint64_t elapsed = 0;

			if (clock_gettime(CLOCK_MONOTONIC, &start))
				return 1;
			do {
				counter = fopen("/sys/module/pingu_policy/parameters/tracked_tasks", "r");
				if (!counter)
					break;
				result = fscanf(counter, "%lu", &remaining);
				fclose(counter);
				if (result != 1 || !remaining)
					break;
				sched_yield();
				if (clock_gettime(CLOCK_MONOTONIC, &now))
					break;
				elapsed = (uint64_t)(now.tv_sec - start.tv_sec) * 1000000000ULL +
					  now.tv_nsec - start.tv_nsec;
			} while (elapsed < 3000000000ULL);
			printf("Tracked tasks after workload: %lu\n", remaining);
			check("module reclaims all task records", remaining == 0);
		}
		counter = fopen("/sys/module/pingu_policy/parameters/entry_hits", "r");
		check("hook observed kernel entries", counter && fscanf(counter, "%lu", &hits) == 1 && hits > 0);
		if (counter)
			fclose(counter);
		printf("Module entry hits: %lu\n", hits);
		errno = 0;
		check("module refuses unsafe unload", syscall(SYS_delete_module, "pingu_policy", O_NONBLOCK) == -1 &&
		      (errno == EWOULDBLOCK || errno == EBUSY));
		check("XCR0 unchanged after unload refusal", read_xcr(0) == original_xcr0);
		check("unrestricted instructions after unload refusal", child_succeeded(start_program(
			(char *const[]){ "/xstate-probe", "--expect=avx512", NULL })));
	}
	close(descriptor);
done:
	printf("MODULE_PROBE_TEST_%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
	reboot(RB_POWER_OFF);
	return failures ? 1 : 0;
}

static int guest_init(void)
{
	int descriptors[2];
	pid_t stress;
	struct rlimit core_limit = { 0, 0 };

	mkdir("/dev", 0755);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	int console = open("/dev/console", O_RDWR);
	if (console >= 0) {
		dup2(console, STDIN_FILENO);
		dup2(console, STDOUT_FILENO);
		dup2(console, STDERR_FILENO);
		if (console > STDERR_FILENO)
			close(console);
	}
	mkdir("/proc", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	setvbuf(stdout, NULL, _IONBF, 0);
	setrlimit(RLIMIT_CORE, &core_limit);
	if (getenv("AVX2_MODULE_PROBE")) {
		mkdir("/sys", 0755);
		mount("sysfs", "/sys", "sysfs", 0, NULL);
		return module_probe_tests();
	}
	puts("AVX512_POLICY_TEST_BEGIN");
	check("unrestricted baseline", child_succeeded(start_program(
		(char *const[]){ "/xstate-probe", "--expect=avx512", NULL })));
	check("pending policy lifecycle", child_succeeded(start_program(
		(char *const[]){ "/policy-test", "--pending", NULL })));
	if (pipe2(descriptors, O_CLOEXEC | O_NONBLOCK) < 0)
		return 1;
	stress = fork();
	if (stress == 0) {
		close(descriptors[1]);
		_exit(unrestricted_stress(descriptors[0]));
	}
	close(descriptors[0]);
	check("restricted instruction probe", child_succeeded(start_program(
		(char *const[]){ "/avx2-run", "/xstate-probe", "--expect=avx2", NULL })));
	check("restricted regression tests", child_succeeded(start_program(
		(char *const[]){ "/avx2-run", "/policy-test", "--restricted", NULL })));
	check("native-mode regression entry point", child_succeeded(start_program(
		(char *const[]){ "/avx2-run", "/policy-test", "--restricted-native",
				"/xstate-probe", NULL })));
	if (setenv("AVX2_POLICY", "xcr0-only", 1) != 0)
		return 1;
	check("XCR0-only instruction probe", child_succeeded(start_program(
		(char *const[]){ "/avx2-run", "/xstate-probe", "--expect=xcr0-only", NULL })));
	check("XCR0-only regression tests", child_succeeded(start_program(
		(char *const[]){ "/avx2-run", "/policy-test", "--restricted-xcr0", NULL })));
	unsetenv("AVX2_POLICY");
	close(descriptors[1]);
	check("concurrent unrestricted AVX-512 state", child_succeeded(stress));
	check("unrestricted state after restricted children exit", child_succeeded(start_program(
		(char *const[]){ "/xstate-probe", "--expect=avx512", NULL })));
	printf("AVX512_POLICY_TEST_%s failures=%d\n", failures ? "FAIL" : "PASS", failures);
	reboot(RB_POWER_OFF);
	return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (getpid() == 1 && argc == 1)
		return guest_init();
	if (argc == 2 && !strcmp(argv[1], "--module-churn")) {
		if (read_xcr(0) != 7 || syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) != 4)
			return 1;
		for (unsigned int round = 0; round < 10000; round++) {
			pid_t child = fork();

			if (child == 0)
				_exit(read_xcr(0) != 7 || syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) != 4);
			if (!child_succeeded(child))
				return 1;
		}
		puts("Module task churn: 10000 inherited children reaped");
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "--pending"))
		return pending_tests();
	if ((argc == 2 && (!strcmp(argv[1], "--restricted") ||
			  !strcmp(argv[1], "--restricted-xcr0"))) ||
	    (argc == 3 && (!strcmp(argv[1], "--restricted-native") ||
			  !strcmp(argv[1], "--restricted-xcr0-native")))) {
		if (strstr(argv[1], "xcr0"))
			expected_policy = ARCH_AVX512_POLICY_XCR0_ACTIVE;
		if (argc == 3) {
			probe_path = argv[2];
			test_injected_nmis = false;
		}
		if (syscall(SYS_arch_prctl, ARCH_GET_AVX512_POLICY, 0UL) !=
		    expected_policy) {
			fputs("Refusing restricted tests without an active kernel policy\n", stderr);
			return 77;
		}
		return restricted_tests();
	}
	fputs("Run this program as init in the disposable test guest\n", stderr);
	return 77;
}