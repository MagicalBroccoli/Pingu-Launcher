.section .text
.global _start
_start:
	xor %ecx, %ecx
	xgetbv
	cmp $7, %eax
	jne failure
	test %edx, %edx
	jne failure
	mov $384, %eax
	mov $0x6002, %ebx
	xor %ecx, %ecx
	int $0x80
	cmp $4, %eax
	jne failure
	sub $8, %esp
	mov $384, %eax
	mov $0x1021, %ebx
	mov %esp, %ecx
	int $0x80
	test %eax, %eax
	jne failure
	cmpl $7, (%esp)
	jne failure
	cmpl $0, 4(%esp)
	jne failure
	add $8, %esp
	vpxor %ymm0, %ymm0, %ymm0
	vzeroupper
	mov $20, %eax
	int $0x80
	mov %eax, %edi
	xor %ecx, %ecx
	xgetbv
	cmp $7, %eax
	jne failure
	test %edx, %edx
	jne failure
	mov (%esp), %ecx
	lea 8(%esp,%ecx,4), %esi
environment:
	cmpl $0, (%esi)
	lea 4(%esi), %esi
	jne environment
auxiliary:
	mov (%esi), %eax
	test %eax, %eax
	je failure
	cmp $32, %eax
	je found_vsyscall
	add $8, %esi
	jmp auxiliary
found_vsyscall:
	mov 4(%esi), %esi
	mov $20, %eax
	call *%esi
	cmp %edi, %eax
	jne failure
	xor %ecx, %ecx
	xgetbv
	cmp $7, %eax
	jne failure
	test %edx, %edx
	jne failure
	mov $4, %eax
	mov $1, %ebx
	mov $message, %ecx
	mov $message_length, %edx
	int $0x80
	xor %ebx, %ebx
	jmp finish
failure:
	mov $1, %ebx
finish:
	mov $1, %eax
	int $0x80
.section .rodata
message:
	.ascii "32-bit ELF: exact XCR0, INT80 and vDSO syscall PASS\n"
.set message_length, . - message
.section .note.GNU-stack,"",@progbits