/* SPDX-License-Identifier: Unlicense */
.text
.globl start
start:
	mov %rdi, %rbp /* entry */
	mov %rsi, %rax /* _tos */
	mov %rdx, %rbx /* argc */
	mov %rcx, %rsi /* argv */

	/* push argv onto stack */
	mov %rbx, %rcx
	add $1, %rcx
	sal $3, %rcx
	sub %rcx, %rsp
	mov %rsp, %rdi
	rep movsb

	/* push argc onto stack */
	push %rbx

	jmp *%rbp

.section .note.GNU-stack,"",@progbits
