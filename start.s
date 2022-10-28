.text
.globl start
start:
	mov %rdi, %rbx /* entry */
	mov %rsi, %rax /* argc */
	mov %rdx, %r8  /* argv */
	mov %rcx, %r9  /* _tos */

	/* push argv onto stack */
	mov %r8, %rcx
	add $1, %rcx
	sal $3, %rcx
	sub %rcx, %rsp
	mov %rsp, %rdi
	mov %r9, %rsi
	rep movsb

	/* push argc onto stack */
	push %r8

	jmp *%rbx

.section .note.GNU-stack,"",@progbits
