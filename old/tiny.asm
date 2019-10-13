; https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
BITS 64
GLOBAL _start
SECTION .text
_start:
	mov rax, 60
	mov rdi, 42
	syscall
