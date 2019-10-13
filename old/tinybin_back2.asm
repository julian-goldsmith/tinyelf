BITS 64

	org     0x400000

ehdr:                                           ; Elf64_Ehdr
	db      0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
	times 8 db      0
	dw      2                               ;   e_type		Elf64_Half
	dw      62                              ;   e_machine		Elf64_Half
	dd      1                               ;   e_version		Elf64_Word
	dq      _start                          ;   e_entry		Elf64_Addr
	dq      phdr - ehdr                     ;   e_phoff		Elf64_Off
	dq      0                               ;   e_shoff		Elf64_Off
	dd      0                               ;   e_flags		Elf64_Word
	dw      ehdrsize                        ;   e_ehsize		Elf64_Half
	dw      phdrsize                        ;   e_phentsize		Elf64_Half
	dw      1                               ;   e_phnum		Elf64_Half
	dw      0                               ;   e_shentsize		Elf64_Half
	dw      0                               ;   e_shnum		Elf64_Half
	dw      0                               ;   e_shstrndx		Elf64_Half

ehdrsize	equ     $ - ehdr

phdr:                                           ; Elf64_Phdr
	dd      1                               ;   p_type		Elf64_Word
	dd      5                               ;   p_flags (r-x)	Elf64_Word
	dq      phdr - ehdr                     ;   p_offset		Elf64_Off
	dq      phdr                            ;   p_vaddr		Elf64_Addr
	dq      phdr                            ;   p_paddr		Elf64_Addr
	dq      filesize                        ;   p_filesz		Elf64_Xword
	dq      filesize                        ;   p_memsz		Elf64_Xword
	dq      0x0004                          ;   p_align		Elf64_Xword

phdrsize	equ     $ - phdr

align 4
_start:
	mov rbp, rsp				; mark bottom of stack
	sub rsp, 32				; push 32 bytes for buffer

read_loop:
	mov rax, 0				; read
	mov rdi, 0				; from stdin
	mov rsi, rsp				; buffer is on stack
	mov rdx, 32				; buffer is 32 long
	syscall

	cmp rax, 0				; rax is bytes read
	jl error_message			; negative bytes read is error
	je end_loop				; zero bytes read is eof

	xchg rax, rdx				; length
	mov rax, 1				; write
	mov rdi, 1				; fd = stdout
	mov rsi, rsp				; buffer
	syscall

	jmp read_loop

end_loop:
	mov rax, 60				; exit
	mov rdi, 0				; return code
	syscall

; prints error code in rax and exits.  don't pass in 0.  error code is negative.
error_message:
	mov rcx, 1				; message length
	dec rsp
	mov byte [rsp], 10			; append newline

	; add error code to message
	neg rax					; error code is negative, so flip sign
	mov bl, 10				; constant denominator
error_message_code_loop:
	div bl					; divide ax by 10
	add ah, '0'				; convert ah to ascii digit
	dec rsp
	inc rcx
	mov byte [rsp], ah			; store character
	xor ah, ah				; clear remainder
	cmp al, 0
	jnz error_message_code_loop

	; copy message to stack
	add rcx, msglen
	mov rdi, msg
	mov rsi, rdi
	add rsi, msglen - 1
error_message_copy_loop:
	dec rsp
	mov al, byte [rsi]
	dec rsi
	mov byte [rsp], al
	cmp rsi, rdi
	jge error_message_copy_loop

	mov rax, 1				; write
	mov rdi, 2				; fd = stderr
	mov rsi, rsp				; buffer
	mov rdx, rcx				; length
	syscall

	mov rsp, rbp

	mov rax, 60				; exit
	mov rdi, -1				; return code
	syscall

msg		db "Error "
msglen		equ $ - msg

filesize	equ     $ - _start
