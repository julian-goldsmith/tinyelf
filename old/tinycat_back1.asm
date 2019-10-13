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
	dq      textsize                        ;   p_filesz		Elf64_Xword
	dq      textsize                        ;   p_memsz		Elf64_Xword
	dq      0x0004                          ;   p_align		Elf64_Xword
phdrsize	equ     $ - phdr

align 4
_start:
	mov rbp, rsp				; mark stack base
	mov rcx, [rsp]				; argc
	;lea rsp, [8+8*rcx+rsp]			; preserve parameters (actually, this trashes them, so don't)
	
	xor rdi, rdi				; default fd = stdin
	mov [rbp - 8], rdi
	cmp rcx, 1				; if we have no arguments, don't open a file
	jle read_loop

	mov rax, 2				; open
	mov rdi, [rbp + 16]			; second argument is file to read
	xor rsi, rsi				; flags = O_RDONLY
	syscall
	mov [rbp - 8], rax			; store fd

	cmp rax, 0				; negative fd indicates error
	jl exit

read_loop:
	xor rax, rax				; read
	mov rdi, [rbp - 8]			; fd
	mov rdx, 1024				; buffer is 1kb
	lea rsi, [rbp - 8 - 1024]		; buffer is on stack
	sub rsi, rdx
	syscall

	cmp rax, 0				; rax is bytes read
	jle exit				; zero bytes read is eof.  negative bytes is error

	xchg rax, rdx				; length
	mov rax, 1				; write
	mov rdi, rax				; fd = stdout = 1
	syscall

	jmp read_loop

exit:
	mov rdi, rax				; put error code in rdi
	neg rdi
	mov rax, 60				; exit
	syscall

textsize	equ     $ - _start
