BITS 64

ehdr:                                           ; Elf64_Ehdr
	db      0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
	times	8 db 0
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

	org     0x400000
align 4
_start:
	mov rax, 82				; rename.  also error code, if needed
	pop rcx					; if we don't have 3 arguments, quit
	cmp cl, 3
	jne exit

	pop rcx					; first argument is executable path
	pop rdi					; second argument is source
	pop rsi					; third argument is destination
	syscall

exit:
	mov rdi, rax				; put error code in rdi
	neg rdi
	mov rax, 60				; exit
	syscall

textsize	equ     $ - _start
