BITS 64

org     0x400000

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

align 4
_start:
	; input buffer is 1024 long at (initial) rsp - 1024
	; output buffer is 5 long (worst-case output length) at (initial) rsp - 1029
	sub rsp, 1029				; 5b output buffer + 1kb input buffer
	lea rbp, [rsp + 5]			; input buffer
	cld					; make sure flag is set to increment

read_loop:
	xor eax, eax				; read
	xor edi, edi				; fd = stdin
	mov edx, 1024				; input buffer is 1kb
	mov rsi, rbp				; input buffer is at rbp
	syscall

	cmp eax, 0				; rax is bytes read.  return code won't fill rax, so use eax
	jle exit				; zero bytes read is eof.  negative bytes is error

rle_asm:
	; rbp is data base
	; rbx is data pos
	; r10 is data length
	; rdi is temp data pointer / temp output pointer
	; ecx is run max counter / byte expand counter
	; rsp is output start
	; output length returned in rdx
	xor ebx, ebx				; init data position
	mov r10, rax				; r10 is now length

rle_asm_outer_loop:
	mov ecx, 255				; cap max run length to 255
	add ecx, ebx
	cmp ecx, r10d				; cap run length to data end if necessary
	cmovg ecx, r10d
	sub ecx, ebx

	lea rdi, [rbp + rbx]
	movzx eax, byte [rdi]			; al is current byte
	mov r8, rdi

	; count bytes in run
	repe scasb				; search string for byte not in al

	; count
	;sub rdi, rbp				; trash rdi, because we reset it later
	sub rdi, r8
	xchg ebx, edi				; rbx should be position in output
	;dec ebx

	; expand run
	mov edx, ebx				; use rdx, since we want it to be length later
	mov ecx, 4				; cap bytes to duplicate to 4
	cmp ecx, edx
	cmovg ecx, edx
	jg expand_loop

	; append the rest of the count
	sub dx, cx
	mov byte [rsp + 4], dl
	mov dl, 5				; dl is output length

expand_loop:
	mov rdi, rsp
	rep stosb

rle_asm_end:
	; length is already in rdx
	mov al, 1				; write.  rax must be < 256 before this
	mov edi, eax				; fd = stdout
	mov rsi, rsp				; buffer is at rsp
	syscall

	;sub r10d, ebx				; take out count. loop if we have data left to process
	cmp r10d, ebx
	jg rle_asm_outer_loop

	jmp read_loop

exit:
	xchg rdi, rax				; put error code in rdi
	neg rdi
	mov rax, 60				; exit
	syscall

textsize	equ     $ - _start
