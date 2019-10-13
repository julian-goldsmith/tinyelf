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
	; data is at rbp - 1024
	; output is at rbp - 2048
	mov rbp, rsp				; mark bottom of stack
	add rsp, 2048				; 2 1kb buffers
read_loop:
	xor rax, rax				; read
	mov rdi, rax				; fd = stdin
	mov rdx, 1024				; buffer is 1kb
	mov rsi, rbp				; buffer is on stack
	sub rsi, rdx
	syscall

	cmp rax, 0				; rax is bytes read
	jle exit				; zero bytes read is eof.  negative bytes is error

	xchg rsi, rax
	call rle_asm

	xchg rax, rdx				; length
	mov rax, 1				; write
	mov rdi, rax				; fd = stdout
	lea rsi, [rbp - 2048]			; buffer
	syscall

	jmp read_loop

exit:
	push rax				; store error code

	mov rax, 3				; close
	mov rdi, rbx				; fd
	syscall

	pop rax					; restore error code

	mov rdi, rax				; put error code in rdi
	neg rdi
	mov rax, 60				; exit
	syscall

rle_asm:
	; rdi is data pos
	; rsi is data length
	; rdx is output
	; output length returned in rax
	lea rdi, [rbp - 1024]
	lea rdx, [rbp - 2048]

	add rsi, rdi					; rsi is now end pointer
	push rdx					; store original output position

rle_asm_outer_loop:
	mov r9, rdi					; r9 = run start
	movzx rax, byte [rdi]				; al is current byte
	
	mov rcx, rdi					; run end = data end, capped to 256
	add rcx, 256
	cmp rcx, rsi
	cmovg rcx, rsi
	jmp rle_asm_run_loop_start

	; count bytes in run
rle_asm_run_loop_start:
	inc rdi

	cmp al, [rdi]					; test byte
	jne rle_asm_run_loop_end

	cmp rdi, rcx					; test for end of run
	jb rle_asm_run_loop_start
rle_asm_run_loop_end:

	; count = data pos - run start
	mov rcx, rdi
	sub rcx, r9

	; expand run
	mov byte [rdx], al
	inc rdx
	dec rcx
	jz rle_asm_after_output_count

	mov byte [rdx], al
	inc rdx
	dec rcx
	jz rle_asm_after_output_count

	mov byte [rdx], al
	inc rdx
	dec rcx
	jz rle_asm_after_output_count

	dec rcx
	mov byte [rdx], al
	inc rdx
	mov byte [rdx], cl
	inc rdx
rle_asm_after_output_count:

	cmp rdi, rsi
	jb rle_asm_outer_loop

	; return output pos - output original
	mov rax, rdx
	pop rdx
	sub rax, rdx

	ret

textsize	equ     $ - _start
