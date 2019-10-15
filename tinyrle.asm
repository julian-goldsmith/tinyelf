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
	; input buffer is 1024 long at rbp - 1024
	; output buffer is 5 long (worst-case output length) at rbp - 1029
	sub rsp, 1029				; 1kb input buffer + 5b output buffer
	lea rbp, [rsp + 5]			; output buffer
read_loop:
	xor eax, eax				; read
	xor edi, edi				; fd = stdin
	mov edx, 1024				; input buffer is 1kb
	mov rsi, rbp				; input buffer is at rbp - len
	syscall

	cmp eax, 0				; rax is bytes read.  return code won't fill rax, so use eax
	jle exit				; zero bytes read is eof.  negative bytes is error

rle_asm:
	; rdi is data pos
	; rsi is data end
	; rsp is output start
	; output length returned in rdx
	mov rdi, rsi				; input buffer is in rsi from read call
	add rsi, rax				; r10 is now end pointer
	xchg r10, rsi

rle_asm_outer_loop:
	mov ax, 255				; run end = data end, capped to 255
	mov edx, eax
	add rdx, rdi
	cmp rdx, r10
	cmovg rdx, r10

	mov r9, rdi				; r9 = run start
	mov al, byte [rdi]			; al is current byte

	; count bytes in run
rle_asm_run_loop_start:
	inc rdi

	cmp rdi, rdx				; test for end of run
	jae rle_asm_run_loop_end

	cmp al, [rdi]				; test byte
	je rle_asm_run_loop_start
rle_asm_run_loop_end:

	; count = data pos - run start
	mov rdx, rdi
	sub rdx, r9

	; expand run
	xor ecx, ecx
	mov cl, 4
	cmp dl, cl
	cmovb ecx, edx
	jb expand_loop

	; append the rest of the count
	sub dl, cl
	mov byte [rsp + 4], dl
	mov dl, 5				; dl is output length

expand_loop:
	mov byte [rsp + rcx - 1], al
	loop expand_loop

rle_asm_end:
	xchg rdi, r9				; stash position pointer

	; length is already in rdx
	mov al, 1				; write.  rax must be < 256 before this
	mov edi, eax				; fd = stdout
	mov rsi, rsp				; buffer is at rsp
	syscall

	xchg rdi, r9
	cmp rdi, r10				; loop if we have data left to process
	jb rle_asm_outer_loop

	jmp read_loop

exit:
	xchg rdi, rax				; put error code in rdi
	neg rdi
	mov rax, 60				; exit
	syscall

textsize	equ     $ - _start
