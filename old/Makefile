all:
	nasm -f elf64 tiny.asm
	ld -m elf_x86_64 -s -static --nmagic -o tiny tiny.o
	#gcc -o tiny -nostdlib -nostartfiles tiny.o

clean:
	rm tiny tiny.o
