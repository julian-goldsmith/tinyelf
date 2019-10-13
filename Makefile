all: tinycat tinymv tinyrle

tinycat: tinycat.asm
	nasm -f bin -o tinycat tinycat.asm
	chmod a+x tinycat

tinymv: tinymv.asm
	nasm -f bin -o tinymv tinymv.asm
	chmod a+x tinymv

tinyrle: tinyrle.asm
	nasm -f bin -o tinyrle tinyrle.asm
	chmod a+x tinyrle
