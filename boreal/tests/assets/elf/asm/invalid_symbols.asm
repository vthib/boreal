cpu 386
bits 32

org 0x08048000

elf_header:
.start:
   db 0x7F, "ELF"
   db 1
   db 1
   db 1
   db 0,0,0,0,0,0,0,0,0
   dw 2
   dw 3
   dd 1
   dd _start
   dd program_header - $$
   dd sections_table - $$
   dd 0
   dw elf_header.size
   dw 32
   dw 1
   dw 40
   dw 2
   dw 1
.size equ $ - .start

program_header:
.start:
   dd 1
   dd 0
   dd 0
   dd 0
   dd code_size
   dd code_size
   dd 5
   dd 0x4
.size equ $ - .start

_start:
   mov  eax, 1
   mov  ebx, 0
   int  0x80

section_names:
   db 0, ".shrtrtab", 0
.size equ $ - section_names

align 4
code_size equ $ - _start

sections_table:

   dd 0
   dd 2
   dd 0
   ; invalid values to make the symbols parsing fail
   dd 1000
   dd 1000
   dd 1000
   dd 0
   dd 0
   dd 0
   dd 0

   dd 1
   dd 3
   dd 0
   dd 0
   dd section_names
   dd section_names.size
   dd 0
   dd 0
   dd 0
   dd 0
