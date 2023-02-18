cpu 386
bits 32

org 0x08048000

elf_header:
.start
   db 0x7F, "ELF"
   db 1
   db 1
   db 1
   db 0,0,0,0,0,0,0,0,0
   dw 3
   dw 3
   dd 1
   dd _start
   dd segments_table - $$
   dd 1000 ; invalid sections table offset
   dd 0
   dw elf_header.size
   dw 32
   dw 2
   dw 0
   dw 0
   dw 0
.size equ $ - .start

segments_table:

code_segment_descriptor:
.start:
   dd 1
   dd 0
   dd $$
   dd 0
   dd code_size
   dd code_size
   dd 5
   dd 0x4
.size equ $ - .start

; empty dynamic section
dyn_segment_descriptor:
.start:
   dd 2
   dd _code
   dd $$
   dd 0
   dd dyn_size
   dd dyn_size
   dd 5
   dd 0x4
.size equ $ - .start

_code :
_start:
   mov  eax, 1
   mov  ebx, 0
   int  0x80
align 4
code_size equ $ - $$

_dyn:
data_size equ $ - _dyn
