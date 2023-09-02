; A simple assembly code for exit we will change it into shell code

; It will contain null when we extract opcode which is our shellcode from object file.

; Compilation and extracting shellcode

; nasm -felf64 exitcode.nasm
; ld exitcode.o
; objdump -M -d intel exitcode.o

SECTION .data

SECTION .text 
    global _start
_start:

; exit
    mov rax, 60
    mov rdi, 0
    syscall 

; Bcz it will contain NULL bytes in shellcode see exitcode02.nasm for code
; that donot give us NULL bytes after objdump.