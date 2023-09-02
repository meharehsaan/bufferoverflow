; Compilation and extracting shellcode

; nasm -felf64 exitcode.nasm
; ld exitcode.o
; objdump -M -d intel exitcode.o

SECTION .data

SECTION .text 
    global _start
_start:

; exit
    ;mov rax, 60

    xor rax, rax
    mov al, 60

    ;mov rdi, 0

    xor rdi, rdi
    syscall 

; Now we wouldn't get NULL bytes after from opcode.
