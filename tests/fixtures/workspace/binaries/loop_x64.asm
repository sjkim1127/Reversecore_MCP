; Simple x86-64 assembly: loop with syscall
bits 64
org 0x400000

_start:
    mov rax, 60        ; sys_exit
    mov rdi, 0         ; exit code 0
    syscall
