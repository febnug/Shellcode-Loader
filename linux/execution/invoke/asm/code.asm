; Shellcode Loader
; Archive of Reversing.ID
; 
;
; Compile:
;   $ nasm -f elf64 code.asm -o code.o
;   $ ld code.o -o code
; Run:
;   $ ./code

%define SYS_MMAP      9
%define SYS_MPROTECT 10
%define SYS_MUNMAP   11
%define SYS_EXIT     60

%define PROT_READ     1
%define PROT_WRITE    2
%define PROT_EXEC     4
%define MAP_PRIVATE   2
%define MAP_ANONYMOUS 32

section .data
    payload     db 0x90, 0x90, 0xCC, 0xC3
    payload_len equ $ - payload

section .text
    global _start

_start:

    ; mmap(NULL, payload_len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    xor     rdi, rdi                    ; addr = NULL
    mov     rsi, payload_len            ; length
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8,  -1                     ; fd
    xor     r9,  r9                     ; offset
    mov     rax, SYS_MMAP
    syscall
    mov     r12, rax                    ; save address to r12

    ; memcpy(runtime, payload, payload_len)
    mov     rdi, r12                    ; dest = mmap'd addr
    lea     rsi, [rel payload]          ; src
    mov     rcx, payload_len
.copy_loop:
    mov     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    loop    .copy_loop

    ; mprotect(runtime, payload_len, PROT_READ | PROT_EXEC)
    mov     rdi, r12
    mov     rsi, payload_len
    mov     rdx, PROT_READ | PROT_EXEC
    mov     rax, SYS_MPROTECT
    syscall

    ; call the shellcode
    call    r12

    ; munmap(runtime, payload_len)
    mov     rdi, r12
    mov     rsi, payload_len
    mov     rax, SYS_MUNMAP
    syscall

    ; exit(0)
    xor     rdi, rdi
    mov     rax, SYS_EXIT
    syscall
