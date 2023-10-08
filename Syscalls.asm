section .text

global Search_For_Syscall_Ret
global NtAllocateVirtualMemory_Callback
global NtCreateThreadEx_Callback
global NtWriteVirtualMemory_Callback

NtAllocateVirtualMemory_Callback:
    mov r10, rcx
    mov r15, [rsp + 38h]
    mov rax, 18h
    jmp r15

NtWriteVirtualMemory_Callback:
    mov r10, rcx
    mov r15, [rsp + 30h]
    mov rax, 3Ah
    jmp r15

NtCreateThreadEx_Callback:
    mov r10, rcx
    mov r15, [rsp + 60h]
    mov rax, 0C2h
    jmp r15

; Search for combination Syscall + Ret
Search_For_Syscall_Ret:
    add rax, 1
    xor rbx, rbx
    xor rcx, rcx
    mov rcx, 00FFFFFF0000000000h
    mov rdi, [rax]
    and rdi, rcx
    or rbx, rdi
    shr rbx, 28h
    cmp rbx, 1F0FC3h
    jne Search_For_Syscall_Ret
    ret