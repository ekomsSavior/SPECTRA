/* Church of Malware, MIT. Benign static analysis fixture. */
.intel_syntax noprefix
.text
.global entry, read_count, dispatch
.type entry,@function
entry:
 lea rdi,[rip+record]
 call read_count
 ret
.size entry,.-entry
.type read_count,@function
read_count:
 mov eax,[rdi+4]
 ret
.size read_count,.-read_count
.type dispatch,@function
dispatch:
 cmp rdi,2
 ja default_case
 lea rdx,[rip+cases]
 movsxd rax,dword ptr [rdx+rdi*4]
 add rax,rdx
 jmp rax
case_zero: mov eax,11
 ret
case_one: mov eax,22
 ret
case_two: mov eax,33
 ret
default_case: mov eax,-1
 ret
.size dispatch,.-dispatch
.section .rodata
.align 4
cases: .long case_zero-cases,case_one-cases,case_two-cases
.align 8
record: .long 7,123
 .quad 0x1122334455667788
.section .note.GNU-stack,"",@progbits
