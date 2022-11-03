; <main.asm>    -   Import Obfuscation Demonstration                            ;       
;                           November 2022                               
;                                                                       
; The method of dynamic import resolution in Windows malware is well known.  
; Perhaps something that less people are aware of is the capabilities of 
; memory analysis tools to recover dynamic import tables. After all, they are
; not so different from normal IATs.
;
; For example, Hasherezade's pe-sieve can easily recover dynamic
; IATs:
; ---
; # pe-sieve64.exe /imp 1 /pid xxx
; 57038,7ffffd65f0b0,kernel32.GetModuleHandleA #639
; 57040,7ffffd65aec0,kernel32.GetProcAddress #697
; 57048,7ffffd6604f0,kernel32.LoadLibraryA #969
; 57050,7ffffd6a0ef0,kernel32.CopyFileA #172
; 57058,7ffffd65fee0,kernel32.LoadLibraryW #972
; ---
; 
; This begs the question, how can we avoid this? An obvious answer is to
; encode pointers. This program demonstrates how to achieve this in
; assembly. At the bottom, I've also included example code to achieve
; the same results in C++. Enjoy!
;----------------------------------------------------------------- @davovich --
option win64:0x08, casemap:none

include win.inc

hash_offset  equ 0xcbf29ce484222325  
hash_prime   equ 0x100000001b3   ; homework - how might you improve this? :)
hash_ntdll   equ 0xA86B1A076C2A987B

; --- structures 
dapi_entry struct
    address qword ?    
    hash    qword ?    
dapi_entry ends

dapi struct
    entries qword ?
    len     dword ?
dapi ends

; --- data 
data segment align(0x10) 'data' read write
    mov     r8, gs:[0x60]
data ends

; --- code 
text segment align(0x10) 'code' read execute
start proc
    mov     rcx, hash_ntdll
    call    getmod
    ret
start endp

getmod proc fastcall hash:qword
    local   modname[256*2]:byte
    local   first:qword
    local   curr:qword
    push    rbx                         
    push    rdi                         
    push    rsi
    mov     rdi, rcx            
    mov     rsi, [gs:0x60]
    mov     rsi, [rsi].peb.ldr          ; rsi points to PEB_LDR_DATA entry 
    mov     rsi, [rsi].pld.moml.fw-10h  ; rsi now points to LDR_MODULE link
    mov     first, rsi                  ;
    mov     rbx, [rsi].ldte.moml.fw-10h ; each each LDR_MODULE links to others
    mov     curr, rbx
_loop:
    lea     rcx, modname
    xor     edx, edx
    mov     r8d, 256
    call    memset
    lea     rcx, modname
    lea     rdx, [rbx].ldte.basename.buffer
    call    wstrcpy
    lea     rcx, modname
    call    wstrtolower                 ; returns the length as well (in bytes, not words)
    lea     rcx, modname
    mov     rdx, rax
    call    gethash
    cmp     rax, rdi
    je      _match
    mov     rbx, curr
    cmp     rbx, first
    je      _done
    jmp     _loop
_match:
    mov     rax, [rbx].ldte.dllbase
_done:
    pop     rsi
    pop     rdi
    pop     rbx
    retn
getmod endp

gethash proc fastcall src:qword, len:dword
    push    rbx
    push    rsi
    push    rdi
    xor     rbx, rbx
    mov     rsi, rcx                        ; rsi is the source buffer
    xor     ecx, ecx                        ; ecx is the counter
    mov     rax, hash_offset                 ; rax is the hash
_loop:
    cmp     ecx, edx
    ja      _done
    mov     bl, [rsi+rcx]
    xor     rax, rbx
    mov     rdi, hash_prime
    imul    rax, rdi
    inc     ecx
    jmp     _loop
_done:
    pop     rdi
    pop     rsi
    pop     rbx
    retn
gethash endp

memset proc fastcall dst:qword, val:byte, len:dword
    push    rbx
    xor     eax, eax
_loop:
    cmp     r8d, eax
    jge     _done
    mov     [rcx+rax], dl
    inc     eax
    jmp     _loop
_done:
    pop     rbx
    retn
memset endp

wstrcpy proc fastcall dst:qword, src:qword
    push    rbx
    xor     eax, eax
_loop:
    mov     bx, [rdx+rax*2]
    test    bx, bx
    jz      _done
    mov     [rcx+rax*2], bx
    inc     eax
    jmp     _loop
_done:
    pop     rbx
    retn
wstrcpy endp

wstrtolower proc fastcall src:qword
    push    rbx
    xor     eax, eax
_loop:
    mov     bx, [rcx+rax*2]
    test    bx, bx
    jz      _done
    cmp     bx, 'A'
    jl      _next
    cmp     bx, 'Z'
    jg      _next
    add     bx, 0x20
    mov     [rcx+rax*2], bx
_next:
    add     eax, 2
    jmp     _loop
_done:
    imul    eax, 2
    inc     eax
    pop     rbx
    retn
wstrtolower endp

wcslen proc fastcall src:qword
    push    rbx
    xor     eax, eax
_loop:
    mov     bx, [rcx+rax*2]
    test    bx, bx
    jz      _done
    inc     eax
    jmp     _loop
_done:
    pop     rbx
    retn
wcslen endp

text ends
end
; C++ Version------------------------------------------------------------------