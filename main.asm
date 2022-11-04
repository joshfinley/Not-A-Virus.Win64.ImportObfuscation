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
; encode pointers. We can store our dynamic imports table in an encoded
; format and wrap our calls with a function to decode and call the real
; pointer.
;
; Another issue is the existence of hash databases. At this point, you can
; bet on most of your generic hashes for Windows APIs are in these databases.
; We can avoid this by encoding our hashes at rest, but this introduces
; some undesirable indicators into our binary. With a bit of work we can
; avoid storing our entire encoded hashes in our code and instead compute
; them at runtime. We can also get the added bonus of adding quite a few
; cycles to our execution at the same time, which might help avoid automated
; dynamic analysis.
;
; This program demonstrates how to achieve this in
; assembly. At the bottom, I've also included example code to achieve
; some similar results in C++. Enjoy!
;----------------------------------------------------------------- @davovich --
option win64:0x08, casemap:none
include win.inc
; 
; Our defined hashes / hashing values. We mask embedded hashes, offsets, and
; primes with our own value to avoid detections on these values.
; 
hash_mask    equ 0x29A29A29A29A29A2
hash_offset  equ 0xcbf29ce484222325 xor hash_mask
hash_prime   equ 0x00000100000001b3 xor hash_mask
hash_ntdll   equ 0x5703856CC8FC1C79
hash_ntavm   equ 0x6640A8978F501F9A

; --- structures                    
dapi_entry struct                           ; dynamic import table entry
    address qword ?                         ; our encoded function pointer           
    hash    qword ?                         ; our encoded hash
dapi_entry ends                             ;

dapi struct                                 ; our dynamic import table
    entries qword ?                         ; pointer to entries
    len     dword ?                         ; number of entries
dapi ends                                   ;

; --- code 
text segment align(0x10) 'code' read execute
start proc
    mov     rcx, hash_ntdll
    call    getmod
    mov     rcx, rax
    mov     rdx, hash_ntavm
    call    getexp
    ret
start endp

getexp proc fastcall base:qword, hash:qword
    local   nth:qword                       ; nt headers
    local   dir:qword                       ; data directory 
    local   exp:qword                       ; export directory
    local   aof:qword                       ; address of function
    local   aon:qword                       ; address of name
    local   aoo:qword                       ; address of name ordinal
    push    rbx
    push    rsi
    push    rdi
    push    r10
    xor     eax, eax                        ; eax is offset holder
    mov     rsi, rcx                        ; rsi is the module base
    mov     r10, rsi                        ; r10 is a backup of the module base
    mov     rdi, rdx                        ; rdi is the target hash
    mov     eax, [rsi].dos_hdr.e_lfanew     ; eax is the dword at rsi offset by 0x3C
    add     rsi, rax                        ; rsi is the nt header
    lea     rsi, [rsi].nt_hdr.opt.d_dir     ; rsi is the offset of the optional header data dir.
    mov     dir, rsi                
    mov     ebx, [rsi].img_data_dir.va
    add     rbx, r10                        ; rbx is the VA of the export directory
    mov     exp, rbx
    mov     eax, [rbx].exp_dir.aon
    add     rax, r10
    mov     aon, rax
    mov     eax, [rbx].exp_dir.aof
    add     rax, r10
    mov     aof, rax
    mov     eax, [rbx].exp_dir.aoo
    mov     rbx, [exp]
    xor     esi, esi                        ; esi is the counter
_loop:
    cmp     esi, [rbx].exp_dir.n_names
    jge     _done
    mov     rcx, [aon]
    mov     ecx, [rcx+rsi*4]
    add     rcx, r10
    mov     rbx, rcx
    call    strlen
    mov     rcx, rbx
    mov     edx, eax
    call    gethash
    inc     esi
    cmp     rax, rdi
    je      _match
    jmp     _loop
_match:
    xor     eax, eax
    mov     rcx, aoo
    movzx   eax, word ptr [rcx+rsi*2]
    mov     rcx, aof
    mov     eax, [rcx+rsi*4]
    add     rax, r10
    jmp     _done
_done:
    pop     r10
    pop     rdi
    pop     rsi
    pop     rbx
    retn
getexp endp

getmod proc fastcall hash:qword
    local   modname[256*2]:byte
    local   first:qword
    local   curr:qword
    push    rbx        
    push    rsi                 
    push    rdi                         
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
    imul    rdx, 2
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
    pop     rdi
    pop     rsi
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
    mov     rax, hash_offset                ; rax is the encoded hash (basis)
    mov     r8, hash_mask                   ; decode the basis
    xor     rax, r8                         ; ...
_loop:
    cmp     ecx, edx
    je      _done
    mov     bl, [rsi+rcx]
    xor     rax, rbx                        ; hash = hash ^ src[i]
    mov     rdi, hash_prime                 ; rdi is the prime (encoded)
    xor     rdi, r8                         ; decode the prime
    imul    rax, rdi                        ; hash = hash * prime
    inc     ecx
    jmp     _loop
_done:
    xor     rax, r8                         ; mask the hash
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

strlen proc fastcall src:qword
    push    rbx
    xor     eax, eax
_loop:
    mov     bl, [rcx+rax]
    test    bl, bl
    jz      _done
    inc     eax
    jmp     _loop
_done:
    pop     rbx
    retn
strlen endp

; wcslen proc fastcall src:qword
;     push    rbx
;     xor     eax, eax
; _loop:
;     mov     bx, [rcx+rax*2]
;     test    bx, bx
;     jz      _done
;     inc     eax
;     jmp     _loop
; _done:
;     pop     rbx
;     retn
; wcslen endp

text ends
end
; C++ Version------------------------------------------------------------------