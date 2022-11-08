; <main.asm>    -   Import Obfuscation Demonstration                            ;
;                           November 2022                                       ;
;                                                                               ;
; The method of dynamic import resolution in Windows malware is well known.     ;
; Perhaps something less well known, or at least less bothered with are         ;
; the features of memory analysis tools to recover dynamic IATs. After all,     ;
; they look very similar in memory to ordinary IATs.                            ;
;                                                                               ;
; For example, Hasherezade's pe-sieve can easily recover dynamic                ;
; IATs:                                                                         ;
; ---                                                                           ;
; # pe-sieve64.exe /imp 1 /pid xxx                                              ;
; 57038,7ffffd65f0b0,kernel32.GetModuleHandleA #639                             ;
; 57040,7ffffd65aec0,kernel32.GetProcAddress #697                               ;
; 57048,7ffffd6604f0,kernel32.LoadLibraryA #969                                 ;
; 57050,7ffffd6a0ef0,kernel32.CopyFileA #172                                    ;
; 57058,7ffffd65fee0,kernel32.LoadLibraryW #972                                 ;
; ---                                                                           ;
;                                                                               ;
; Evading this is trivial in most cases - all that is necessary is to           ;
; encode pointers at rest. Suddenly, automated tools like pe-sieve don't        ;
; work so well.                                                                 ;
;                                                                               ;
; Another issue is the presence of most ordinary API hashes in online           ;
; databases. We can avoid this by encoding our hashes at rest. Note that this   ;
; will increase the overall entropy of the respective code blocks. We can       ;
; get this entropy down by building up the hash over multiple instructions.     ;
;                                                                               ;
; The developers of Blackmatter have taken this a step further and will         ;
; perform the encoding dynamically based on a runtime derived random value.     ;
; The code snippets for encoding/decoding the hashes are generated dynamically  ;
; at runtime.                                                                   ;
;                                                                               ;
; We can be even more tricky and perform the allocations for code generation    ;
; using ROP techniques. The syscall opcode (0F 05) is not uncommon in kernel32, ;
; which is implicitly loaded into every usermode process.                       ;
;                                                                               ;
; The combination of all these traits gives us a program which masks its        ;
; imports effectively from memory scanners, doing so by masking the pointers    ;
; and hashes it uses at runtime using polymorphic encoding stubs. Of course,    ;
; all of these things are possible in C/C++, but I find the process of          ;
; demonstrating code like this in assembly much more gratifying. With that      ;
; being said, the rest of this file contains such a demonstration in the        ;
; MASM syntax, which can be assembled with UASM.                                ;
;                                                                               ;
;       ~ Enjoy!                                                                ;
;                                                                               ;
; -------------------------------------------------------------- yesh --------- ;
option win64:0x08, casemap:none                                                 ;
include win.inc                                                                 ;
; ----------------------------------------------------------------------------- ;
;                              Obfuscation Macros                               ;
; ----------------------------------------------------------------------------- ;
; x86 registers                                                                 ;
_eax            equ 0                                                           ;
_ecx            equ 1                                                           ;
_edx            equ 2                                                           ;
_ebx            equ 3                                                           ;
_esp            equ 4                                                           ;
_ebp            equ 5                                                           ;
_esi            equ 6                                                           ;
_edi            equ 7                                                           ;
                                                                                ;
; x64 extended registers                                                        ;
_r8             equ 0                                                           ;
_r9             equ 1                                                           ;
_r10            equ 2                                                           ;
_r11            equ 3                                                           ;
_r12            equ 4                                                           ;
_r13            equ 5                                                           ;
_r14            equ 6                                                           ;
_r15            equ 7                                                           ;
                                                                                ;
; MODRM                                                                         ;
S_mod_ri        equ 00000000b               ; 0x00 MODRM register indirect      ;
s_mod_ra        equ 11000000b               ; 0xC0 MODRM register addressing    ;
s_mod_1sbdsp    equ 01000000b               ; 0x40 MODRM one byte signed disp   ;
s_mod_4sbdsp    equ 10000000b               ; 0x80 MODRM four byte signed disp  ;
                                                                                ;
; Prefixes                                                                      ;
s_pfx_o16       equ 01100110b               ; 0x66 16/32 bit operand override   ;
s_pfx_a16       equ 01100111b               ; 0x67 16/32 bit address override   ;
s_pfx_o8        equ 10001000b               ; 0x88 8 bit operand override       ;
s_rex           equ 01000000b               ; 0x40 REX (access new 8 bit regы)  ;
s_rex_8         equ 01000001b               ; 0x41 REX reg imm mode             ;
s_pfx_rexw      equ 01001000b               ; 0x48 REX.W (64 bit operand)       ;
s_pfx_rexwb     equ 01001001b               ; 0x49 REX.WB                       ;
                                                                                ;
; Opcodes                                                                       ;
s_op_pushr      equ 0x50                    ; push rax. OR with reg encodings.  ;
s_op_popr       equ 0x58                    ; pop rax. OR with reg encodings    ;
                                                                                ;
; Conditional Jumps                                                             ;
s_jb_rel8       equ 0x72                    ; jb/jnae/jc                        ;
s_jae_rel8      equ 0x73                    ; jnb/jae/jnc                       ;
s_je_rel8       equ 0x74                    ; jz/ne                             ;
s_jne_rel8      equ 0x75                    ; jnz/jne                           ;
s_jna_rel8      equ 0x76                    ; jbe/jna                           ;
s_ja_rel8       equ 0x77                    ; jnbe/ja                           ;
s_jnge_rel8     equ 0x7c                    ; jl/jnge                           ;
s_jd_rel8       equ 0x7d                    ; jnl/jge                           ;
s_jle_rel8      equ 0x7e                    ; jle/jng                           ;
s_jf_rel8       equ 0x7f                    ; jnle/jg                           ;
                                                                                ;
; Relative Jumps                                                                ;
s_jmp_rel8      equ 0xeb                    ; jmp rel8                          ;
                                                                                ;
; Basic Register Operations                                                     ;
s_add_rall      equ 0x03                    ; add r/16/32/64                    ;
s_or_rall       equ 0x0b                    ; or  r/16/32/64                    ;
s_and_rall      equ 0x23                    ; and r/16/32/64                    ;
s_sub_rall      equ 0x2b                    ; sub r/16/32/64                    ;
s_xor_rall      equ 0x33                    ; xor r/16/32/64                    ;
s_cmp_rall      equ 0x3b                    ; cmp r/16/32/64                    ;
s_mov_rall      equ 0x8b                    ; mov r/16/32/64                    ;
s_mov_r8_imm8   equ 0xb0                    ; mov r8 imm8                       ;
s_mov_r8        equ 0x8a                    ; mov r8 r/m8                       ;
s_mov_r8_imm    equ 0xb8                    ; mov r8 imm8                       ;
s_mov_r64_imm64 equ 0xC7                    ; mov r64 imm64                     ;
s_shl           equ 0xe0c1                  ; shl                               ;
                                                                                ;
; Get an assembly-time random value of a specific size. Maximum 32 bits.        ;
; This value will change on successive expansions                               ;
rnd macro __mask                                                                ;
    local m                                                                     ;
    m=(@SubStr(%@Time,7,2)+@Line)*(@SubStr(%@Date,1,2)                          ;
    m=m+@SubStr(%@Date,4,2)*100+@SubStr(%@Date,7,2))* (-1001)                   ;
    m=(m+@SubStr(%@Time,1,2)+@SubStr(%@Time,4,2))*(@SubStr(%@Time,7,2)+1)       ;
    ifnb <__mask>                                                               ;
        m = m and __mask                                                        ;
    endif                                                                       ;
    exitm % m                                                                   ;
endm                                                                            ;
                                                                                ;
; Emit some junk bytes that look vaguely like real code                         ;
emit_junk macro                                                                 ;
    local v1, v2, r0, r1, r2, r3, r4, b                                         ;
    count = 0                                                                   ;
    ...                                                                         ;
endm                                                                            ;
                                                                                ;
; Emit a junk operation of the given type (example/incomplete)                  ;
emit_junk_op macro v1, opc, r1, r2                                              ;
    if v1 eq 0                                                                  ;
        db s_pfx_rexw                                                           ;
        db opc                                                                  ;
        b = r2                                                                  ;
        b = (b shl 3) or (r1)                                                   ;
        db b                                                                    ;
    elseif v1 eq 1                                                              ;
        db opc                                                                  ;
        b = r1                                                                  ;
        b = (b shl 3) or (r2)                                                   ;
        db b                                                                    ;
    elseif v1 eq 2                                                              ;
        db opc                                                                  ;
        b = r2                                                                  ;
        b = (b shl 3) or (r1)                                                   ;
        db b                                                                    ;
    endif                                                                       ;
endm                                                                            ;
                                                                                ;
; Emit a junk conditional comparison                                            ;
emit_junk_jcnd macro v, dist                                                    ;
    if v eq 0                                                                   ;
        db s_ja_rel8                                                            ;
        db dist                                                                 ;
    elseif v eq 1                                                               ;
        db s_jle_rel8                                                           ;
        db dist                                                                 ;
    elseif v eq 2                                                               ;
        db s_jne_rel8                                                           ;
        db dist                                                                 ;
    endif                                                                       ;
endm                                                                            ;
                                                                                ;
; Emit the bytes of a string                                                    ;
emit_bytes macro string                                                         ;
    for value, <string>                                                         ;
        db value                                                                ;
    endm                                                                        ;
endm                                                                            ;
                                                                                ;
; Emit a relative 8 jump                                                        ;
emit_jmp_rel8 macro dist                                                        ;
    db s_jmp_rel8                                                               ;
    db dist                                                                     ;
endm                                                                            ;
; ----------------------------------------------------------------------------- ;
;                           Dynamic Import Macros                               ;
; ----------------------------------------------------------------------------- ;
;                                                                               ;
; Our defined hashes / hashing values. We mask embedded hashes, offsets, and    ;
; primes with our own value to avoid detections on these values.                ;
;                                                                               ;
; We use the `static_rnd` compile time macro, credit to mabdelouahab@masm32.com ;
;                                                                               ;
; Get an assembly-time random byte. This value will stay the same on successive ;
; expansions                                                                    ;
static_rnd macro __mask                                                         ;
    local m                                                                     ;
    m=(@SubStr(%@Time,7,2)) xor (@SubStr(%@Date,7,2))                           ;
    m=(m+@SubStr(%@Time,1,2)+@SubStr(%@Time,4,2))*(@SubStr(%@Time,7,2)+1)       ;
    ifnb <__mask>                                                               ;
        m = m and __mask                                                        ;
    endif                                                                       ;
    exitm % m                                                                   ;
endm                                                                            ;
                                                                                ;
random_mask     equ static_rnd(0xffffffff)                                      ;
hash_basis      equ            0xC59D1C81  xor random_mask                      ;
hash_prime      equ            0x01000193  xor random_mask                      ;
                                                                                ;
;                                                                               ;
; Our function hashes will all be double words of high entropy but at least     ;
; they won't be a dead giveaway in a hash database                              ;
;                                                                               ;
hash_ntdll      equ            0x25959F7F xor random_mask                       ;
hash_ntavm      equ            0x6973F2B4 xor random_mask                       ;
                                                                                ;
; Data Structures ------------------------- ;                                   ;
dynimp_entry struct                         ; dynamic import table entry        ;
    address qword ?                         ; our encoded function pointer      ;
dynimp_entry ends                           ;                                   ;
                                            ;                                   ;
dynimp struct                               ; our dynamic import table          ;
    entries qword ?                         ; pointer to entries                ;
    len     dword ?                         ; number of entries                 ;
dynimp ends                                 ;                                   ;
; ----------------------------------------- ;                                   ;
;                                                                               ;
; ----------------------------------------------------------------------------- ;
;                               Executable Code                                 ;
; ----------------------------------------------------------------------------- ;
text segment align(10h) 'code' read execute ;                                   ;
;                                           ;                                   ;
; Program entry point                       ;                                   ;
start proc                                  ;                                   ;
    local   d_ents[10]:dynimp_entry         ; encoded address on the stack      ;
    local   d_table:dynimp                  ; dynamic api table                 ;
    push    rbx
    mov     rcx, hash_ntdll                 ; encoded hash of `ntdll.dll`       ;
    call    getmod                          ; get module base of ntdll.dll      ;
    mov     rcx, rax                        ; rcx is the module base            ;
    mov     rbx, rax
    mov     rdx, hash_ntavm                 ; rdx encoded function hash         ;
    call    getexp                          ; resolve address by hash           ;
    mov     edx, [d_table.len]              ; store the result in the table     ;
    inc     [d_table.len]                   ;                                   ;
    mov     rcx, rax                        ; rcx is the unencoded address      ;
    mov     rcx, rbx
    mov     rdx, 0x69696969
    call    getexp
    ret                                     ; 
    ;                                       ; 
    ;                                       ; 
start endp                                  ;                                   ;
;                                           ;                                   ;
; Address masking operations                ;                                   ;
mask_ptr proc fastcall value:qword          ;                                   ;
    push    rbx                             ;                                   ;
    mov     ebx, random_mask                ; rbx is the mask                   ;
    mov     rax, rcx                        ; rax is the address                ;
    xor     ecx, ecx                        ; rcx is the counter                ;
_loop:                                      ;                                   ;
    cmp     ecx, 8                          ; eight is sufficient               ;
    je      _done                           ;                                   ;
    xor     rax, rbx                        ;                                   ;
    inc     ecx                             ;                                   ;
    shl     rbx, cl                         ; shift the mask over by the rcx    ;
    jmp     _loop                           ; next operation                    ;
_done:                                      ;                                   ;
    pop     rbx                             ;                                   ;
    ret                                     ; return the enc/dec address        ;
mask_ptr endp                               ;                                   ;
; ----------------------------------------- ;                                   ;
; Resolve a DLL export by hash              ;                                   ;
getexp proc fastcall base:qword, hash:qword ;                                   ;
    push    rbx
    push    rsi
    push    rdi
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    xor     eax, eax                        ; eax is offset holder              ;
    mov     rsi, rcx                        ; rsi is the module base            ;
    mov     r10, rsi                        ; r10 is a backup of the mod base   ;
    mov     rdi, rdx                        ; rdi is the target hash            ;
    mov     eax, [rsi].dos_hdr.e_lfanew     ; eax is nth offset                 ;
    add     rsi, rax                        ; rsi is the nt header va           ;
    lea     rsi, [rsi].nt_hdr.opt.d_dir     ; rsi is the rva of the data dir    ;
    mov     ebx, [rsi].img_data_dir.va      ; rbx is the va of the export dir   ;
    add     rbx, r10                        ; rbx is the va of export dir       ;
    mov     eax, [rbx].exp_dir.aon          ; resolve AddressOfNames            ;
    add     rax, r10                        ;                                   ;
    mov     r12, rax                        ;                                   ;
    mov     eax, [rbx].exp_dir.aof          ; resolve AddressOfFunctions        ;
    add     rax, r10                        ;                                   ;
    mov     r13, rax                        ;                                   ;
    mov     eax, [rbx].exp_dir.aoo          ; resolve ordinals                  ;
    add     rax, rsi
    mov     r14, rax
    xor     esi, esi                        ; esi is the counter                ;
_loop:                                      ; iterate over the exports          ;
    cmp     esi, [rbx].exp_dir.n_names      ;                                   ;
    jge     _done                           ;                                   ;
    mov     rcx, r12                        ; aon                               ;
    mov     ecx, [rcx+rsi*4]                ; next offset                       ;
    add     rcx, r10                        ; next va                           ;
    mov     rbx, rcx                        ; rcd is va of string               ;
    call    strlen                          ; calculate its length              ;
    mov     rcx, rbx                        ;                                   ;
    mov     edx, eax                        ;                                   ;
    call    gethash                         ; calculate its hash                ;
    inc     esi                             ; next ordinal                      ;
    cmp     rax, rdi                        ; hashes match?                     ;
    je      _match                          ; resolve the function address      ;
    jmp     _loop                           ; next function                     ;
_match:                                     ;                                   ;
    xor     eax, eax                        ; resolve the function address      ;
    mov     rcx, r14                        ; get current ordinal               ;
    movzx   eax, word ptr [rcx+rsi*2]       ;                                   ;
    mov     rcx, r13                        ;                                   ;
    mov     eax, [rcx+rsi*4]                ; get current function rva          ;
    add     rax, r10                        ; get current function va           ;
    jmp     _done                           ; all done here                     ;
_done:                                      ;                                   ;
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     rdi
    pop     rsi
    pop     rbx
    retn                                    ;                                   ;
getexp endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
; Resolve a module base address by hash     ;                                   ;
getmod proc fastcall hash:qword             ;                                   ;
    local   modname[256*2]:byte             ; stack space for module name buf   ;
    local   first:qword                     ; first module entry                ;
    local   curr:qword                      ; current module entry              ;
    local   brbx:qword
    local   brsi:qword
    local   brdi:qword
    mov     brbx, rbx
    mov     brsi, rsi
    mov     brdi, rdi
    mov     rdi, rcx                        ;                                   ;
    mov     rsi, [gs:0x60]                  ; get PEB                           ;
    mov     rsi, [rsi].peb.ldr              ; rsi -> PEB_LDR_DATA entry         ;
    mov     rsi, [rsi].pld.moml.fw-10h      ; rsi points to LDR_MODULE link     ;
    mov     first, rsi                      ;                                   ;
    mov     rbx, [rsi].ldte.moml.fw-10h     ; each LDR_MODULE links to others   ;
    mov     curr, rbx                       ; save current module               ;
_loop:                                      ; loop over modules                 ;
    lea     rcx, modname                    ;                                   ;
    xor     edx, edx                        ;                                   ;
    mov     r8d, 256                        ;                                   ;
    call    memset                          ; clear the name buffer             ;
    lea     rcx, modname                    ;                                   ;
    lea     rdx, [rbx].ldte.basename.buffer ;                                   ;
    call    wstrcpy                         ; copy the UNICODE_STRING buffer    ;
    lea     rcx, modname                    ; convert it to lowercase           ;
    call    wstrtolower                     ; returns the length as well        ;
    lea     rcx, modname                    ;  (in bytes)                       ;
    mov     rdx, rax                        ;                                   ;
    imul    rdx, 2                          ; since unicode_strings are wide    ;
    call    gethash                         ; get module name hash              ;
    cmp     rax, rdi                        ; match target?                     ;
    je      _match                          ;                                   ;
    mov     rbx, curr                       ; while current != first            ;
    cmp     rbx, first                      ;                                   ;
    je      _done                           ;                                   ;
    jmp     _loop                           ;                                   ;
_match:                                     ;                                   ;
    mov     rax, [rbx].ldte.dllbase         ; get dll base address              ;
_done:                                      ;                                   ;
    mov     rdi, brdi
    mov     rsi, brsi
    mov     rbx, brbx
    retn                                    ;                                   ;
getmod endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
; Get a FNV32 hash of a buffer              ;                                   ;
gethash proc fastcall src:qword, len:dword  ;                                   ;
    push    rbx                             ;                                   ;
    push    rsi                             ;                                   ;
    push    rdi                             ;                                   ;
    xor     rbx, rbx                        ;                                   ;
    mov     rsi, rcx                        ; rsi is the source buffer          ;
    xor     ecx, ecx                        ; ecx is the counter                ;
    mov     eax, hash_basis                 ; eax is the hash basis             ;
    xor     eax, random_mask                ; decode the basis                  ;
_loop:                                      ; loop over src bytes               ;
    cmp     ecx, edx                        ;                                   ;
    je      _done                           ;                                   ;
    xor     ebx, ebx                        ;                                   ;
    mov     bl, [rsi+rcx]                   ; bl is the current byte            ;
    xor     eax, ebx                        ; hash = hash ^ src[i]              ;
    mov     edi, hash_prime                 ;                                   ;
    xor     edi, random_mask                ; decode the prime                  ;
    imul    eax, edi                        ; hash = hash * prime               ;
    inc     ecx                             ; next byte                         ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    xor     eax, random_mask                ; mask the hash                     ;
    pop     rdi                             ;                                   ;
    pop     rsi                             ;                                   ;
    pop     rbx                             ;                                   ;
    retn                                    ;                                   ;
gethash endp                                ;                                   ;
; ----------------------------------------- ;
; Find matching bytes in memory
find_bytes proc fastcall src:qword, buf:qword, len:dword 
    push    rbx
    push    rsi
    push    rdi
    push    r10
    mov     rsi, rcx
    mov     rdi, rdx
    mov     rbx, r8
    xor     r10, r10
_loop:
    xor     eax, eax
    cmp     r10, rbx
    je      _done
    mov     rcx, rsi
    mov     rdx, rdi
    inc     r10
    inc     rsi
    mov     r8, rbx
    call    memcmp
    test    eax, eax
    jz      _loop
_match:
    dec     rsi
    mov     rax, rsi
_done:
    pop     r10
    pop     rdi
    pop     rsi
    pop     rbx
    ret
find_bytes endp

; ----------------------------------------- ;
; Generic memcpy
memcmp proc fastcall src:qword, dst:qword, len:dword
    push    rbx
    xor     r9, r9
_loop:
    cmp     r9, r8
    je      _done
    xor     eax, eax
    mov     bl, [rcx+r9]
    cmp     [rdx+r9], bl
    jne     _done
_match:
    mov     eax, 1
    inc     r9
    jmp     _loop
_done:
    pop     rbx
    ret
memcmp endp

; ----------------------------------------- ;                                   ;
; Generic memset                            ;                                   ;
memset proc fastcall dst:qword, val:byte, len:dword                             ;
    push    rbx                             ;                                   ;
    xor     eax, eax                        ;                                   ;
_loop:                                      ;                                   ;
    cmp     r8d, eax                        ;                                   ;
    jge     _done                           ;                                   ;
    mov     [rcx+rax], dl                   ;                                   ;
    inc     eax                             ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    pop     rbx                             ;                                   ;
    retn                                    ;                                   ;
memset endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
; Copy a wide string                        ;                                   ;
wstrcpy proc fastcall dst:qword, src:qword  ;                                   ;
    push    rbx                             ;                                   ;
    xor     eax, eax                        ;                                   ;
_loop:                                      ;                                   ;
    mov     bx, [rdx+rax*2]                 ;                                   ;
    test    bx, bx                          ;                                   ;
    jz      _done                           ;                                   ;
    mov     [rcx+rax*2], bx                 ;                                   ;
    inc     eax                             ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    pop     rbx                             ;                                   ;
    retn                                    ;                                   ;
wstrcpy endp                                ;                                   ;
; ----------------------------------------- ;                                   ;
; Convert a wide string to lowercase        ;                                   ;
wstrtolower proc fastcall src:qword         ;                                   ;
    push    rbx                             ;                                   ;
    xor     eax, eax                        ;                                   ;
_loop:                                      ;                                   ;
    mov     bx, [rcx+rax*2]                 ;                                   ;
    test    bx, bx                          ;                                   ;
    jz      _done                           ;                                   ;
    cmp     bx, 'A'                         ;                                   ;
    jl      _next                           ;                                   ;
    cmp     bx, 'Z'                         ;                                   ;
    jg      _next                           ;                                   ;
    add     bx, 0x20                        ;                                   ;
    mov     [rcx+rax*2], bx                 ;                                   ;
_next:                                      ;                                   ;
    add     eax, 2                          ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    imul    eax, 2                          ;                                   ;
    inc     eax                             ;                                   ;
    pop     rbx                             ;                                   ;
    retn                                    ;                                   ;
wstrtolower endp                            ;                                   ;
; ----------------------------------------- ;                                   ;
; Calculate length of a string              ;                                   ;
strlen proc fastcall src:qword              ;                                   ;
    push    rbx                             ;                                   ;
    xor     eax, eax                        ;                                   ;
_loop:                                      ;                                   ;
    mov     bl, [rcx+rax]                   ;                                   ;
    test    bl, bl                          ;                                   ;
    jz      _done                           ;                                   ;
    inc     eax                             ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    pop     rbx                             ;                                   ;
    retn                                    ;                                   ;
strlen endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
text ends                                   ;                                   ;
end                                         ;                                   ;
;                                                                               ;
; ----------------------------------------------------------------------------- ;
;                  C++ - Obfuscated Dynamic Imports (Example)                   ;
; -----------------------------------c----------------------------------------- ;
; #define DYNIMP( x )      decltype( &x ) x
; #define D_TYPE( x )     (decltype( &x ))
; #define D_XOR_KEY       RND_XOR(0xffff)   // constexpr function call
;
; #define D_EXEC( e, ... ) \
;    ( ( decltype(e)((QWORD)(e) ^ D_XOR_KEY) )(__VA_ARGS__) )
;
; typedef struct _DYNIMP_NTDLL
; {
;       DYNIMP(NtAllocateVirtualMemory);
;       ...
; } DYNIMP_NTDLL, * PDYNIMP_NTDLL;
; #define DYNIMP_NTDLL_LEN ( sizeof(DYNIMP_NTDLL) / sizeof(QWORD) )
;
; typedef struct _DYNIMP 
; {
;       union { 
;           DYNIMP_NTDLL  Apis
;           PVOID       Entries[DYNIMP_NTDLL_LEN];
;       } Ntdll;
; } DYNIMP, * PDYNIMP;
;
; VOID ResolveDapi(PDYNIMP Api)
; {
;       constexpr NtdllHash = ...;
;       constexpr FnvNtAllocateVirtualMemory = D_TYPE(NtAllocateVirtualMemory) 
;           (FNV_NTALLOCATEVIRTUALMEMORY ^ D_XOR_KEY);
;       for (... resolve the module and pointers to functions)
;       {
;           Api->Ntdll.Entries[idx] = (PVOID)((QWORD)Ptr ^ D_XOR_KEY);
;       };       
; }
;
; // now, just call the pointers like the normal function
; 
; D_EXEC(Api->Ntdll.Entries[idx], args...);
;
; ------------------------------------------------------------------------------;