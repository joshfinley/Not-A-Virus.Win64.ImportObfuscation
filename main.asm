; TODO: Improve random generation using cli passed macro/definition
; TODO: Add runtime polymorphism constructs (shuffle register table), macros    
; TODO: Generic WINAPI Wrapper with automated prototypes (regular includes?)
; TODO: Macros to obfuscate embedded hashes (dynamically generate)
;
;
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
; The developers of BlackMatter have taken this a step further and will         ;
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
option win64:0x08, casemap:none, frame:auto, stackbase:rsp
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
; credit to mabdelouahab@masm32.com                                             ;
rnd macro __mask                                                                ;
    local m                                                                     ;
    m=(@SubStr(%@Time,7,2)+@Line)*(@SubStr(%@Date,1,2))                     ;
    m=(m+@SubStr(%@Date,4,2)*100+@SubStr(%@Date,7,2))* (-1001)            ;
    m=(m+@SubStr(%@Time,1,2)+@SubStr(%@Time,4,2))*(@SubStr(%@Time,7,2)+1)       ;

    ifnb <__mask>                                                               ;
        m = m and __mask                                                        ;
    endif                                                                       ;
    exitm % m                                                                   ;
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

; Get high bytes of a DWORD
dword_hi macro val
    local p
    p = ((val) and 0xffff0000)
    exitm % p
endm

; Get low bytes of a DWORD
dword_lo macro val
    local p
    p = ((val) and 0x0000ffff)
    exitm % p
endm

; Set a target register to a target hash. Code generated at assemble time based
; on four variants.
sethash macro reg, hash
    local   choice 
    choice  = (rnd(0x03))
    if choice eq 0
        mov     reg, dword_hi(hash)
        or      reg, dword_lo(hash)
        mov     reg, hash
    elseif choice eq 1
        xor     reg, reg
        mov     reg, (dword_hi(hash) shr 8)
        shl     reg, 8
        and     reg, reg
        or      reg, dword_lo(hash)
    elseif choice eq 2
        mov     reg, (hash xor choice)
        xor     reg, choice
    elseif choice eq 3
        mov     reg, hash
    endif
endm

; Clear out volatile registers. Generate one of three variants
; at assemble time. Two variants include opaque predicates.
clobber_regs macro
    local   choice, l1, l2, l3, l4, l5, l6
    choice  = (rnd(0x02))
    if choice eq 0
        mov     ecx, 0
        and     ecx, 0x00
        jz      l2
    l1: 
        byte    rnd(0xff)
        byte    (rnd(0xff) xor 0x10)
    l2: mov     edx, 0
        cmp     ecx, edx
        jne     l1
        xor     r8, r8
        add     r8d, ecx
        mov     r9, rdx
    elseif choice eq 1
        mov     ecx, 0
        mov     edx, ecx
        mov     r9, rcx
        mov     r8, r9
    elseif choice eq 2
        mov     edx, 0
        and     ecx, 0xff
        cmp     ecx, edx
        jnz     l4
    l3: jmp     l5
    l4: and     r8d, edx
        mov     r9, r8
        jmp     l6
    l5: jmp     l4
    l6: cmp     edx, 0
        jnz     l3
        mov     ecx, 0
    endif
endm

; ----------------------------------------------------------------------------- ;
;                           Dynamic Import Macros                               ;
; ----------------------------------------------------------------------------- ;
;                                                                               ;
; Our defined hashes / hashing values. We mask embedded hashes, offsets, and    ;
; primes with our own value to avoid detections on these values.                ;
;                                                                               ;
; Get an assembly-time random byte. This value will stay the same on successive ;
; expansions.                                                                   ;
;                                                                               ;
static_rnd macro __mask                                                         ;
    local m                                                                     ;
    m=(@SubStr(%@Time,7,2))*(@SubStr(%@Date,1,2))                         
    m=(m+@SubStr(%@Date,4,2)*100+@SubStr(%@Date,7,2))* (-1001)                
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
hash_ntdll      equ            0x8B9A6A34 xor random_mask                       ;
hash_ntavm      equ            0x6973F2B4 xor random_mask                       ;
hash_ntpvm      equ            0xB7F40932 xor random_mask                       ;
hash_k32        equ            0xC1C79AF3 xor random_mask   
hash_kbase      equ            0x6458F824 xor random_mask
hash_cfw        equ            0x00000000 xor random_mask   ; CreateFileW
hash_gcd        equ            0x00000000 xor random_mask   ; GetCurrentDirec.
hash_fff        equ            0x00000000 xor random_mask   ; FindFirstFile
hash_fnf        equ            0x00000000 xor random_mask

max_stub_size   equ            0xffff

;
; Data structures
;
dynimp struct                               ; our dynamic import table          ;
    ntavm   qword ?
    ntpvm   qword ?
    cfw     qword ?                         ; CreateFileW
    fff     qword ?
    len     dword ?                         ; number of entries                 ;
dynimp ends                                                                     ;

;
; Function Prototypes
;                                                                             
find_bytes      proto :qword, :qword, :qword, :qword

fn_ntavm typedef proto :qword, :qword, :qword, :qword, :dword, :dword
pntavm   typedef ptr fn_ntavm
;                                                                               ;
; ----------------------------------------------------------------------------- ;
;                               Executable Code                                 ;
; ----------------------------------------------------------------------------- ;
text segment align(16) 'code' read execute 

; ----------------------------------------------------------------------------- ;
;                                Entry Point                                    ;
; ----------------------------------------------------------------------------- ;
;
; The approach here is similar to the BlackMatter ransomware implementation.
; We not only  encode our dynamic imports at rest, and wrap them in code to
; decode them before use, but we generate the decoding routines per function,
; at runtime. To make this possible, we'll need to allocate some memory.
;
; We'll need only NtAllocateVirtualMemory and NtProtectVirtualMemory. To avoid
; hooks, we will check the first four bytes for a known legit signature. If its
; found, we continue and just use the function pointer to invoke the syscall.
; Otherwise, the syscall number will be set in the dynamic import table instead
;
; Our syscall invocation wrapper will take care of figuring out which variant
; to use.
;
; Next, we loop over the dynamic imports, resolve the target functions, and
; generate a reversible encoding/decoding routine for each target using the
; syscalls we resolved earlier. A random key is generated at runtime and
; embedded into each new cipher stub. The pointers in the dynamic import
; table will then be set to the new stub routine. From here, we can just
; call whichever functions we need like normal, and our stubs will handle
; the rest.
;
start proc fastcall
    call    genimps
    ret   
start endp

; Generate a unique cipher stub for the address
genimps proc 
    local   pdimp:qword
    local   buf_size:qword


    local   ntavm:qword
    local   ntpvm:qword
    local   @rbx:qword
    local   @rsi:qword
    local   @rdi:qword
    mov     @rbx, rbx
    mov     @rsi, rsi
    mov     @rdi, rdi
    mov     rdi, rcx
; Get NtAllocate/ProtectVirtualMemory
    sethash rcx, hash_ntdll                 ; encoded hash of `ntdll.dll`       ;
    call    getmod                          ; get module base of ntdll.dll      ;
    mov     rsi, rax                        ; save ntdll base                   ;
    mov     rcx, rax                        ; rcx is the module base            ;
    sethash rdx, hash_ntavm     
    call    getexp                          ; resolve address by hash           ;
    mov     ntavm, rax
    mov     rcx, rsi                        ; reload ntdll base                 ;
    sethash rdx, hash_ntpvm
    call    getexp                          ; resolve ntpvm by hash             ;
    mov     ntpvm, rax
; allocate memory for dynamic imports table
    mov     rbx, ntavm
    or      rcx, 0xffffffffffffffff
    lea     rdx, pdimp
    mov     qword ptr [rdx], 0
    mov     r8, 7FFFFFFFFh
    mov     buf_size, max_stub_size
    lea     r9, buf_size
    invoke  fn_ntavm ptr ntavm, rcx, rdx, r8, r9, 0x3000, 0x04
    mov     rbx, pdimp
; write current values to the dynamic imports table
    mov     rax, ntavm 
    xor     rax, random_mask
    mov     [rbx].dynimp.ntavm, rax
    mov     rax, ntpvm
    xor     rax, random_mask
    mov     [rbx].dynimp.ntpvm, rax
; resolve kernel32 exports
    sethash rax, hash_cfw
    mov     [rbx].dynimp.cfw, rax
    sethash rax, hash_fff
    mov     [rbx].dynimp.fff, rax
    mov     [rbx].dynimp.len, 16
    xor     eax, eax                        ; rax is the counter
    mov     rcx, offset dynimp.cfw          ; first hash
_resolve:
    mov     rcx, rsi
    add     rcx, rax
    cmp     rcx, [rbx].dsynimp.len
    je      _resolve_done
    mov     rdx, [rbx+rcx]
    mov     rcx, rsi
    call    getexp

    add     rax, 8
    cmp     rax

_resolve_done:


; clean up values left in volatile registers
    clobber_regs
    mov     rdi, @rdi
    mov     rsi, @rsi
    mov     rbx, @rbx
    ret
genimps endp

; Generate a decoding stub
genstub proc buf:qword, dimp:qword, slot:qword

genstub endp

; Invoke either a system call export address or raw syscall number from rbx
; If this fails inexplicably, check stack alignment

; Get the syscall number from an NTDLL export address
;
; If a jump is found, its likely the syscall is hooked. This not only means
; we have detection to worry about, but it complicates syscall resolution.
;
; The caller has to account for this in case validate_scn returns 0
;
validate_scn proc 
    ; xor     eax, eax
    ; mov     rdx, syscall_stub_sig
    ; mov     r8, 4
    ; call    find_bytes                      ; search for 4C 8B D1 D8
    ; test    eax, eax      
    xor     eax, eax
    mov     rdx, syscall_stub_sig
    mov     r8, 4
    mov     r9, r8
    invoke  find_bytes, rcx, rdx, r8, r9
    test    eax, eax                        
    jnz     _done                           
_done:

    ret
validate_scn endp

; ----------------------------------------- ;                                   ;
; Resolve a DLL export by hash              ;                                   ;
getexp proc base:qword, hash:qword 
    local   @rbx:qword
    local   @rsi:qword
    local   @rdi:qword
    local   @r10:qword
    local   @r11:qword
    local   @r12:qword
    local   @r13:qword
    local   @r14:qword
    mov     @rbx, rbx
    mov     @rsi, rsi
    mov     @r10, r10
    mov     @r11, r11
    mov     @r12, r12
    mov     @r13, r13
    mov     @r14, r14
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
    mov     r14, @r14
    mov     r13, @r13
    mov     r12, @r12
    mov     r11, @r11
    mov     r10, @r10
    mov     rdi, @rdi
    mov     rsi, @rsi
    mov     rbx, @rbx
    retn                                    ;                                   ;
getexp endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
; Resolve a module base address by hash     ;                                   ;
getmod proc hash:qword                      ;                                   ;
    local   first:qword                     ; first module entry                ;
    local   curr:qword                      ; current module entry              ;
    local   @rbx:qword
    local   @rsi:qword
    local   @rdi:qword
    mov     @rbx, rbx
    mov     @rsi, rsi
    mov     @rdi, rdi
    mov     rdi, rcx                        ;                                   ;
    mov     rsi, [gs:0x60]                  ; get PEB                           ;
    mov     rsi, [rsi].peb.ldr              ; rsi -> PEB_LDR_DATA entry         ;
    mov     rsi, [rsi].pld.moml.fw-10h      ; rsi points to LDR_MODULE link     ;
    mov     first, rsi                      ;                                   ;
    mov     rbx, [rsi].ldte.moml.fw-10h     ; each LDR_MODULE links to others   ;
    mov     curr, rbx                       ; save current module               ;
_loop:                                      ; loop over modules                 ;
    lea     rcx, [rbx].ldte.basename.buffer ;                                   ;
    xor     edx, edx
    mov     dx, [rbx].ldte.basename.len                   
    call    gethash                         ; get module name hash              ;
    cmp     rax, rdi                        ; match target?                     ;
    je      _match                          ;                                   ;
    mov     rbx, [curr].ldte.moml.fw-10h    ; while current != first            ;
    mov     rbx, [rbx]
    mov     curr, rbx
    cmp     rbx, first                      ;                                   ;
    je      _done                           ;                                   ;
    jmp     _loop                           ;                                   ;
_match:                                     ;                                   ;
    mov     rax, [rbx].ldte.dllbase         ; get dll base address              ;
_done:                                      ;                                   ;
    mov     rdi, @rdi
    mov     rsi, @rsi
    mov     rbx, @rbx
    retn                                    ;                                   ;
getmod endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
; Get a FNV32 hash of a buffer              ;                                   ;
gethash proc src:qword, len:dword  ;                                   ;
    local   @rbx:qword
    local   @rsi:qword
    local   @rdi:qword
    mov     @rbx, rbx
    mov     @rsi, rsi
    mov     @rdi, rdi
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
    mov     rdi, @rdi
    mov     rsi, @rsi
    mov     rbx, @rbx
    retn                                    ;                                   ;
gethash endp            

; ----------------------------------------- ;
; Find matching bytes in memory
find_bytes proc src:qword, buf:qword, len:qword, max:qword
    local   @rbx:qword
    local   @rsi:qword
    local   @rdi:qword
    local   @r10:qword
    local   res:qword
    mov     @rbx, rbx
    mov     @rsi, rsi
    mov     @rdi, rdi
    mov     @r10, r10
    mov     res, 0
    xor     r10, r10
_loop:
    mov     rcx, r10
    add     rcx, len
    cmp     rcx, max
    ja      _done
    mov     rcx, src
    mov     rdx, buf
    mov     r8, len
    mov     rax, src
    inc     src
    call    memcmp
    test    eax, eax
    jz      _loop
_done:
    mov     res, rax
    mov     rdi, @rdi
    mov     rdi, @rdi
    mov     rsi, @rsi
    mov     rbx, @rbx
    ret
find_bytes endp

; ----------------------------------------- ;
; Generic memcpy
memcmp proc src:qword, dst:qword, len:dword
    local   @rbx:qword
    mov     @rbx, rbx
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
    mov     rbx, @rbx
    ret
memcmp endp

; ----------------------------------------- ;                                   ;
; Generic memset                            ;                                   ;
memset proc dst:qword, val:byte, len:dword                             
    xor     eax, eax                        ;                                   ;
_loop:                                      ;                                   ;
    cmp     r8d, eax                        ;                                   ;
    jge     _done                           ;                                   ;
    mov     [rcx+rax], dl                   ;                                   ;
    inc     eax                             ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    retn                                    ;                                   ;
memset endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
; Copy a wide string                        ;                                   ;
wstrcpy proc  dst:qword, src:qword 
    local   @rbx:qword
    mov     @rbx, rbx
    xor     eax, eax                        ;                                   ;
_loop:                                      ;                                   ;
    mov     bx, [rdx+rax*2]                 ;                                   ;
    test    bx, bx                          ;                                   ;
    jz      _done                           ;                                   ;
    mov     [rcx+rax*2], bx                 ;                                   ;
    inc     eax                             ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    mov     rbx, @rbx
    retn                                    ;                                   ;
wstrcpy endp                                ;                                   ;
; ----------------------------------------- ;                                   ;
; String length of wide string
wcslen proc          
    mov     rax, rcx                
_loop:                                      ;                                   ;
    mov     dx, [rax]       
    test    dx, dx                          ;                                   ;
_next:                                      ;                                   ;
    add     rax, 2                          ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    sub     rax, rcx
    ret                                     ;                                   ;
wcslen endp                            ;

; ----------------------------------------- ;                                   ;
; Calculate length of a string              ;                                   ;
strlen proc  src:qword            
    local   @rbx:qword
    mov     @rbx, rbx                     
    xor     eax, eax                        ;                                   ;
_loop:                                      ;                                   ;
    mov     bl, [rcx+rax]                   ;                                   ;
    test    bl, bl                          ;                                   ;
    jz      _done                           ;                                   ;
    inc     eax                             ;                                   ;
    jmp     _loop                           ;                                   ;
_done:                                      ;                                   ;
    mov     rbx, @rbx                   
    retn                                    ;                                   ;
strlen endp                                 ;                                   ;
; ----------------------------------------- ;                                   ;
; Pseudo-data section
data:
syscall_stub_sig:
    db 0x4c, 0x8B, 0xD1, 0xB8        

end_data:

text ends                                   ;                                   ;
end                                         ;                                   ;
;                                                                               ;
; ----------------------------------------------------------------------------- ;
;                  C++ - Obfuscated Dynamic Imports (Example)                   ;
; -----------------------------------c----------------------------------------- ;
; #define dynimp( x )      decltype( &x ) x
; #define D_TYPE( x )     (decltype( &x ))
; #define D_XOR_KEY       RND_XOR(0xffff)   // constexpr function call
;
; #define D_EXEC( e, ... ) \
;    ( ( decltype(e)((QWORD)(e) ^ D_XOR_KEY) )(__VA_ARGS__) )
;
; typedef struct _dynimp_NTDLL
; {
;       dynimp(NtAllocateVirtualMemory);
;       ...
; } dynimp_NTDLL, * PDYNIMP_NTDLL;
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
;                               References                                      ;
; ------------------------------------------------------------------------------;
; - https://zerosum0x0.blogspot.com/2019/?m=0
;-  http://www.terraspace.co.uk/uasm233_ext.pdf
;