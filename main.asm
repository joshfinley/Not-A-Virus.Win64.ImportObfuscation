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
; We can avoid this by encoding our hashes at rest, but if were not careful,
; we'll introduce too much entropy in specific blocks.

; This program demonstrates how to achieve this in
; assembly. At the bottom, I've also included example code to achieve
; some similar results in C++. Enjoy!
; ---------------------------------------------------------------- @davovich --
option win64:0x08, casemap:none
include win.inc

; -----------------------------------------------------------------------------
;                           Obfuscation Macros
; -----------------------------------------------------------------------------
; x86 registers
_eax    equ 0
_ecx    equ 1
_edx    equ 2
_ebx    equ 3
_esp    equ 4
_ebp    equ 5
_esi    equ 6
_edi    equ 7

; x64 extended registers
_r8     equ 0
_r9     equ 1
_r10    equ 2
_r11    equ 3
_r12    equ 4
_r13    equ 5
_r14    equ 6
_r15    equ 7

; MODRM
S_mod_ri        equ 00000000b   ; 0x00 MODRM register indirect
s_mod_ra        equ 11000000b   ; 0xC0 MODRM register addressing mode
s_mod_1sbdsp    equ 01000000b   ; 0x40 MODRM one byte signed displacement
s_mod_4sbdsp    equ 10000000b   ; 0x80 MODRM four byte signed displacement

; Prefixes
s_pfx_o16       equ 01100110b   ; 0x66 prefix 16/32 bit operand override
s_pfx_a16       equ 01100111b   ; 0x67 prefix 16/32 bit address override
s_pfx_o8        equ 10001000b   ; 0x88 prefix 8 bit operand override (e.g. mov r/m8)
s_rex           equ 01000000b   ; 0x40 REX Prefix (access new 8 bit registers)
s_rex_8         equ 01000001b   ; 0x41 REX Prefix reg imm mode
s_pfx_rexw      equ 01001000b   ; 0x48 REX.W prefix (64 bit operand)
s_pfx_rexwb     equ 01001001b   ; 0x49 REX.WB 

; Opcodes
s_op_pushr      equ 0x50        ; push rax. OR with register encodings.
s_op_popr       equ 0x58        ; pop rax. OR with register encodings

; Conditional Jumps
s_jb_rel8       equ 0x72        ; jb/jnae/jc
s_jae_rel8      equ 0x73        ; jnb/jae/jnc
s_je_rel8       equ 0x74        ; jz/ne
s_jne_rel8      equ 0x75        ; jnz/jne
s_jna_rel8      equ 0x76        ; jbe/jna
s_ja_rel8       equ 0x77        ; jnbe/ja
s_jnge_rel8     equ 0x7c        ; jl/jnge
s_jd_rel8       equ 0x7d        ; jnl/jge
s_jle_rel8      equ 0x7e        ; jle/jng
s_jf_rel8       equ 0x7f        ; jnle/jg

; Relative Jumps
s_jmp_rel8      equ 0xeb        ; jmp rel8

; Basic Register Operations
s_add_rall      equ 0x03        ; add r/16/32/64
s_or_rall       equ 0x0b        ; or  r/16/32/64
s_and_rall      equ 0x23        ; and r/16/32/64
s_sub_rall      equ 0x2b        ; sub r/16/32/64
s_xor_rall      equ 0x33        ; xor r/16/32/64
s_cmp_rall      equ 0x3b        ; cmp r/16/32/64
s_mov_rall      equ 0x8b        ; mov r/16/32/64
s_mov_r8_imm8   equ 0xb0        ; mov r8 imm8
s_mov_r8        equ 0x8a        ; mov r8 r/m8
s_mov_r8_imm    equ 0xb8        ; mov r8 imm8
s_mov_r64_imm64 equ 0xC7        ; mov r64 imm64
s_shl           equ 0xe0c1      ; shl 

; Get an assembly-time random value of a specific size. Maximum 32 bits. 
; This value will change on successive expansions
rnd macro __mask
    local m
    m=(@SubStr(%@Time,7,2)+@Line)*(@SubStr(%@Date,1,2)+@SubStr(%@Date,4,2)*100+@SubStr(%@Date,7,2))* (-1001)
    m=(m+@SubStr(%@Time,1,2)+@SubStr(%@Time,4,2))*(@SubStr(%@Time,7,2)+1)
    ifnb <__mask>
        m = m and __mask
    endif
    exitm % m
endm

; Get an assembly-time random byte. This value will stay the same on successive
; expansions
static_rnd macro __mask
    local m
    m=(@SubStr(%@Time,7,2)) xor (@SubStr(%@Date,7,2))
    m=(m+@SubStr(%@Time,1,2)+@SubStr(%@Time,4,2))*(@SubStr(%@Time,7,2)+1)
    ifnb <__mask>
        m = m and __mask
    endif
    exitm % m
endm

; Emit some junk bytes that look vaguely like real code
emit_junk macro 
    local v1, v2, r0, r1, r2, r3, r4, b
    count = 0
    v1 = rnd(0x02)
    r0 = (v1 or 1)
    r1 = (v1 or 2)
    r2 = (v1 or 3)
    r3 = (v1 or 4)
    r4 = (v1 or 5)
    v2 = rnd(0xff)

    emit_junk_op v1, s_mov_rall, r4, r3
    emit_junk_op v1, s_add_rall, r4, r1
    emit_junk_op v1, s_sub_rall, r4, r1
    emit_junk_op v1, s_cmp_rall, r0, r1
    emit_junk_jcnd v1, v2
    emit_jmp_rel8 v2 
endm

; Emit a junk operation of the given type (buggy)
emit_junk_op macro v1, opc, r1, r2
    if v1 eq 0
        db s_pfx_rexw
        db opc
        b = r2
        b = (b shl 3) or (r1)
        db b
    elseif v1 eq 1
        db opc
        b = r1
        b = (b shl 3) or (r2)
        db b

    elseif v1 eq 2
        db opc
        b = r2
        b = (b shl 3) or (r1)
        db b
    endif
endm

; Emit a junk conditional comparison
emit_junk_jcnd macro v, dist
    if v eq 0
        db s_ja_rel8
        db dist
    elseif v eq 1
        db s_jle_rel8
        db dist
    elseif v eq 2
        db s_jne_rel8
        db dist
    endif
endm

; Emit the bytes of a string
emit_bytes macro string
    for value, <string>
        db value
    endm
endm

; Emit a relative 8 jump
emit_jmp_rel8 macro dist
    db s_jmp_rel8
    db dist
endm

; -----------------------------------------------------------------------------
;                           Dynamic Import Macros
; -----------------------------------------------------------------------------
; 
; Our defined hashes / hashing values. We mask embedded hashes, offsets, and
; primes with our own value to avoid detections on these values.
;
; We use the `rnd` compile time macro, credit to mabdelouahab@masm32.com
;
; We go through a little more trouble to protect these:
;
random_mask         equ static_rnd(0xfffffff)
hash_basis          equ            0xC59D1C81  xor random_mask      
hash_prime          equ            0x01000193  xor random_mask     

;
; Our function hashes will all be double words of high entropy but at least
; they won't be a dead giveaway in a hash database
;
hash_ntdll      equ         0x25959F7F xor random_mask
hash_ntavm      equ         0x6640A89B xor random_mask

_movd_mask macro reg, ext
    if ext eq 1
        db s_pfx_rexwb
    endif 

    db s_mov_r8_imm8
    db random_mask

    if ext eq 1
        db s_pfx_rexwb
    endif

    dw s_shl or reg

endm

; Data Structures ------;
dapi_entry struct       ; dynamic import table entry
    address qword ?     ; our encoded function pointer           
    hash    qword ?     ; our encoded hash
dapi_entry ends         ;

dapi struct             ; our dynamic import table
    entries qword ?     ; pointer to entries
    len     dword ?     ; number of entries
dapi ends               ;
; ----------------------;

; -----------------------------------------------------------------------------
;                               Executable Code
; ----------------------------------------------------------------------------- 
text segment align(0x10) 'code' read execute
start proc
    local   d_ents[10]:dapi_entry
    local   d_table:dapi
    mov     eax, random_mask
    shl     rax, 8
    ;_movd_mask _eax, 0
    ;_movd_mask _r8, 1
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
    mov     eax, hash_basis                 ; eax is the hash basis
    xor     eax, random_mask                
_loop:
    cmp     ecx, edx
    je      _done
    xor     ebx, ebx
    mov     bl, [rsi+rcx]
    xor     eax, ebx                        ; hash = hash ^ src[i]
    mov     edi, hash_prime
    xor     edi, random_mask
    imul    eax, edi                        ; hash = hash * prime
    inc     ecx
    jmp     _loop
_done:
    xor     eax, random_mask                ; mask the hash
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
; C++ Version -----------------------------------------------------------------

; Refrences -------------------------------------------------------------------
; [1] https://web.archive.org/web/20220511043450/https://www.mikrocontroller
;   .net/attachment/450367/MASM61PROGUIDE.pdf
; [2] https://web.archive.org/web/20220715024359/http://www.phatcode.net/res
;   /223/files/html/Chapter_8/CH08-9.html