%include "win32n.inc"

section .data
    kernel32: dd 0

    GetStdHandlePtr: dd 0
    WriteFilePtr: dd 0

    msg: db 'no import',0dh,0ah
    len: equ $-msg

    msg2: db 'who called',0dh,0ah
    len2: equ $-msg2

    scratch: dd 1
    always_zero: dd 1 dup(0)


    PE_SECTION_ALIGNMENT: equ 10000h
    DOS_HEADER_MAGIC: equ 5A4Dh
    DOS_HEADER_LFANEW: equ 03ch
    EXPORT_DIR_RVA: equ 78h ; + 18h to get into optional header from NT headers, then + 60h to get into data directories start which has export dir vir address first

%define fnv32_basis 0811c9dc5h
%define fnv32_prime 01000193h

 %macro fnv32a2 2
   mov esi, %2 ; buffer
   mov ecx, %1 ; length
   mov eax, fnv32_basis ; basis
   mov edi, fnv32_prime ; prime
 %%nexta:
   xor al, [esi]
   mul edi
   inc esi
   loop %%nexta
%endmacro

%macro resolvefuncptr 1  
    ; find the ordinal
    pusha
    shr ecx, 1h ; offset to address of names,  but not the ordinal itself
    mov esi, [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals] ; RVA of name ordinals array
    add esi, ecx ; adjust the offset with ordinal's RVA
    add esi, eax ; add kernel base
    movzx ecx, word [esi] ; success: name ordinal acquired.

    ; resolve func pointer using ordinal
    shl ecx, 2h
    mov esi, [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions] ; should be very familiar by now
    add esi, ecx ; offset by ordinal that has also been adjusted to be bigger.
    add esi, eax ; add kernel base as always
    mov esi, [esi] ; read RVA from self ptr into self
    add esi, eax ; re add kernel base, get ptr to func to esi
    mov [%1], esi ; finally we have the function pointer
    popa
%endmacro

; causes positive sp value found when trying to decompile (f5) on ida
%macro breakida 0
    push eax
    xor eax, eax
    jz %%spfuck
    add esp, 4 
%%spfuck:
    pop eax
%endmacro

%macro pointercheck 1
    push edx
    mov edx, dword [%1]
    test edx, edx   ; check anothr func ptr and keep looking if both funcs arent found yet (need diff solution for multiple funcs)
    pop edx
    jz .keeplooking
    jmp .program
%endmacro

%macro comparefuncs 3
    pusha ; cant be bothered to deal with register fuckups possibly
    fnv32a2 %1, esi ; calc fnv32a hash for the exported func's name
    cmp dword eax, %2 ; precalculated fnv32a hash for our target
    popa ; restore all our registers now that we have compared the return value
    je %3 ; jump to our func if match
%endmacro

%macro resolvelocation 1
    jmp $+5 ; another ida test
    mov [scratch], dword entry ; move entry address to scratch location in data, so ida doesnt see direcrt reference
    mov ebp, dword [scratch] ; get entry from the scratch location into ebp
    add ebp, dword %1 - entry ; add the offset between target and entry
    add ebp, dword [always_zero] ; add a value that is always zero
    push ebp ; push ebp, we will return to it
    jmp $+6 ; random ida testing, will just
    ret ; just random test
    ret
%endmacro

%macro getkernel32 0
    mov esi, dword [esp] ; should contain kernel32.BaseThreadInitThunk
    and esi, dword 0FFFF0000h

%%findkernel32:
    cmp word [esi+IMAGE_DOS_HEADER.e_magic], DOS_HEADER_MAGIC ; compare value in memory to the actual value aka MZ
    je .gotkernel32
    
    sub esi, dword PE_SECTION_ALIGNMENT ; avoid memory with no reading perms
    jmp %%findkernel32 ; keep looking it might be further

    ; in 99% of cases kernel32.dll will be exactly 1 PE_SECTION_ALIGNMENT away from esi
%endmacro

%macro getexportdir 1
    mov [%1], esi ; esi has kernel32 value now basically
    mov eax, esi
    add esi, dword [esi+DOS_HEADER_LFANEW] ; dos hdr -> nt headers
    mov ebx, dword [esi+EXPORT_DIR_RVA] ; get to NT -> optional -> data dirs -> export rva
    add ebx, eax ; we now have export directory in ebx
    xor ecx, ecx ; zero out ecx as index
%endmacro

%macro getexportentries 0
.nameexportloop:
    
    xor esi, esi
    mov esi, dword [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNames] ; RVA of name list
    add esi, ecx ; curr index
    add esi, eax ; kernel
    mov esi, [esi] ; deref ptr to name RVA
    add esi, eax ; add kernel and we got the name a export at ecx

    ; basically calling fnv32a hash on the export entry name, and matching against precalculated hashes
    comparefuncs 0dh, 0E7102BDEh, .foundgetstdhandle
    comparefuncs 0ah, 0433A007Eh, .foundwritefile  

.keeplooking:
    add ecx, 4h ; len of a entry 
    jmp .nameexportloop ; next address of names entry

%endmacro

%macro checkexportedfuncs 0
.foundgetstdhandle:
    resolvefuncptr GetStdHandlePtr  ; get func ptr for this
    pointercheck WriteFilePtr       ; determine where to go next based on arg

.foundwritefile:
    resolvefuncptr WriteFilePtr     ; same process as above but inverse
    pointercheck GetStdHandlePtr
%endmacro

%macro writeconsole 2
    push STD_OUTPUT_HANDLE
    call [GetStdHandlePtr]
    push dword 0
    push dword 0
    push %1 ; len
    push %2 ; buffer
    push eax ; has return val of getstdhandle
    call [WriteFilePtr]
%endmacro

section 12
entry:
    breakida                ; positive sp value
    resolvelocation target  ; go to target indirectly
section 34
target: 
    getkernel32             ; gets kernel32 address into esi
.gotkernel32:
    getexportdir kernel32   ; get export directory of kernel32
    getexportentries        ; now get the export entries
    checkexportedfuncs      ; check that all exported funcs are OK
.program: 
    writeconsole len, msg   ; simply write our message to console.
    writeconsole len2, msg2 ; another test msg