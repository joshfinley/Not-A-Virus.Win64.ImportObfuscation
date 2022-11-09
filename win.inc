ifndef _win_inc
_win_inc equ <1>

list_entry struct
    fw   qword ?
    bk  qword ?
list_entry ends

large_integer struct
    low_part dword ?
    high_part dword ?
large_integer ends

ucstr struct
    _length word ?
    max_len word ?
    byte 4 dup(?)
    buffer  qword ?
ucstr ends

peb struct
    inheritedaddressspace                byte ?                 ; 0x0000
    readimagefileexecoptions             byte ?                 ; 0x0001
    beingdebugged                        byte ?                 ; 0x0002
    bitfield                             byte ?                 ; 0x0003
    padding0                             byte 4 dup(?)          ; 0x0004
    mutant                               qword ?                ; 0x0008
    imagebaseaddress                     qword ?                ; 0x0010
    ldr                                  qword ?                ; 0x0018
    processparameters                    qword ?                ; 0x0020
    subsystemdata                        qword ?                ; 0x0028
    processheap                          qword ?                ; 0x0030
    fastpeblock                          qword ?                ; 0x0038
    atlthunkslistptr                     qword ?                ; 0x0040
    ifeokey                              qword ?                ; 0x0048
    crossprocessflags                    dword ?                ; 0x0050
    padding1                             byte 4 dup(?)          ; 0x0054
    usersharedinfoptr                    qword ?                ; 0x0058
    systemreserved                       dword ?                ; 0x0060
    atlthunkslistptr32                   dword ?                ; 0x0064
    apisetmap                            qword ?                ; 0x0068
    tlsexpansioncounter                  dword ?                ; 0x0070
    padding2                             byte 4 dup(?)          ; 0x0074
    tlsbitmap                            qword ?                ; 0x0078
    tlsbitmapbits                        dword 2 dup(?)         ; 0x0080
    readonlysharedmemorybase             qword ?                ; 0x0088
    shareddata                           qword ?                ; 0x0090
    readonlystaticserverdata             qword ?                ; 0x0098
    ansicodepagedata                     qword ?                ; 0x00a0
    oemcodepagedata                      qword ?                ; 0x00a8
    unicodecasetabledata                 qword ?                ; 0x00b0
    numberofprocessors                   dword ?                ; 0x00b9
    ntglobalflag                         dword ?                ; 0x00bc
    criticalsectiontimeout               large_integer <>       ; 0x00c0
    heapsegmentreserve                   qword ?                ; 0x00c8
    heapsegmentcommit                    qword ?                ; 0x00d0
    heapdecommittotalfreethreshold       qword ?                ; 0x00d8
    heapdecommitfreeblockthreshold       qword ?                ; 0x00e0
    numberofheaps                        dword ?                ; 0x00e8
    maximumnumberofheaps                 dword ?                ; 0x00ec
    processheaps                         qword ?                ; 0x00f0
    gdisharedhandletable                 qword ?                ; 0x00f8
    processstarterhelper                 qword ?                ; 0x0100
    gdidcattributelist                  dword ?                 ; 0x0108
    padding3                             byte 4 dup(?)          ; 0x010c
    loaderlock                           qword ?                ; 0x0110
    maj_ver                              dword ?                ; 0x0118
    osminorversion                       dword ?                ; 0x011c
    osbuildnumber                        word ?                 ; 0x0120
    oscsdversion                         word ?                 ; 0x0122
    osplatformid                         dword ?                ; 0x0124
    imagesubsystem                       dword ?                ; 0x0128
    imagesubsystemmajorversion           dword ?                ; 0x012c
    imagesubsystemminorversion           dword ?                ; 0x0130
    padding4                             byte 4 dup(?)          ; 0x0134
    activeprocessaffinitymask            qword ?                ; 0x0138
    gdihandlebuffer                      dword 60 dup(?)        ; 0x0140
    postprocessinitroutine               qword ?                ; 0x0230
    tlsexpansionbitmap                   qword ?                ; 0x0238
    tlsexpansionbitmapbits               dword 32 dup(?)        ; 0x0240
    sessionid                            dword ?                ; 0x02c0
    padding5                             byte 4 dup(?)          ; 0x02c4
    appcompatflags                       large_integer <>      ; 0x02c8
    appcompatflagsuser                   large_integer <>      ; 0x02d0
    pshimdata                            qword ?                ; 0x02d8
    appcompatinfo                        qword ?                ; 0x02e0
    csdversion                           ucstr <>      ; 0x02e8
    activationcontextdata                qword ?                ; 0x02f8
    processassemblystoragemap            qword ?                ; 0x0300
    systemdefaultactivationcontextdata   qword ?                ; 0x0308
    systemassemblystoragemap             qword ?                ; 0x0310
    minimumstackcommit                   qword ?                ; 0x0318
    sparepointers                        qword 4 dup(?)         ; 0x0320
    spareulongs                          dword 5 dup(?)         ; 0x0340
                                         byte 4 dup(?)
    werregistrationdata                  qword ?                ; 0x0358
    wershipassertptr                     qword ?                ; 0x0360
    punused                              qword ?                ; 0x0368
    pimageheaderhash                     qword ?                ; 0x0370
    tracingflags                         dword ?                ; 0x0378
    padding6                             byte 4 dup(?)          ; 0x037c
    csrserverreadonlysharedmemorybase    qword ?                ; 0x0380
    tppworkerplistlock                   qword ?                ; 0x0388
    tppworkerplist                       list_entry <>          ; 0x0390
    waitonaddresshashtable               qword 128 dup(?)       ; 0x03a0
    telemetrycoverageheader              qword ?                ; 0x07a0
    cloudfileflags                       dword ?                ; 0x07a8
    cloudfilediagflags                   dword ?                ; 0x07ac
    placeholdercompatibilitymode         byte ?                 ; 0x07b0
    placeholdercompatibilitymodereserved byte 7 dup(?)          ; 0x07b1
    leapseconddata                       qword ?                ; 0x07b8
    leapsecondflags                      dword ?                ; 0x07c0
    ntglobalflag2                        dword ?                ; 0x07c4
peb ends

; peb loader data
pld struct 
    _length                         dword ?                     ; 0x0000
    initialized                     byte ?                      ; 0x0004
                                    byte 3 dup(?)               ; padding
    sshandle                        qword ?                     ; 0x0008
    ; load order module list
    loml                            list_entry <>               ; 0x0010
    ; in memory order module list
    moml                            list_entry <>               ; 0x0020
    ; iniitialization order module list
    ioml list_entry <>                                          ; 0x0030
    entryinprogress                 qword ?                     ; 0x0040
    shutdowninprogress              byte ?                      ; 0x0048
                                    byte 7 dup(?)               ; padding
    shutdownthreadid                qword ?                     ; 0x0050
pld ends

rtl_balanced_node struct 
    _dummy byte 24 dup(?)
rtl_balanced_node ends

ldte struct 
    inloadorderlinks            list_entry <>                   ; 0x0000
    moml                        list_entry <>                   ; 0x0010
    ininitializationorderlinks  list_entry <>                   ; 0x0020
    dllbase                     qword ?                         ; 0x0030
    entrypoint                  qword ?                         ; 0x0038
    sizeofimage                 dword ?                         ; 0x0040
                                byte 4 dup(?)                   ; padding
    fulldllname                 ucstr <>                        ; 0x0048
    basename                    ucstr <>                        ; 0x0058
    flaggroup                   byte 4 dup(?)                   ; 0x0068
    obsoleteloadcount           word ?                          ; 0x006c
    tlsindex                    word ?                          ; 0x006e
    hashlinks                   list_entry <>                   ; 0x0070
    timedatestamp               dword ?                         ; 0x0080
                                byte 4 dup(?)                   ; padding 
    entrypointactivationcontext qword ?                         ; 0x0088
    _lock                       qword ?                         ; 0x0090
    ddagnode                    qword ?                         ; 0x0098
    nodemodulelink              list_entry <>                   ; 0x00a0
    loadcontext                 qword ?                         ; 0x00b0
    parentdllbase               qword ?                         ; 0x00b8
    switchbackcontext           qword ?                         ; 0x00c0
    baseaddressindexnode        rtl_balanced_node <>            ; 0x00c8
    mappinginfoindexnode        rtl_balanced_node <>            ; 0x00e0
    originalbase                qword ?                         ; 0x00f8
    loadtime                    large_integer <>                ; 0x0100
    basenamehashvalue           dword ?                         ; 0x0108
    loadreason                  dword ?                         ; 0x010c
    implicitpathoptions         dword ?                         ; 0x0110
    referencecount              dword ?                         ; 0x0114
    dependentloadflags          dword ?                         ; 0x0118      
    signinglevel                byte ?                          ; 0x011c
ldte ends

dos_hdr struct
    e_magic    word ?                                           ; 0x0000 
    e_cblp     word ?                                           ; 0x0002
    e_cp       word ?                                           ; 0x0004
    e_crlc     word ?                                           ; 0x0006
    e_cparhdr  word ?                                           ; 0x0008
    e_minalloc word ?                                           ; 0x000a
    e_maxalloc word ?                                           ; 0x000c
    e_ss       word ?                                           ; 0x000e
    e_sp       word ?                                           ; 0x0010
    e_csum     word ?                                           ; 0x0012
    e_ip       word ?                                           ; 0x0014
    e_cs       word ?                                           ; 0x0016
    e_lfarlc   word ?                                           ; 0x0018
    e_ovno     word ?                                           ; 0x001a
    e_res      word 4 dup(?)                                    ; 0x001c
    e_oemid    word ?                                           ; 0x0024
    e_oeminfo  word ?                                           ; 0x0026
    e_res2     word 10 dup(?)                                   ; 0x0028
    e_lfanew   dword ?                                          ; 0x003c
dos_hdr ends

file_hdr struct
    machine              word ?                                 ; 0x0000
    numberofsections     word ?                                 ; 0x0002
    timedatestamp        dword ?                                ; 0x0004
    pointertosymboltable dword ?                                ; 0x0008
    numberofsymbols      dword ?                                ; 0x000c
    sizeofoptionalheader word ?                                 ; 0x0010
    characteristics      word ?                                 ; 0x0012
file_hdr ends

img_data_dir struct
    va dword ? ; 0x0000
    _size          dword ? ; 0x0004
img_data_dir ends

opt_hdr struct
    magic                       word ?                          ; 0x0000
    majorlinkerversion          byte ?                          ; 0x0002
    minorlinkerversion          byte ?                          ; 0x0003
    sizeofcode                  dword ?                         ; 0x0004
    sizeofinitializeddata       dword ?                         ; 0x0008
    sizeofuninitializeddata     dword ?                         ; 0x000c
    addressofentrypoint         dword ?                         ; 0x0010
    baseofcode                  dword ?                         ; 0x0014
    imagebase                   qword ?                         ; 0x0018
    sectionalignment            dword ?                         ; 0x0020
    filealignment               dword ?                         ; 0x0024
    majoroperatingsystemversion word ?                          ; 0x0028
    minoroperatingsystemversion word ?                          ; 0x002a
    majorimageversion           word ?                          ; 0x002c
    minorimageversion           word ?                          ; 0x002e
    majorsubsystemversion       word ?                          ; 0x0030
    minorsubsystemversion       word ?                          ; 0x0032
    win32versionvalue           dword ?                         ; 0x0034
    sizeofimage                 dword ?                         ; 0x0038
    sizeofheaders               dword ?                         ; 0x003c
    checksum                    dword ?                         ; 0x0040
    subsystem                   word ?                          ; 0x0044
    dllcharacteristics          word ?                          ; 0x0046
    sizeofstackreserve          qword ?                         ; 0x0048
    sizeofstackcommit           qword ?                         ; 0x0050
    sizeofheapreserve           qword ?                         ; 0x0058
    sizeofheapcommit            qword ?                         ; 0x0060
    loaderflags                 dword ?                         ; 0x0068
    numberofrvaandsizes         dword ?                         ; 0x006c
    d_dir                       img_data_dir 16 dup(<>)         ; 0x0070
opt_hdr ends

nt_hdr struct
    signature       dword ?                                     ; 0x0000
    fileheader      file_hdr <>                                 ; 0x0004
    opt             opt_hdr<>                                   ; 0x0018
nt_hdr ends

exp_dir struct
    characteristics       dword ?                               ; 0x0000
    timedatestamp         dword ?                               ; 0x0004
    majorversion          word  ?                               ; 0x0008
    minorversion          word  ?                               ; 0x000a
    _name                 dword ?                               ; 0x000c
    base                  dword ?                               ; 0x0010
    numberoffunctions     dword ?                               ; 0x0014
    n_names               dword ?                               ; 0x0018
    aof                   dword ?                               ; 0x001c
    aon                   dword ?                               ; 0x0020
    aoo                   dword ?                               ; 0x0024
exp_dir ends

endif ; !_win_inc