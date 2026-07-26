/* Context.cpp */
#include <Windows.h>
#include "Structs.h"
#include "Primitives.h"
#include "Common.h"
#include "Debug.h"

/*================================================
@ InitializeSpoofContext Function
# Zeros out the BYOUD_CONTEXT structure and sets
# the active technique ID and target module base
================================================*/
VOID ByoudContext::InitializeSpoofContext(
    OUT PBYOUD_CONTEXT pByoudCtx,
    _In_ DWORD dwTechnique,
    _In_ PVOID pTarget
) {
    Primitive::MemorySet(pByoudCtx, 0, sizeof(BYOUD_CONTEXT));
    pByoudCtx->Technique            = dwTechnique;
    pByoudCtx->pTargetModule        = pTarget;
}

/*================================================
@ CommitSpoofChange Function
# Pushes a BYOUD_CHANGE entry into the context's
# change log array. Returns FALSE if the log is
# full (BYOUD_MAX_CHANGES reached)
================================================*/
BOOL ByoudContext::CommitSpoofChange(
    _Inout_ PBYOUD_CONTEXT pByoudCtx,
    _In_ PBYOUD_CHANGE pByoudChange
) {
    if (pByoudCtx->Count >= BYOUD_MAX_CHANGES)
        return FALSE;

    pByoudCtx->Changes[pByoudCtx->Count++] = *pByoudChange;
    return TRUE;
}

/*================================================
@ TrackCacheNullification Function
# Records a cache zeroing operation so it can be
# reverted later. Stores the cache address and
# its original value before nullification
================================================*/
BOOL ByoudContext::TrackCacheNullification(
    _Inout_ PBYOUD_CONTEXT pByoudCtx,
    _In_ ULONG_PTR uAddress,
    _In_ DWORD dwOld
) {
    BYOUD_CHANGE Change = {};
    Change.Type = BCT_CACHE_ZERO;
    Change.u.Cache.Address = uAddress;
    Change.u.Cache.OldValue = dwOld;
    return CommitSpoofChange(pByoudCtx, &Change);
}

/*================================================
@ TrackPDataProtection Function
# Records a .pdata protection change (either
# PAGE_READWRITE or PAGE_NOACCESS) so the
# original protection can be restored on cleanup
================================================*/
BOOL ByoudContext::TrackPDataProtection(
    _Inout_ PBYOUD_CONTEXT pByoudCtx,
    _In_ PVOID pModule,
    _In_ PVOID pBase,
    _In_ SIZE_T Size,
    _In_ DWORD dwOldProtect
) {
    BYOUD_CHANGE Change = {};
    Change.Type = BCT_PDATA_PROTECT;
    Change.u.Pdata.pModule = pModule;
    Change.u.Pdata.Base = pBase;
    Change.u.Pdata.Size = Size;
    Change.u.Pdata.OldProtect = dwOldProtect;
    return CommitSpoofChange(pByoudCtx, &Change);
}

/*================================================
@ TrackInvertedTableCollapse Function
# Records the original ImageSize before it was
# set to 0 in _INVERTED_FUNCTION_TABLE, enabling
# ExpandInvertedTableEntry to restore it later
================================================*/
BOOL ByoudContext::TrackInvertedTableCollapse(
    _Inout_ PBYOUD_CONTEXT pByoudCtx, 
    _In_ PVOID pModule, 
    _In_ ULONG ulOldSize
) {
    BYOUD_CHANGE Change = {};
    Change.Type = BCT_INVERTED_TABLE_SHRINK;
    Change.u.InvertedTable.pModule = pModule;
    Change.u.InvertedTable.OldImageSize = ulOldSize;
    return CommitSpoofChange(pByoudCtx, &Change);
}

/*================================================
@ TrackDynamicTableInsertion Function
# Records the allocated RUNTIME_FUNCTION pointer
# so RtlDeleteFunctionTable can remove it and
# the memory can be freed during cleanup
================================================*/
BOOL ByoudContext::TrackDynamicTableInsertion(
    _Inout_ PBYOUD_CONTEXT pByoudCtx, 
    _In_ PRUNTIME_FUNCTION pRuntimeFunction
) {
    BYOUD_CHANGE Change = {};
    Change.Type = BCT_DYNAMIC_TABLE_ADD;
    Change.u.DynamicAdd.pFunctionTable = pRuntimeFunction;
    return CommitSpoofChange(pByoudCtx, &Change);
}

/*================================================
@ TrackDynamicTableTypeChange Function
# Records the original Type field value of the
# _DYNAMIC_FUNCTION_TABLE entry before it was
# set to 0 (RF_CALLBACK) for WinDbg bypass
================================================*/
BOOL ByoudContext::TrackDynamicTableTypeChange(
    _Inout_ PBYOUD_CONTEXT pByoudCtx, 
    _In_ PVOID pEntry, 
    _In_ DWORD dwOldType
) {
    BYOUD_CHANGE Change = {};
    Change.Type = BCT_DYNAMIC_TABLE_TYPE;
    Change.u.DynamicType.pEntry = pEntry;
    Change.u.DynamicType.OldType = dwOldType;
    return CommitSpoofChange(pByoudCtx, &Change);
}

/*================================================
@ TrackShellcodeInjection Function
# Records the ShadowGate stub appended to .text
# so it can be zeroed during cleanup
================================================*/
BOOL ByoudContext::TrackShellcodeInjection(
    _Inout_ PBYOUD_CONTEXT pByoudCtx,
    _In_ PVOID pModule,
    _In_ PVOID pAddress,
    _In_ DWORD dwSize
) {
    BYOUD_CHANGE Change = {};
    Change.Type = BCT_SHELLCODE_APPENDED;
    Change.u.ShellcodeAppended.pModule = pModule;
    Change.u.ShellcodeAppended.pAddress = pAddress;
    Change.u.ShellcodeAppended.Size = dwSize;
    return CommitSpoofChange(pByoudCtx, &Change);
}

/*================================================
@ RevertAllSpoofChanges Function
# Walks the change log in reverse order and undoes
# every tracked modification. Reverse order is
# critical — PAGE_NOACCESS must be removed first
# or subsequent .pdata access will fault
================================================*/
BOOL ByoudContext::RevertAllSpoofChanges(
    _Inout_ PBYOUD_CONTEXT pByoudCtx
) {
    BOOL                                B0K                 = TRUE;
    DWORD                               Dummy               = 0;

    for (int i = (int)pByoudCtx->Count - 1; i >= 0; i--) {

        PBYOUD_CHANGE pC = &pByoudCtx->Changes[i];

        switch (pC->Type) {

            case BCT_CACHE_ZERO: {
                PVOID       BaseAddress     = (PVOID)pC->u.Cache.Address;
                SIZE_T      RegionSize      = sizeof(DWORD);
                Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_READWRITE, &Dummy);
                *(PDWORD)pC->u.Cache.Address = pC->u.Cache.OldValue;
                Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_READONLY, &Dummy);
                break;
            }

            case BCT_PDATA_PROTECT: {
                PVOID           BaseAddress         = pC->u.Pdata.Base;
                SIZE_T          RegionSize          = pC->u.Pdata.Size;
                Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, pC->u.Pdata.OldProtect, &Dummy);
                break;
            }

            case BCT_PDATA_NOACCESS: {
                StackSpoof::RestorePDataAccess(pC->u.Pdata.pModule, pC->u.Pdata.OldProtect);
                break;
            }

            case BCT_INVERTED_TABLE_SHRINK: {
                Unwinder::ExpandInvertedTableEntry(pC->u.InvertedTable.pModule, pC->u.InvertedTable.OldImageSize);
                break;
            }

            case BCT_DYNAMIC_TABLE_ADD: {
                g_Win32.Nt.RtlDeleteFunctionTable(pC->u.DynamicAdd.pFunctionTable);
                ::operator delete(pC->u.DynamicAdd.pFunctionTable);
                break;
            }

            case BCT_DYNAMIC_TABLE_TYPE: {
                *(PDWORD)((ULONG_PTR)pC->u.DynamicType.pEntry + 0x50) = pC->u.DynamicType.OldType;
                break;
            }

            case BCT_SHELLCODE_APPENDED: {
                PVOID                   BaseAddress         = pC->u.ShellcodeAppended.pAddress;
                SIZE_T                  RegionSize          = pC->u.ShellcodeAppended.Size;
                DWORD                   OldProt             = 0;
                Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_EXECUTE_READWRITE, &OldProt);
                Primitive::MemorySet(
                    pC->u.ShellcodeAppended.pAddress,
                    0,
                    pC->u.ShellcodeAppended.Size
                );
                Proxy::WorkItemNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, PAGE_EXECUTE_READ, &Dummy);
                break;
            }
        }
    }

    pByoudCtx->Count = 0;
    return B0K;
}