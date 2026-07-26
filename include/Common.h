/* Common.h */
#pragma once

/* HEADER GUARD */
#ifndef COMMON_H
#define COMMON_H

#include <Windows.h>
#include "Structs.h"

/*================================================
@ WIN32_API Struct
================================================*/
struct WIN32_API {
    struct {
        NTSTATUS(NTAPI* RtlQueueWorkItem)(
            _In_ WORKERCALLBACKFUNC Function,
            _In_opt_ PVOID Context,
            _In_ ULONG Flags
         );

        NTSTATUS(NTAPI* NtQueryInformationProcess)(
            _In_ HANDLE ProcessHandle,
            _In_ PROCESSINFOCLASS ProcessInformationClass,
            _Out_ PVOID ProcessInformation,
            _In_ ULONG ProcessInformationLength,
            _Out_opt_ PULONG ReturnLength
         );

        NTSTATUS(NTAPI* NtWaitForSingleObject)(
            _In_ HANDLE Handle,
            _In_ BOOLEAN Alertable,
            _In_opt_ PLARGE_INTEGER Timeout
         );

        NTSTATUS(NTAPI* NtCreateEvent)(
            _Out_ PHANDLE EventHandle,
            _In_ ACCESS_MASK DesiredAccess,
            _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
            _In_ EVENT_TYPE EventType,
            _In_ BOOLEAN InitialState
         );

        NTSTATUS(NTAPI* NtSetEvent)(
            _In_ HANDLE EventHandle,
            _Out_opt_ PLONG PreviousState
         );

        BOOLEAN(NTAPI* RtlAddFunctionTable)(
            _In_ PRUNTIME_FUNCTION FunctionTable,
            _In_ ULONG EntryCount,
            _In_ ULONG64 BaseAddress
         );

        BOOLEAN(NTAPI* RtlDeleteFunctionTable)(
            _In_ PRUNTIME_FUNCTION FunctionTable
         );

        VOID(NTAPI* RtlAcquireSRWLockExclusive)(
            _Inout_ PRTL_SRWLOCK SRWLock
         );

        VOID(NTAPI* RtlReleaseSRWLockExclusive)(
            _Inout_ PRTL_SRWLOCK SRWLock
         );

        PEXCEPTION_ROUTINE(NTAPI* RtlVirtualUnwind)(
            _In_ DWORD HandlerType,
            _In_ DWORD64 ImageBase,
            _In_ DWORD64 ControlPc,
            _In_ PRUNTIME_FUNCTION FunctionEntry,
            _Inout_ PCONTEXT ContextRecord,
            _Out_ PVOID* HandlerData,
            _Out_ PDWORD64 EstablisherFrame,
            _Inout_opt_ PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
         );

        PRUNTIME_FUNCTION(NTAPI* RtlLookupFunctionEntry)(
            _In_ DWORD64 ControlPc,
            _Out_ PDWORD64 ImageBase,
            _Out_ PUNWIND_HISTORY_TABLE HistoryTable
         );

    } Nt;

    struct {
        DWORD(WINAPI* WaitForSingleObject)(
            _In_ HANDLE hHandle,
            _In_ DWORD dwMilliseconds
         );

        HMODULE(WINAPI* LoadLibraryW)(
            _In_ LPCWSTR lpLibName
         );

        HMODULE(WINAPI* GetModuleHandleW)(
            _In_opt_ LPCWSTR lpModuleName
         );

    } K32;

    struct {
        LSTATUS(WINAPI* RegOpenKeyExW)(
            _In_ HKEY hKey,
            _In_opt_ LPCWSTR lpSubKey,
            _In_ DWORD ulOptions,
            _In_ REGSAM samDesired,
            _Out_ PHKEY phkResult
         );

        LSTATUS(WINAPI* RegQueryValueExW)(
            _In_ HKEY hKey,
            _In_opt_ LPCWSTR lpValueName,
            LPDWORD lpReserved,
            _Out_opt_ LPDWORD lpType,
            _Out_opt_ LPBYTE lpData,
            _Inout_opt_ LPDWORD lpcbData
         );

        LSTATUS(WINAPI* RegCloseKey) (
            _In_ HKEY hKey
         );

        PVOID SystemFunction032;
    } AdvApi32;

};

/* Global Object */
inline WIN32_API g_Win32{};

/* External assembly functions */
extern "C" ULONG_PTR CaptureStackPointer();
extern "C" ULONG_PTR ScanStackForValue(
    _In_ ULONG_PTR uSearchValue,
    OUT PULONG_PTR puFoundAddress
);
extern "C" ULONG_PTR ShadowGate(
    _In_ PSHADOWGATE_PARAMS pShadowParams
);
extern "C" ULONG_PTR ShadowGateEnd();

/*================================================
@ Function Pointers
================================================*/

/* From Resolver.cpp */
namespace Resolver {
    PVOID LdrGetModuleByHash(
        _In_ ULONG uModuleHash
    );
    PVOID LdrGetSymbolByHash(
        _In_ PVOID pModule,
        _In_ ULONG uFunctionHash
    );
    VOID ResolveSectionInfo(
        _In_ PVOID pModule,
        _In_ PCHAR pcSectionName,
        OUT PSECTION_INFO pSectionInfo
    );
    VOID ResolvePDataSectionInfo(
        _In_ PVOID pModule,
        OUT PSECTION_INFO pSectionInfo
    );
    VOID ResolveTextSectionInfo(
        _In_ PVOID pModule,
        OUT PSECTION_INFO pSectionInfo
    );
    PVOID ResolveExceptionDirectory(
        _In_ PVOID pModule,
        OUT PDWORD pdwDirSize
    );
    DWORD LocateCallInstructionOffset(
        _In_ ULONG_PTR uStartAddress,
        _In_ DWORD dwSearchLimit
    );
}

/* From StackUtils.cpp */
namespace StackUtils {
    ULONG_PTR ResolveThreadStackOrigin(
        OUT PULONG_PTR puStackPointer
    );
    BOOL DetectStackCookiePresence(
        _In_ PVOID pModule
    );
}

/* From Unwind.cpp */
namespace Unwinder {
    DWORD CalculateUnwindFrameSize(
        _In_ PVOID pModule,
        _In_ PVOID pUnwindInfo,
        OUT PDWORD pdwTarget
    );
    PRUNTIME_FUNCTION FindDonorByFrameSize(
        _In_ PVOID pModule,
        _In_ DWORD dwFrameSize,
        _In_ BOOL bStrict,
        OUT PDWORD pdwActual
    );
    NTSTATUS UnlockPDataSection(
        _In_ PVOID pModule
    );
    NTSTATUS LockPDataSection(
        _In_ PVOID pModule
    );
    NTSTATUS UnlockTextSection(
        _In_ PVOID pModule
    );
    NTSTATUS LockTextSection(
        _In_ PVOID pModule
    );
    BOOL ResolveDynamicFunctionTablePtrs(
        _In_ HANDLE hProcess,
        OUT PULONG_PTR puHeadPtr,
        OUT PULONG_PTR puSentinel
    );
    PDYNAMIC_FUNCTION_TABLE LocateDynamicFunctionTableEntry(
        _In_ ULONG_PTR uAddress
    );
    BOOL LocateInvertedFunctionTable(
        OUT PINVERTED_FUNCTION_TABLE* ppInvertedTable,
        OUT PRTL_SRWLOCK* ppSrwLock
    );
    BOOL ResolveLdrMrdataProtector(
        OUT fnLdrProtectMrdata* pOutFnPtr
    );
    BOOL CollapseInvertedTableEntry(
        _In_ PVOID pModule,
        OUT PULONG puOldSize
    );
    BOOL ExpandInvertedTableEntry(
        _In_ PVOID pModule,
        _In_ ULONG ulOldSize
    );
    BOOL AppendCodeToText(
        _In_ PVOID pModule,
        _In_ PVOID pCode,
        _In_ DWORD dwCodeSize,
        OUT PDWORD pdwBeginRva
    );
    DWORD ResolveFunctionSize(
        _In_ PVOID pModule,
        _In_ PVOID pFunction
    );
}

/* From Context.cpp */
namespace ByoudContext {
    VOID InitializeSpoofContext(
        OUT PBYOUD_CONTEXT pByoudCtx,
        _In_ DWORD dwTechnique,
        _In_ PVOID pTarget
    );
    BOOL CommitSpoofChange(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ PBYOUD_CHANGE pByoudChange
    );
    BOOL TrackCacheNullification(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ ULONG_PTR uAddress,
        _In_ DWORD dwOld
    );
    BOOL TrackPDataProtection(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ PVOID pModule,
        _In_ PVOID pBase,
        _In_ SIZE_T Size,
        _In_ DWORD dwOldProtect
    );
    BOOL TrackInvertedTableCollapse(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ PVOID pModule,
        _In_ ULONG ulOldSize
    );
    BOOL TrackDynamicTableInsertion(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ PRUNTIME_FUNCTION pRuntimeFunction
    );
    BOOL TrackDynamicTableTypeChange(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ PVOID pEntry,
        _In_ DWORD dwOldType
    );
    BOOL TrackShellcodeInjection(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ PVOID pModule,
        _In_ PVOID pAddress,
        _In_ DWORD dwSize
    );
    BOOL RevertAllSpoofChanges(
        _Inout_ PBYOUD_CONTEXT pByoudCtx
    );
}

/* From StackSpoofing.cpp */
namespace StackSpoof {
    BOOL FlushFunctionTableCache(
        OUT PULONG_PTR puAddress,
        OUT PDWORD pdwOld
    );
    BOOL FlushFunctionEntryCache(
        OUT PULONG_PTR puAddress,
        OUT PDWORD pdwOld
    );
    BOOL SuppressPDataAccess(
        _In_ PVOID pModule,
        OUT PDWORD pdwOldProtect
    );
    BOOL RestorePDataAccess(
        _In_ PVOID pModule,
        _In_ DWORD dwOldProtect
    );
    PSHADOWGATE_PARAMS ConstructShadowGateParams(
        _In_ PVOID pFunction,
        _In_ DWORD dwFrameSize,
        _In_ ULONG_PTR Argc,
        _In_ PULONG_PTR pArgv
    );
    PSHADOWGATE_PARAMS ConstructShadowGateParamsVa(
        _In_ PVOID pFunction,
        _In_ DWORD dwFrameSize,
        _In_ ULONG_PTR Argc,
        ...
    );
    BOOL RegisterSpoofedRuntimeFunction(
        _Inout_ PBYOUD_CONTEXT pByoudCtx,
        _In_ PVOID pModule,
        _In_ DWORD dwShcOffset,
        _In_ DWORD dwShcSize,
        _In_ DWORD dwDesired,
        OUT PDWORD pdwActual
    );
    ULONG_PTR ExecuteWithSpoofedStack(
        _In_ PVOID pPayload,
        _In_ DWORD dwPayloadSize
    );
}

/* From Proxy.cpp */
namespace Proxy {
    PVOID WorkItemLoadLibrary(
        _In_ PWSTR LibraryName
    );
    NTSTATUS WorkItemNtProtectVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _Inout_ PSIZE_T RegionSize,
        _In_ ULONG NewProtection,
        OUT PULONG OldProtection
    );
}

#endif /* COMMON.H */