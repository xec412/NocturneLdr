/* Resolver.cpp */
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"
#include "Primitives.h"

/*================================================
@ LdrGetModuleByHash Function
# Walks the PEB loader list and returns the base
# address of the module matching the given hash
================================================*/
PVOID Resolver::LdrGetModuleByHash(
    _In_ ULONG uModuleHash
) {
    PLDR_DATA_TABLE_ENTRY                       DataTableEntry                  = nullptr;
    PLIST_ENTRY                                 Head                            = nullptr;
    PLIST_ENTRY                                 Entry                           = nullptr;

    /* Get pointer to the list */
    Head        = &NtCurrentTeb()->ProcessEnvironmentBlock->LoaderData->InLoadOrderModuleList;
    Entry       = Head->Flink;

    /* Return the handle of local exe image if no hash is given */
    if (!uModuleHash) {
        DataTableEntry = (PLDR_DATA_TABLE_ENTRY)(Entry);
        return DataTableEntry->DllBase;
    }

    /* Iterate through module list */
    for (; Head != Entry; Entry = Entry->Flink) {

        DataTableEntry = (PLDR_DATA_TABLE_ENTRY)(Entry);

        /* Check if hashes match */
        if (Hash::ExprHashStrDjb2(DataTableEntry->BaseDllName.Buffer) == uModuleHash)
            return DataTableEntry->DllBase;
    }

#ifdef DEBUG
    DBGPRINT("[-] LdrGetModuleByHash Failed At Hash -> 0x%0.8X - %s.%d \n", uModuleHash, GET_FILENAME(__FILE__), __LINE__);
#endif
    return nullptr;
}

/*================================================
@ LdrGetSymbolByHash Function
# Parses the export directory of the given module
# and returns the address of the export matching
# the provided hash. Handles forwarded exports
# recursively via WorkItemProxyLoadLibrary
================================================*/
PVOID Resolver::LdrGetSymbolByHash(
    _In_ PVOID pModule,
    _In_ ULONG uFunctionHash
) {
    if (!pModule || !uFunctionHash) {
#ifdef DEBUG
        DBGPRINT("[-] LdrGetSymbolByHash Failed At Hash -> 0x%0.8X - %s.%d \n", uFunctionHash, GET_FILENAME(__FILE__), __LINE__);
#endif
        return nullptr;
    }

    //-------------------------------------------------------------------------

    /* Avoid casting to PBYTE each time */
    PBYTE BaseAddress = (PBYTE)pModule;

    /* Fetch the NT headers and do a signature check */
    auto Nt = (PIMAGE_NT_HEADERS)(BaseAddress + ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    /* Fetch the export cirectory and the size of it */
    auto ExportDirectory        = (PIMAGE_EXPORT_DIRECTORY)(BaseAddress + Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto ExportSize             = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    /* Fetch the function's name & address & ordinal pointers */
    auto AddressOfFunctions     = (PDWORD)(BaseAddress + ExportDirectory->AddressOfFunctions);
    auto AddressOfNames         = (PDWORD)(BaseAddress + ExportDirectory->AddressOfNames);
    auto AddressOfOrdinals      = (PWORD)(BaseAddress + ExportDirectory->AddressOfNameOrdinals);
    
    /* Iterate through exported functions */
    for (int i = 0; i < ExportDirectory->NumberOfNames; i++) {

        PCHAR FunctionName          = (PCHAR)(BaseAddress + AddressOfNames[i]);
        PVOID FunctionVA            = (PVOID)(BaseAddress + AddressOfFunctions[AddressOfOrdinals[i]]);

        /* Check if hashes match */
        if (Hash::ExprHashStrDjb2(FunctionName) == uFunctionHash) {

            /* Handle forwarded functions */
            ULONG_PTR               FunctionAddress             = (ULONG_PTR)FunctionVA;
            ULONG_PTR               ExportBeginning             = (ULONG_PTR)ExportDirectory;
            ULONG_PTR               ExportEnd                   = ExportBeginning + ExportSize;

            if (FunctionAddress >= ExportBeginning && FunctionAddress < ExportEnd) {
#ifdef DEBUG
                DBGPRINT("[i] LdrGetSymbolByHash -> [%s] Is A Forwarded Function \n", FunctionName);
#endif
                CHAR                Forwarder[MAX_PATH]         = { 0 };
                WCHAR               WidePath[MAX_PATH]          = { 0 };
                DWORD               Offset                      = 0;
                PCHAR               PFunctionMod                = nullptr;
                PCHAR               PFunctionName               = nullptr;

                Primitive::MemoryCopy(Forwarder, (PVOID)FunctionAddress, Primitive::StringLength((PCHAR)FunctionAddress));

                for (DWORD j = 0; j < Primitive::StringLength((PCHAR)Forwarder); j++) {

                    if (((PCHAR)Forwarder)[j] == '.') {

                        Offset              = j;
                        Forwarder[j]        = '\0';
                        break;
                    }
                }

                PFunctionMod    = Forwarder;
                PFunctionName   = Forwarder + Offset + 1;

                /* Convert ansi name to unicode */
                Primitive::AnsiToWide(PFunctionMod, WidePath, MAX_PATH);
                PVOID ForwardedMod = Proxy::WorkItemLoadLibrary(WidePath);

                return LdrGetSymbolByHash(ForwardedMod, Hash::ExprHashStrDjb2(PFunctionName));
            }

            /* If it's not a forwarded function, return the address directly */
            return (FARPROC)FunctionAddress;
        }
    }

#ifdef DEBUG
    DBGPRINT("[-] LdrGetSymbolByHash Failed At Hash -> 0x%0.8X - %s.%d \n", uFunctionHash, GET_FILENAME(__FILE__), __LINE__);
#endif
    return nullptr;
}

/*================================================
@ ResolveSectionInfo Function
# Parses the PE section headers of the given module
# and fills pSectionInfo with the virtual address
# and size of the section matching pcSectionName
================================================*/
VOID Resolver::ResolveSectionInfo(
    _In_ PVOID pModule,
    _In_ PCHAR pcSectionName,
    OUT PSECTION_INFO pSectionInfo
) {
    if (!pModule || !pcSectionName || !pSectionInfo)
        return;

    /* Fetch the NT headers and do a signature check */
    auto Nt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + ((PIMAGE_DOS_HEADER)pModule)->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE)
        return;

    /* Get section header and the length of section name */
    auto        SectionHeader       = IMAGE_FIRST_SECTION(Nt);
    SIZE_T      NameLength          = Primitive::StringLength(pcSectionName);

    /* Iterate through PE sections */
    for (int i = 0; i < Nt->FileHeader.NumberOfSections; i++, SectionHeader++) {

        if (Primitive::MemoryCompare(SectionHeader->Name, (PCHAR)pcSectionName, NameLength) == 0) {
            pSectionInfo->VirtualAddress            = (PVOID)((PBYTE)pModule + SectionHeader->VirtualAddress);
            pSectionInfo->VirtualSize               = SectionHeader->Misc.VirtualSize;
            return;
        }
    }

    return;
}

/*================================================
@ ResolvePDataSectionInfo Function
# Wrapper around ResolveSectionInfo that resolves
# the .pdata (exception handler table) section
================================================*/
VOID Resolver::ResolvePDataSectionInfo(
    _In_ PVOID pModule,
    OUT PSECTION_INFO pSectionInfo
) {
    const CHAR SectionName[] = { '.', 'p', 'd', 'a', 't', 'a', '\0' };
    Resolver::ResolveSectionInfo(pModule, (PCHAR)SectionName, pSectionInfo);
}

/*================================================
@ ResolveTextSectionInfo Function
# Wrapper around ResolveSectionInfo that resolves
# the .text section
================================================*/
VOID Resolver::ResolveTextSectionInfo(
    _In_ PVOID pModule,
    OUT PSECTION_INFO pSectionInfo
) {
    const CHAR SectionName[] = { '.', 't', 'e', 'x', 't', '\0' };
    Resolver::ResolveSectionInfo(pModule, (PCHAR)SectionName, pSectionInfo);
}

/*================================================
@ ResolveExceptionDirectory Function
# Returns the base address and size of the module's
# exception directory (IMAGE_DIRECTORY_ENTRY_EXCEPTION)
# Used to locate and iterate RUNTIME_FUNCTION entries
================================================*/
PVOID Resolver::ResolveExceptionDirectory(
    _In_ PVOID pModule,
    OUT PDWORD pdwDirSize
) {
    if (!pModule || !pdwDirSize)
        return nullptr;

    auto Nt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + ((PIMAGE_DOS_HEADER)pModule)->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    auto ExceptionDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    *pdwDirSize = ExceptionDir->Size;

    return (PVOID)((PBYTE)pModule + ExceptionDir->VirtualAddress);
}

/*================================================
@ LocateCallInstructionOffset Function
# Scans forward from uStartAddress looking for the
# first CALL instruction (near, indirect or REX-prefixed)
# Returns the offset to the instruction immediately
# following the CALL, i.e. the return address that
# would be pushed onto the stack
================================================*/
DWORD Resolver::LocateCallInstructionOffset(
    _In_ ULONG_PTR uStartAddress,
    _In_ DWORD dwSearchLimit
) {
    DWORD                                   Offset                  = 0;
    DWORD                                   CallOffset              = 0;
    DWORD                                   StaticOffset            = 4; /* Size of call instruction */
    BOOL                                    Found                   = FALSE;

    while (Offset < dwSearchLimit) {

        /*
           0xE8         = CALL rel32            (direct near call,        1-byte opcode)
           0xFF15       = CALL [RIP+rel32]       (indirect near call,      2-byte opcode)
           0x48FF15     = REX.W CALL [RIP+rel32] (REX-prefixed indirect,   3-byte opcode)
       */
        if (*(PBYTE)(uStartAddress + Offset) == CALL_NEAR || *(PWORD)(uStartAddress + Offset) == CALL_NEAR_QPTR || (*(PDWORD)(uStartAddress + Offset) & 0x00ffffff) == CALL_FAR_QPTR) {

            /* Adjust CallOffset based on opcode length */
            if ((*(PDWORD)(uStartAddress + Offset) & 0x00ffffff) == CALL_FAR_QPTR)
                CallOffset += 3;
            else if (*(PWORD)(uStartAddress + Offset) == CALL_NEAR_QPTR)
                CallOffset += 2;
            else
                CallOffset++;

            Found = TRUE;
            break;
        }

        Offset++;
    }

    return Found ? (Offset + StaticOffset + CallOffset) : 0;
}