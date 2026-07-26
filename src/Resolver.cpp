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

PVOID FindShieldGadget(
) {
    ULONG_PTR                       Memory              = { 0 };
    BYTE                            Pattern[]           = {
                                                    0x48, 0x8B,
                                                    0x00, 0xC3
    };

    Memory = (ULONG_PTR)Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"ntdll.dll")) + 0x1000;
    
    for (ULONG_PTR Len = 0; Len < 0x1000 * 0x1000; Len++) {
        if (Primitive::MemoryCompare((PVOID)(Memory + Len), Pattern, sizeof(Pattern)) == 0) {
            return (PVOID)(Memory + Len);
        }
    }

    return nullptr;
}

/*================================================
@ LdrGetSymbolByHash Function
# Parses the export directory of the given module
# and returns the address of the export matching
# the provided hash. Handles forwarded exports
# recursively via WorkItemProxyLoadLibrary
================================================*/
PVOID Resolver::LdrShieldedSymbolResolveByHash(
    _In_ PVOID pModule,
    _In_ ULONG uFunctionHash
) {
    if (!pModule || !uFunctionHash) {
#ifdef DEBUG
        DBGPRINT("[-] LdrShieldedSymbolResolveByHash Failed At Hash -> 0x%0.8X - %s.%d \n", uFunctionHash, GET_FILENAME(__FILE__), __LINE__);
#endif
        return nullptr;
    }

    PVOID Gadget = FindShieldGadget();
    if (!Gadget)
        return nullptr;

    PBYTE BaseAddress = (PBYTE)pModule;

    auto Nt = (PIMAGE_NT_HEADERS)(BaseAddress + (DWORD)ShieldedRead((ULONG_PTR) & ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew, (ULONG_PTR)Gadget));
    if ((DWORD)ShieldedRead((ULONG_PTR)&Nt->Signature, (ULONG_PTR)Gadget) != IMAGE_NT_SIGNATURE)
        return nullptr;

    auto ExportRva = (DWORD)ShieldedRead((ULONG_PTR)&Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, (ULONG_PTR)Gadget);
    auto ExportSize = (DWORD)ShieldedRead((ULONG_PTR)&Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, (ULONG_PTR)Gadget);

    auto ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(BaseAddress + ExportRva);
    auto AddressOfFunctions = (PDWORD)(BaseAddress + (DWORD)ShieldedRead((ULONG_PTR)&ExportDirectory->AddressOfFunctions, (ULONG_PTR)Gadget));
    auto AddressOfNames = (PDWORD)(BaseAddress + (DWORD)ShieldedRead((ULONG_PTR)&ExportDirectory->AddressOfNames, (ULONG_PTR)Gadget));
    auto AddressOfOrdinals = (PWORD)(BaseAddress + (DWORD)ShieldedRead((ULONG_PTR)&ExportDirectory->AddressOfNameOrdinals, (ULONG_PTR)Gadget));
    auto NumberOfNames = (DWORD)ShieldedRead((ULONG_PTR)&ExportDirectory->NumberOfNames, (ULONG_PTR)Gadget);

    for (DWORD i = 0; i < NumberOfNames; i++) {

        DWORD NameRva = (DWORD)ShieldedRead((ULONG_PTR)&AddressOfNames[i], (ULONG_PTR)Gadget);
        PCHAR FunctionName = (PCHAR)(BaseAddress + NameRva);

        if (Hash::ExprHashStrDjb2(FunctionName) == uFunctionHash) {

            WORD  Ordinal = (WORD)ShieldedRead((ULONG_PTR)&AddressOfOrdinals[i], (ULONG_PTR)Gadget);
            DWORD FuncRva = (DWORD)ShieldedRead((ULONG_PTR)&AddressOfFunctions[Ordinal], (ULONG_PTR)Gadget);
            PVOID FunctionVA = (PVOID)(BaseAddress + FuncRva);

            ULONG_PTR FunctionAddress = (ULONG_PTR)FunctionVA;
            ULONG_PTR ExportBeginning = (ULONG_PTR)ExportDirectory;
            ULONG_PTR ExportEnd = ExportBeginning + ExportSize;

            if (FunctionAddress >= ExportBeginning && FunctionAddress < ExportEnd) {
#ifdef DEBUG
                DBGPRINT("[i] LdrShieldedSymbolResolveByHash -> [%s] Is A Forwarded Function \n", FunctionName);
#endif
                CHAR                    Forwarder[MAX_PATH]             = { 0 };
                WCHAR                   WidePath[MAX_PATH]              = { 0 };
                DWORD                   Offset                          = 0;
                PCHAR                   PFunctionMod                    = nullptr;
                PCHAR                   PFunctionName                   = nullptr;

                Primitive::MemoryCopy(Forwarder, (PVOID)FunctionAddress, Primitive::StringLength((PCHAR)FunctionAddress));

                for (DWORD j = 0; j < Primitive::StringLength((PCHAR)Forwarder); j++) {
                    if (((PCHAR)Forwarder)[j] == '.') {
                        Offset = j;
                        Forwarder[j] = '\0';
                        break;
                    }
                }

                PFunctionMod            = Forwarder;
                PFunctionName           = Forwarder + Offset + 1;

                Primitive::AnsiToWide(PFunctionMod, WidePath, MAX_PATH);
                PVOID ForwardedMod = Proxy::WorkItemLoadLibrary(WidePath);

                return LdrShieldedSymbolResolveByHash(ForwardedMod, Hash::ExprHashStrDjb2(PFunctionName));
            }

            return (FARPROC)FunctionAddress;
        }
    }

#ifdef DEBUG
    DBGPRINT("[-] LdrShieldedSymbolResolveByHash Failed At Hash -> 0x%0.8X - %s.%d \n", uFunctionHash, GET_FILENAME(__FILE__), __LINE__);
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