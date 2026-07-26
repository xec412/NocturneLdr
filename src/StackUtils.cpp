/* StackUtils.cpp */
#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Primitives.h"
#include "Debug.h"

/*================================================
@ ResolveThreadStackOrigin Function
# Combines the resolver and stack scanner to
# calculate the required stack frame size for
# stack spoofing. Locates BaseThreadInitThunk,
# finds its internal CALL offset, then scans
# the stack for that return address
================================================*/
ULONG_PTR StackUtils::ResolveThreadStackOrigin(
    OUT PULONG_PTR puStackPointer
) {
    /* Find BTIT address */
    PVOID Btit = Resolver::LdrGetSymbolByHash(Resolver::LdrGetModuleByHash(Hash::ExprHashStrDjb2(L"kernel32.dll")), Hash::ExprHashStrDjb2("BaseThreadInitThunk"));
    if (Btit == nullptr) {
#ifdef DEBUG
        DBGPRINT("[-] BTIT Return Address Not Found - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return 0;
    }

    /* Find offset of the call instruction inside BTIT */
    DWORD CallOffset = Resolver::LocateCallInstructionOffset((ULONG_PTR)Btit, 0x100);

    /* Search the stack for the return address */
    ULONG_PTR StackSpace = ScanStackForValue(
        (ULONG_PTR)Btit + CallOffset,
        puStackPointer
    );

#ifdef DEBUG
    DBGPRINT("[i] BTIT Return Address Found -> 0x%Ix \n", StackSpace);
#endif
    return StackSpace;
}

/*================================================
@ DetectStackCookiePresence Function
# Checks whether the given module was compiled
# with /GS by inspecting the SecurityCookie field
# in the PE's Load Configuration Directory
================================================*/
BOOL StackUtils::DetectStackCookiePresence(
    _In_ PVOID pModule
) {
    auto Nt = (PIMAGE_NT_HEADERS)((PBYTE)pModule + ((PIMAGE_DOS_HEADER)pModule)->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    auto LcDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!LcDir->VirtualAddress || !LcDir->Size)
        return FALSE;

    auto Lc = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PBYTE)pModule + LcDir->VirtualAddress);
    return Lc->SecurityCookie != 0;
}