/* IatCamouflage.h */
#pragma once

#include <Windows.h>
#include "Structs.h"
#include "Primitives.h"
#include "Common.h"

/*================================================
@ CompileTimeSeed Function
================================================*/
int RandomCompileTimeSeed(void) {

    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

/*================================================
@ AllocateDummyBuffer Function
================================================*/
PVOID AllocateDummyBuffer(
    PVOID* ppAddress
) {
    PVOID Address = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
    if (!Address)
        return nullptr;

    *(int*)Address = RandomCompileTimeSeed() % 0xFF;
    
    *ppAddress = Address;
    return Address;
}

/*================================================
@ IatCamouflage Function
================================================*/
VOID IatCamouflage() {

    PVOID                               Address             = nullptr;
    int*                                X                   = (int*)AllocateDummyBuffer(&Address);

    if (*X > 350) {

        unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
        i = SetCriticalSectionSpinCount(NULL, NULL);
        i = GetWindowContextHelpId(NULL);
        i = GetWindowLongPtrW(NULL, NULL);
        i = RegisterClassW(NULL);
        i = IsWindowVisible(NULL);
        i = ConvertDefaultLocale(NULL);
        i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
        i = IsDialogMessageW(NULL, NULL);
    }

    Macro::DeletePtr(Address);
}