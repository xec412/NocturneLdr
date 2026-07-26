/* Intrinsic.cpp */

#include <Windows.h>

#pragma intrinsic(memset)
#pragma function(memset)
extern void* __cdecl memset(void*, int, size_t);

void* __cdecl memset(void* dest, int val, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    while (count--)
        *p++ = (unsigned char)val;
    return dest;
}