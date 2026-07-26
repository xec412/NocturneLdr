/* Primivites.h */
#pragma once

/* HEADER GUARD */
#ifndef PRIMIVITES_H
#define PRIMIVITES_H

#include <Windows.h>
#include "Structs.h"

/*==================================================
@ ExprHashStrDjb2 Function
# Hashes the provided string via djb2 algorithm
# at compile time. Supports both ANSI & UNICODE
====================================================*/
namespace Hash {
    template <typename T> struct CleanType;
    template <typename T> struct CleanType<T*> { using type = T; };
    template <typename T> struct CleanType<const T*> { using type = T; };

    template <typename T>
    constexpr ULONG ExprHashStrDjb2(_In_ T StringToHash) {

        ULONG           Hash = 5448;
        ULONG           Seed = 7;
        constexpr auto  XorKey = 0x1337u;

        using CharType = typename CleanType<T>::type;
        CharType Char = 0;

        if (!StringToHash) {
            return 0;
        }

        while ((Char = *StringToHash++) != 0) {

            /* Convert current character to uppercase */
            if (Char >= 'a' && Char <= 'z') {
                Char -= 0x20;
            }

            /* Append Hash */
            Hash = ((Hash << Seed) + Hash) + Char;
        }

        return Hash ^ XorKey;
    }
}

/*==================================================
@ CRT (C Runtime Library) Function Replacements
====================================================*/
namespace Primitive {

    /* memcpy */
    inline VOID MemoryCopy(_In_ PVOID pDestination, _In_ PVOID pSource, _In_ SIZE_T sSize) {

        PBYTE D = (PBYTE)pDestination;
        PBYTE S = (PBYTE)pSource;

        while (sSize--) {
            *D++ = *S++;
        }
    }

    /* memset */
    inline PVOID MemorySet(_In_ PVOID pDestination, _In_ INT iValue, _In_ SIZE_T sCount) {

        PBYTE D = (PBYTE)pDestination;

        while (sCount--) {

            *D = (BYTE)iValue;
            D++;
        }

        return pDestination;
    }

    /* strlen (Supports both ANSI & UNICODE) */
    template <typename T>
    inline SIZE_T StringLength(_In_ T String) {

        auto Ptr = String;

        if (!String) return 0;

        while (*Ptr) {
            Ptr++;
        }

        return (SIZE_T)(Ptr - String);
    }

    /* memcmp */
    inline INT MemoryCompare(_In_ const VOID* Ptr1, _In_ const VOID* Ptr2, _In_ SIZE_T Num) {

        const unsigned char* P1 = (const unsigned char*)Ptr1;
        const unsigned char* P2 = (const unsigned char*)Ptr2;

        while (Num--) {
            if (*P1 != *P2)
                return *P1 - *P2;
            P1++;
            P2++;
        }

        return 0;
    }

    /* strrchr */
    inline PCHAR StringFindLastChar(_In_ PCHAR String, _In_ INT Char) {

        PCHAR Last = nullptr;

        if (!String) return nullptr;

        while (*String) {
            if (*String == (CHAR)Char)
                Last = String;
            String++;
        }

        return Last;
    }

    /* Other Helpers */
    inline VOID WideToAnsi(_In_ PWSTR Wide, OUT PCSTR Ansi, _In_ SIZE_T MaxCount) {

        if (!Wide || !Ansi || !MaxCount)
            return;

        SIZE_T Index = 0;

        while (Wide[Index] != L'\0' && Index < (MaxCount - 1)) {

            ((PCHAR)Ansi)[Index] = ((CHAR)Wide[Index]);
            Index++;
        }

        ((PCHAR)Ansi)[Index] = '\0';
    }

    inline VOID AnsiToWide(_In_ PCSTR Ansi, OUT PWSTR Wide, _In_ SIZE_T MaxCount) {

        if (!Ansi || !Wide || !MaxCount)
            return;

        SIZE_T Index = 0;

        while (Ansi[Index] != '\0' && Index < (MaxCount - 1)) {

            Wide[Index] = (WCHAR)Ansi[Index];
            Index++;
        }

        Wide[Index] = L'\0';
    }
}

inline void* operator new(size_t size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

inline void operator delete(void* ptr) noexcept {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

inline void operator delete(void* ptr, size_t) noexcept {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

/*==================================================
@ Macros to provide better readability for the reader
====================================================*/
namespace Macro {

    template <typename T>
    inline VOID DeleteHandle(T& H) {
        if (H && H != INVALID_HANDLE_VALUE) {
            CloseHandle(H);
            H = nullptr;
        }
    }

    template <typename T>
    inline VOID DeletePtr(T& PTR) {
        if (PTR != nullptr) {
            HeapFree(GetProcessHeap(), 0, PTR);
            PTR = nullptr;
        }
    }
}

#endif // PRIMIVITES_H
