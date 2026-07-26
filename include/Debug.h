/* Debug.h */
#pragma once

#include <Windows.h>

/* Comment the following line in order to disable debug mode */
#define DEBUG

#ifdef DEBUG

VOID CreateDebugConsole();

#define ERROR_BUF_SIZE          (MAX_PATH * 2)
#define GET_FILENAME(Path) \
    (Primitive::StringFindLastChar((PCHAR)Path, '\\') ? \
     Primitive::StringFindLastChar((PCHAR)Path, '\\') + 1 : (PCHAR)Path)

#define DBGPRINT(STR, ...)                                                                                                      \
    if (1) {                                                                                                                    \
        LPSTR cBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUF_SIZE);                                   \
        if (cBuffer){                                                                                                           \
            int Length = wsprintfA(cBuffer, STR, __VA_ARGS__);                                                                  \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, Length, nullptr, nullptr);                                  \
            HeapFree(GetProcessHeap(), 0, cBuffer);                                                                             \
        }                                                                                                                       \
    }

#endif // DEBUG