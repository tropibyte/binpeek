/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Tropibyte, Inc.
 *
 * Source of tests/data/hello.exe. Built without the C runtime; start is the
 * entry point. Imports add and greet by name and secret by ordinal from
 * greet.dll, and four functions from KERNEL32.dll.
 */

#include <windows.h>

__declspec(dllimport) int add(int a, int b);
__declspec(dllimport) const char* greet(void);
__declspec(dllimport) int secret(void);

void start(void) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const char* text = greet();
    DWORD written = 0;
    WriteFile(out, text, (DWORD)lstrlenA(text), &written, NULL);
    ExitProcess((UINT)(add(1, 2) + secret()));
}
