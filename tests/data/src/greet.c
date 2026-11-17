/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Tropibyte, Inc.
 *
 * Source of tests/data/greet.dll (with greet.def) and tests/data/greet.obj.
 * Built without the C runtime; DllMain is the entry point.
 */

#include <windows.h>

static char buffer[64];

/* A section name longer than eight bytes: in the object file it is stored
 * in the COFF string table and the section header holds "/nn". */
__attribute__((section(".rdata$greeting"))) const char greeting[] = "hello";

__declspec(dllexport) int add(int a, int b) { return a + b; }

__declspec(dllexport) const char* greet(void) {
    lstrcpyA(buffer, greeting);
    return buffer;
}

int secret(void) { return 42; }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
