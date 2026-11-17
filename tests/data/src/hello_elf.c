/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Tropibyte, Inc.
 *
 * Source of tests/data/hello.elf. Linked without the C runtime's start
 * files: _start is the entry point and calls into libc and libm directly.
 */

int puts(const char* s);
double sqrt(double x);
void exit(int status);

int counter = 3;
static const char message[] = "hello from binpeek";

__attribute__((force_align_arg_pointer, noreturn)) void _start(void) {
    puts(message);
    exit((int)sqrt((double)(counter * counter)));
}
