/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Tropibyte, Inc.
 *
 * Source of tests/data/sample.o: a relocatable object with global, weak,
 * hidden and local symbols and an undefined reference.
 */

int puts(const char* s);

int counter = 3;
static int total;

__attribute__((visibility("hidden"))) int helper(int x) { return x + total; }

__attribute__((weak)) int fallback(void) { return -1; }

int greet(const char* who) {
    total += counter;
    puts(who);
    return helper(counter) + fallback();
}
