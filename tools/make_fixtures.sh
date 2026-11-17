#!/bin/sh
# Rebuilds the binary test fixtures in tests/data from tests/data/src.
#
# Needs an x86-64 Linux host with gcc and binutils, and the MinGW-w64 cross
# compiler. The fixtures are committed, so this is only for changing them;
# afterwards update the facts tests/test_fixtures.cpp checks.
#
# None of the fixtures contains C runtime code: the ELF executable and the
# PE files are linked with -nostdlib and their own entry points.
#
#   tools/make_fixtures.sh

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
src=$root/tests/data/src
out=$root/tests/data
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

CC=${CC:-gcc}
MINGW_CC=${MINGW_CC:-x86_64-w64-mingw32-gcc}

# ELF executable, dynamically linked against libc and libm, with a build ID
# and a RUNPATH. noseparate-code keeps it to two pages.
"$CC" -Os -fno-ident -fno-asynchronous-unwind-tables -nostdlib \
    -Wl,-z,noseparate-code -Wl,--build-id=sha1 -Wl,--hash-style=gnu \
    -Wl,-rpath,'$ORIGIN/lib' -Wl,--enable-new-dtags \
    "$src/hello_elf.c" -o "$out/hello.elf" -lc -lm
strip --strip-all --remove-section=.comment "$out/hello.elf"

# The same, cut off before its section header table, for the CLI error tests.
head -c 1024 "$out/hello.elf" > "$out/truncated.elf"

# ELF relocatable object with a symbol table.
"$CC" -Os -fno-ident -fno-asynchronous-unwind-tables -c "$src/sample.c" -o "$out/sample.o"
strip --strip-debug --remove-section=.comment "$out/sample.o"

# PE DLL (exports by name, by ordinal only, and a forwarder), the EXE that
# imports from it, and the DLL's source as a COFF object.
"$MINGW_CC" -Os -s -shared -nostdlib -e DllMain -Wl,--no-insert-timestamp \
    "$src/greet.c" "$src/greet.def" -o "$out/greet.dll" \
    -Wl,--out-implib,"$tmp/libgreet.a" -lkernel32
"$MINGW_CC" -Os -s -nostdlib -e start -Wl,--no-insert-timestamp \
    "$src/hello_pe.c" -o "$out/hello.exe" -L"$tmp" -lgreet -lkernel32
"$MINGW_CC" -Os -fno-ident -c "$src/greet.c" -o "$out/greet.obj"

ls -l "$out"
