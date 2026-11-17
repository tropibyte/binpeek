# binpeek

Inspect ELF and PE/COFF executables, shared libraries and object files.

binpeek is a C++20 library and command-line tool that reads ELF (32 and
64-bit, either byte order), PE images (PE32 and PE32+) and COFF object
files from untrusted bytes: headers, sections, segments, symbols, imports
and exports. Every read is bounds-checked and every field is decoded with
the file's byte order; malformed input raises an exception that names the
file offset at fault. Portable standard C++, no dependencies.

```
$ binpeek -i -e greet.dll
greet.dll: PE32+ DLL (Windows CUI), AMD64

Imports from KERNEL32.dll (1 function):
  IAT         Hint  Name
  ----------  ----  --------
  0x00007038  1602  lstrcpyA

Exports from greet.dll (4 entries, ordinal base 1):
  Ordinal  RVA         Name     Forwarder
  -------  ----------  -------  --------------------
        1  0x00001000  add
        2  0x00001004  greet
        3  0x00006060  ExitNow  KERNEL32.ExitProcess
        7  0x00001029

$ binpeek truncated.elf
binpeek: truncated.elf: offset 0x10b8: section header table starts past the end of the file (size 0x400)
```

## Features

- **ELF**: file header (with extended section and program header counts),
  program headers, section headers with names, `.symtab` and `.dynsym`
  (name, value, size, type, binding, visibility, section index, including
  `SHN_XINDEX`), the dynamic section with `DT_NEEDED`, `DT_SONAME`,
  `DT_RPATH` and `DT_RUNPATH`, the `PT_INTERP` interpreter and the GNU build
  ID. Files without section headers are read through their program headers.
- **PE images**: DOS header, COFF file header, optional header (PE32 and
  PE32+) with data directories, the section table, the import directory
  (DLLs; functions by name with hints, or by ordinal) and the export
  directory (named and ordinal-only exports, aliases, forwarders).
- **COFF objects** for x86, x64 and ARM64: sections, including long names
  (`/123` and `//BASE64`) from the string table, and the symbol table.
- **Format detection** from the first bytes.
- **Output**: aligned text tables, or JSON. Names from the file are escaped
  so they cannot put control characters on the terminal or make invalid
  JSON.

## Building

Requirements: CMake 3.20+ and a C++20 compiler (GCC 13+, Clang 17+, MSVC
2022 17.4+; `<format>` is used).

**Linux / macOS**:

```sh
cmake --preset dev          # Debug, warnings as errors (or: release, asan)
cmake --build --preset dev
ctest --preset dev
```

Without presets: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release`,
`cmake --build build -j`, `ctest --test-dir build --output-on-failure`.

**Windows, Visual Studio 2022**: File > Open > Folder, pick the
repository, and choose the `dev` or `release` configure preset (`asan`
and `mingw` are hidden on Windows). Build with Build > Build All and run
the tests from the Test Explorer, or from a Developer Command Prompt:

```bat
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

**Cross build for Windows from Linux**: the `mingw` preset uses MinGW-w64
(`x86_64-w64-mingw32-g++-posix`, from the Debian/Ubuntu `mingw-w64`
package) through `cmake/mingw-w64.cmake`, links the runtime statically,
and runs the tests under Wine (`wine64`, from the `wine64` package):

```sh
cmake --preset mingw && cmake --build --preset mingw && ctest --preset mingw
```

| Option | Default | Meaning |
| --- | --- | --- |
| `BINPEEK_BUILD_TESTS` | ON when top-level | doctest unit tests and CLI smoke tests |
| `BINPEEK_BUILD_CLI` | ON when top-level | the `binpeek` tool |
| `BINPEEK_BUILD_EXAMPLES` | ON when top-level | `binpeek_list_deps` (see `examples/`) |
| `BINPEEK_WARNINGS_AS_ERRORS` | OFF | `-Werror` / `/WX` |
| `BINPEEK_SANITIZE` | OFF | AddressSanitizer + UBSan (GCC/Clang) |

## Command line

```
binpeek [options] FILE...

  -H, --headers    file header; for ELF also the interpreter, build ID and
                   dynamic section; for PE the DOS, COFF and optional headers
  -S, --sections   section table
  -l, --segments   program headers (ELF)
  -s, --symbols    symbol table (ELF .symtab, COFF symbol table)
      --dyn-syms   dynamic symbol table (ELF .dynsym)
  -i, --imports    needed libraries and imported symbols (ELF), import table (PE)
  -e, --exports    exported dynamic symbols (ELF), export table (PE)
  -a, --all        all of the above
  -j, --json       write JSON instead of text
  -h, --help       show this help
  -V, --version    show the version
```

With no part selected, `--headers` is shown. Short options combine (`-HS`).
Exit status is 0 on success, 1 when a file cannot be read or is malformed
(the other files are still processed), and 2 for usage errors. With
`--json`, one file gives one object and several files an array; a file
that fails becomes `{"file": ..., "error": ..., "offset": ...}`.

```
$ binpeek tests/data/hello.elf
tests/data/hello.elf: ELF64 little-endian DYN (shared object or PIE), x86-64

File header:
  Class:            ELF64
  Data:             little-endian
  Version:          1
  OS/ABI:           SYSV (0)
  ABI version:      0
  Type:             DYN (shared object or PIE)
  Machine:          x86-64 (62)
  Entry point:      0x4a0
  Flags:            0x0
  Header size:      64 bytes
  Program headers:  10 at 0x40, 56 bytes each
  Section headers:  19 at 0x10b8, 64 bytes each
  Section names:    18 (.shstrtab)
  Interpreter:      /lib64/ld-linux-x86-64.so.2
  Build ID:         30c43ff9837bd7d0277bc434135c38702852faab
  Needed:           libc.so.6
  Needed:           libm.so.6
  RUNPATH:          $ORIGIN/lib

Dynamic section (18 entries):
  Tag               Type        Value
  ----------------  ----------  -------------
  0000000000000001  NEEDED      [libc.so.6]
  0000000000000001  NEEDED      [libm.so.6]
  000000000000001d  RUNPATH     [$ORIGIN/lib]
  ...

$ binpeek -i tests/data/hello.elf
tests/data/hello.elf: ELF64 little-endian DYN (shared object or PIE), x86-64

Needed libraries (2):
  libc.so.6
  libm.so.6

Library search paths:
  RUNPATH:  $ORIGIN/lib

Imported symbols (3):
  Type  Bind    Name
  ----  ------  ----
  FUNC  GLOBAL  puts
  FUNC  GLOBAL  exit
  FUNC  GLOBAL  sqrt

$ binpeek -S tests/data/greet.obj
tests/data/greet.obj: COFF object, AMD64

Sections (7):
  Nr  Name             VirtSize  VirtAddr  RawSize   RawPtr    Relocs  Perm  Characteristics
  --  ---------------  --------  --------  --------  --------  ------  ----  -------------------------------------------
   1  .text            00000000  00000000  00000040  0000012c       3  R-X   0x60500020 CODE ALIGN_16BYTES
   2  .data            00000000  00000000  00000000  00000000       0  RW-   0xc0500040 INITIALIZED_DATA ALIGN_16BYTES
   3  .bss             00000000  00000000  00000040  00000000       0  RW-   0xc0600080 UNINITIALIZED_DATA ALIGN_32BYTES
   4  .xdata           00000000  00000000  00000014  0000016c       0  R--   0x40300040 INITIALIZED_DATA ALIGN_4BYTES
   5  .pdata           00000000  00000000  00000030  00000180      12  R--   0x40300040 INITIALIZED_DATA ALIGN_4BYTES
   6  .rdata$greeting  00000000  00000000  00000010  000001b0       0  R--   0x40500040 INITIALIZED_DATA ALIGN_16BYTES
   7  .drectve         00000000  00000000  00000020  000001c0       0  RW-   0xc0300040 INITIALIZED_DATA ALIGN_4BYTES

$ binpeek --json -i tests/data/hello.exe
{
  "file": "tests/data/hello.exe",
  "format": "PE",
  "description": "PE32+ executable (Windows CUI), AMD64",
  "imports": [
    {
      "dll": "greet.dll",
      "lookup_table_rva": 20544,
      "address_table_rva": 20616,
      "timestamp": 0,
      "forwarder_chain": 0,
      "functions": [
        {
          "name": "add",
          "hint": 1,
          "iat_rva": 20616
        },
        ...
```

## Using the library

```cpp
#include "binpeek/binpeek.hpp"

const std::vector<std::byte> data = binpeek::read_file("app.exe");
try {
    const binpeek::ParsedFile file = binpeek::parse(data);
    if (const auto* pe = std::get_if<binpeek::pe::PeFile>(&file)) {
        for (const auto& dll : pe->imports) std::cout << dll.name << '\n';
    } else if (const auto* elf = std::get_if<binpeek::elf::ElfFile>(&file)) {
        for (const auto& lib : elf->needed) std::cout << lib << '\n';
    }
} catch (const binpeek::FormatError& e) {
    std::cerr << "malformed at offset " << e.offset() << ": " << e.message() << '\n';
}
```

Link against `binpeek::binpeek`. `parse()` takes any
`std::span<const std::byte>`; `elf::parse_elf()`, `pe::parse_pe()` and
`pe::parse_coff_object()` parse one format. `ParseOptions` selects the
optional parts (symbols, dynamic section, imports, exports) so that a
caller who wants only the sections neither pays for nor fails on the rest.
Results own their strings and do not refer to the input afterwards.
`write_text()` and `write_json()` (`binpeek/report.hpp`) produce the
command-line tool's output. `examples/list_deps.cpp` is a complete program.

## Limitations

- **Strict by design.** A header, section or segment that claims bytes past
  the end of the file is an error, even where a loader might cope, so a
  truncated file is rejected rather than partially shown. Each optional part
  is validated only when requested (`ParseOptions`, or the command-line
  options), so `binpeek -S` still lists the sections of a file whose import
  table is damaged.
- **Whole files in memory.** Input is read into memory (or supplied as a
  span); there is no streaming or memory mapping.
- **Names are not demangled**, and ELF symbol versions (`.gnu.version*`) are
  not decoded: `puts`, not `puts@GLIBC_2.2.5`.
- **No relocations, debug information or resources.** Relocation sections
  and base relocations, DWARF and PDB data, and the PE resource, security,
  exception, TLS, load-config and delay-import directories are listed as
  sections or data directories but not decoded. The PE checksum and
  Authenticode signatures are not verified.
- **Dynamic symbols need section headers.** Without them, the dynamic
  section, interpreter and build ID are still read through the program
  headers, but `.dynsym` is not (its size is only recorded in the hash
  tables).
- **PE details.** Images whose sections overlap in memory are rejected when
  imports or exports are requested. Bound imports whose lookup table was
  dropped (`OriginalFirstThunk` 0 with addresses in the IAT) cannot be
  decoded. `NumberOfRvaAndSizes` larger than the optional header holds is an
  error, where the Windows loader ignores the excess. Unused export slots
  (RVA 0, no name) are left out. Only the GNU build-ID note is decoded.
- **COFF objects** are recognized for x86, x64 and ARM64 only; `/bigobj`
  objects and short import-library members are not supported. Auxiliary
  symbol records are counted but not decoded.
- **Output limits.** Names copied out of one file are capped in total at
  1 MiB plus four times the file size (`ParseOptions::max_string_bytes`), so
  thousands of records naming one long string cannot multiply the output.
  In JSON, bytes that are not UTF-8 become U+FFFD; in text they are written
  as `\xNN`.

## Project layout

```
include/binpeek/   public headers; binpeek.hpp includes them all
src/               byte access, ELF, PE/COFF, display names, text and JSON reports
tools/             the binpeek command-line tool, fixture and oracle scripts
tests/             doctest unit tests, the test image builder, CLI smoke tests
tests/data/        small ELF, PE and COFF fixtures, and their sources
examples/          a small program using the library
cmake/             the MinGW-w64 toolchain file
docs/              architecture notes
third_party/       doctest (MIT), used only by the tests
```

`tools/make_fixtures.sh` rebuilds the fixtures in `tests/data` (gcc and
MinGW-w64). `tools/compare_oracle.sh` checks binpeek against `readelf` and
`llvm-readobj` on system binaries and the fixtures (Linux only, not part of
`ctest`).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [ROADMAP.md](ROADMAP.md) and
[CHANGELOG.md](CHANGELOG.md).

## License

MIT. Copyright (c) 2026 Tropibyte, Inc. See [LICENSE](LICENSE).
doctest is MIT-licensed; see `third_party/doctest/LICENSE.txt`.
