# binpeek architecture

```
bytes ─► detect_format ─► elf::parse_elf ─────────┐
  │                       pe::parse_pe ───────────┼─► ParsedFile ─► write_text / write_json
  │                       pe::parse_coff_object ──┘   (variant)      (report.cpp, report_*.cpp)
  └─ ByteView / Cursor / StringTable: every read bounds-checked, FormatError(offset, ...)
```

## Reading untrusted bytes

All parsing goes through `ByteView` (`bytes.hpp`), a span over the whole
file with 64-bit offsets. Its rules:

- Every access names a file offset and a length and is checked with
  `contains()`, written so that `offset + length` cannot overflow.
  Arrays are checked with `require_array()`, which also rejects counts
  whose total size overflows 64 bits (an ELF64 extended section count of
  2^58 + 1, say).
- Multi-byte fields are decoded byte by byte in the file's byte order
  (`Cursor` carries it). Nothing is `reinterpret_cast` onto the buffer as a
  struct, so alignment, padding and host byte order never matter. The only
  casts are `std::byte*` to `const char*` for viewing strings.
- Strings come from a `StringTable`, a bounded window of the file: a string
  that has no NUL before the window ends is an error, not a read into the
  next structure.
- Errors are `FormatError(offset, message)`. The offset is that of the
  structure or field at fault: the start of a table that does not fit, the
  section header whose range is bad, or the `e_lfanew` field that points
  nowhere.

Two budgets keep the work proportional to the input, so a small file
cannot make the parser allocate or loop without bound:

- `detail::StringBudget` charges every name copied out of a file (1 MiB
  plus four times the file size by default). Thousands of symbols that
  all name one long string would otherwise multiply the output.
- Counts are only trusted after the table they describe has been checked
  against the file, so allocations are bounded by the file size. Where
  records can share data (several PE import descriptors pointing at one
  lookup table, or overlapping ELF note sections), a second budget caps the
  total: import entries at one per thunk-sized slot in the file, note bytes
  scanned at the file size.

The parsers are strict: every section and segment that claims file bytes
must lie inside the file, checked when the headers are read. Optional parts
(`ParseOptions`) are decoded and validated only when requested, so a broken
symbol table does not hide a good section table. Results own their strings
(`std::string`), so they outlive the input buffer.

## ELF

`elf.cpp` is one `Parser` class. Order of work:

1. `read_header`: identification (class, data encoding), then the rest of
   the header in the right width and byte order. Extended numbering is
   resolved here: `e_shnum == 0`, `e_shstrndx == SHN_XINDEX` and
   `e_phnum == PN_XNUM` take their values from section header 0.
2. Section and program header tables, entry sizes checked against the
   class's minimum.
3. Section names from `e_shstrndx`, then `check_ranges`: every non-NOBITS
   section and every segment must lie inside the file.
4. Optional parts. Symbol tables are the first `SHT_SYMTAB` and
   `SHT_DYNSYM`; names come from the `sh_link` string table, `SHN_XINDEX`
   indexes from the `SHT_SYMTAB_SHNDX` section that links to the table.
   The dynamic section comes from `SHT_DYNAMIC` (strings via `sh_link`) or,
   without section headers, from `PT_DYNAMIC` with `DT_STRTAB`/`DT_STRSZ`
   mapped through the `PT_LOAD` segments. The build ID is searched in
   `SHT_NOTE` sections, or `PT_NOTE` segments when there are none, honoring
   8-byte note alignment.

## PE and COFF

`coff.cpp` has what images and objects share: the COFF file header, the
section table, long section names, the string table and the symbol table.
`pe.cpp` adds the image parts.

- The section table follows the optional header (`SizeOfOptionalHeader`).
  Names of the form `/123` or `//BASE64` are string table offsets when the
  file has a symbol table; the string table is loaded only if some name
  needs it, so an image with a stale `PointerToSymbolTable` still lists
  its sections.
- `RvaMap` maps RVAs to file offsets with a binary search over sections
  sorted by address. A section covers `[VirtualAddress, VirtualAddress +
  VirtualSize)` (or `SizeOfRawData` when `VirtualSize` is 0), but only the
  part backed by raw data has a file offset; RVAs below `SizeOfHeaders` map
  to themselves. Overlapping sections are rejected when the map is built,
  which makes the result equal to the public `rva_to_offset()`, a linear
  first-match search. Each lookup also returns how many bytes follow in the
  same section, and tables and strings are read within that limit: an
  import lookup table or a name that runs off the end of its section is an
  error even if the file continues.
- Imports: descriptors until the all-zero one; for each, the lookup table
  (`OriginalFirstThunk`, or `FirstThunk` when that is 0) until a zero entry.
  The ordinal flag is bit 31 (PE32) or 63 (PE32+); otherwise the entry is a
  31-bit hint/name RVA.
- Exports: the address table, then the name pointer and ordinal tables
  matched up by index. An address inside the export directory's own range
  is a forwarder string. Output is one entry per name plus one per unnamed
  function, in ordinal order; unused slots (RVA 0, no name) are dropped.

## Reports and the command-line tool

`report.cpp` dispatches on the `ParsedFile` variant; `report_elf.cpp` and
`report_pe.cpp` write text (with the `Table` and `Fields` helpers in
`text.cpp`) and JSON (`JsonWriter`, `json.cpp`). Text output escapes control
characters and invalid UTF-8 in names (`printable()`); the JSON writer
escapes control characters and replaces invalid UTF-8 with U+FFFD.
`parse_options_for()` turns the requested report parts into the
`ParseOptions` that decode exactly those parts.

`tools/binpeek_cli.cpp` parses arguments, reads each file, and maps
outcomes to exit codes (0, 1 for `FormatError` and I/O errors, 2 for usage
errors). On Windows it takes its arguments from `CommandLineToArgvW`, so
file names outside the ANSI code page work.

## Tests

- `tests/image_builder.cpp` writes ELF (both classes and byte orders), PE32,
  PE32+ (with import and export tables) and COFF images, and records where
  each structure lands so tests can corrupt specific fields.
- `tests/test_corrupt.cpp` runs every truncation of every sample image,
  single-byte and boundary-value overwrites at every field position, and
  seeded random corruption, each on a fresh, exactly-sized copy so that the
  `asan` preset catches any over-read; then targeted cases (offsets and
  sizes past the end, overflowing counts, unterminated strings, RVAs
  outside every section, endless lookup tables) with the expected offsets.
- `tests/test_fixtures.cpp` checks facts about the real binaries in
  `tests/data`; `tools/compare_oracle.sh` compares whole outputs with
  `readelf` and `llvm-readobj`.

## Adding things

- **A field or table in an existing format**: decode it in the parser
  through a `Cursor`, check its range first (`require`, `require_array`,
  or an `RvaMap` location's `available`), add it to the model in the
  header, and if it is optional, gate it behind a `ParseOptions` flag and
  `parse_options_for()`. Show it in `report_*.cpp`, test it with the image
  builder, and add a truncation or corruption case that hits the new check.
- **A display name**: add the constant to `elf.hpp`/`pe.hpp` (lower case,
  prefixed, so it cannot collide with `<elf.h>` or `<windows.h>` macros)
  and a row to the table in `elf_names.cpp`/`pe_names.cpp`.
- **A new format**: a `parse_xxx()` returning its own model, a case in
  `detect_format()` and `parse()`, a new alternative in `ParsedFile`, and a
  `report_xxx.cpp`. `std::visit` in `report.cpp` will not compile until
  every alternative is handled.
