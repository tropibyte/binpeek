# Roadmap

Planned work. Nothing here is implemented yet.

## Robustness

- **Fuzzing harness**: libFuzzer and AFL++ entry points that feed bytes to
  `parse()`, built behind an option (`BINPEEK_BUILD_FUZZ`) with the
  sanitizers on, plus a seed corpus: the fixtures in `tests/data` and the
  images `tests/image_builder.cpp` makes. The deterministic mutation tests
  in `tests/test_corrupt.cpp` cover the same ground in `ctest` today;
  a fuzzer would search wider and keep the inputs that reach new code.

## New data

- **DWARF line tables**: decode `.debug_line` (versions 2 to 5) into
  address-to-`file:line` rows, with a `--lines` option and a lookup API for
  one address. Compressed debug sections (`SHF_COMPRESSED`, zlib and zstd)
  would come with it.
- **PE resources**: walk the `.rsrc` directory tree (types, names, languages)
  and decode the version information (`VS_VERSIONINFO`: file and product
  versions, string tables) and the application manifest.
- **PE security directory**: list the certificate table entries (WIN_CERTIFICATE),
  verify the optional header checksum, and compute the Authenticode digest
  so that a caller can compare it with the signed one. Certificate chain
  validation stays out of scope.
- **Relocations**: ELF `.rel`/`.rela`/`.relr` sections with symbol names and
  per-architecture type names, and PE base relocation blocks
  (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), plus COFF object relocations.

## Formats and input

- **Mach-O**: thin and universal (fat) binaries: header, load commands,
  segments and sections, `LC_LOAD_DYLIB` dependencies, and the symbol table.
- **Memory-mapped input** for very large files (`mmap` and
  `CreateFileMapping` behind one interface), so that only the pages the
  parser touches are read. `ByteView` already takes any span, so the parsers
  would not change.

## Output

- **C++ symbol demangling** for the Itanium ABI (`_Z...`) and MSVC (`?...`)
  schemes, as an option (`--demangle`) on symbol, import and export
  listings, with a self-contained demangler rather than a dependency on the
  toolchain's.
