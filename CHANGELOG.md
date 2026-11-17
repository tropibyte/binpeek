# Changelog

## 0.1.0 - 2026-11-17

Initial release.

### Added

- `binpeek` library: bounds-checked byte access (`ByteView`, `Cursor`,
  `StringTable`) with overflow-checked offset arithmetic; `FormatError`
  carrying the file offset of the fault.
- ELF parsing (32 and 64-bit, little and big-endian): file header with
  extended numbering, program headers, section headers and names, `.symtab`
  and `.dynsym` (including `SHN_XINDEX`), the dynamic section (`DT_NEEDED`,
  `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`), `PT_INTERP` and the GNU build ID.
- PE parsing (PE32 and PE32+): DOS, COFF and optional headers, data
  directories, section table, imports (by name with hint, or by ordinal),
  exports (named, ordinal-only, forwarders), COFF symbols and long section
  names; RVA to file offset mapping.
- COFF object files for x86, x64 and ARM64.
- Format detection, `ParseOptions` to select the optional parts, and a cap
  on the names copied out of one file.
- Text and JSON reports (`binpeek/report.hpp`) and the `binpeek` command-line
  tool with `--headers`, `--sections`, `--segments`, `--symbols`,
  `--dyn-syms`, `--imports`, `--exports`, `--all` and `--json`.
- CMake presets `dev`, `release`, `asan` and `mingw` (cross build for
  Windows, tests under Wine).
- Tests: in-memory ELF, PE and COFF image builders; truncation and
  corruption sweeps; real fixtures built by `tools/make_fixtures.sh`; and
  `tools/compare_oracle.sh`, which checks the output against `readelf` and
  `llvm-readobj`.
