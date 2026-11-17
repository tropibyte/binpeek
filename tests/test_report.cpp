// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <sstream>
#include <string>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::test;

namespace {

std::string text_report(const ParsedFile& file, const ReportOptions& report) {
    std::ostringstream out;
    write_text(out, file, report);
    return out.str();
}

std::string json_report(const ParsedFile& file, const ReportOptions& report, std::string_view name = {}) {
    std::ostringstream out;
    JsonWriter json(out);
    write_json(json, file, report, name);
    CHECK(json.done());
    return out.str();
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

TEST_CASE("report options decide what is parsed") {
    ReportOptions r;
    ParseOptions p = parse_options_for(r);
    CHECK_FALSE(p.symbols);
    CHECK_FALSE(p.dynamic_symbols);
    CHECK_FALSE(p.dynamic);
    CHECK_FALSE(p.imports);
    CHECK_FALSE(p.exports);

    r.headers = true;
    CHECK(parse_options_for(r).dynamic);
    r = ReportOptions{};
    r.imports = true;
    p = parse_options_for(r);
    CHECK(p.imports);
    CHECK(p.dynamic);
    CHECK(p.dynamic_symbols);
    CHECK_FALSE(p.symbols);

    const ReportOptions all = ReportOptions::everything();
    CHECK(all.all);
    p = parse_options_for(all);
    CHECK((p.symbols && p.dynamic_symbols && p.dynamic && p.imports && p.exports));
}

TEST_CASE("describe") {
    CHECK(describe(parse(make_sample_elf(true, Endian::Little).bytes)) ==
          "ELF64 little-endian EXEC (executable), x86-64");
    CHECK(describe(parse(make_sample_elf(false, Endian::Big).bytes)) == "ELF32 big-endian EXEC (executable), MIPS");
    CHECK(describe(parse(make_sample_pe(true).bytes)) == "PE32+ DLL (Windows GUI), AMD64");
    CHECK(describe(parse(make_sample_pe(false).bytes)) == "PE32 DLL (Windows GUI), i386");
    CHECK(describe(parse(make_sample_coff(pe::machine_arm64).bytes)) == "COFF object, ARM64");
}

TEST_CASE("ELF text report") {
    const ParsedFile f = parse(make_sample_elf(true, Endian::Little).bytes);
    const std::string text = text_report(f, ReportOptions::everything());
    CHECK(contains(text, "\nFile header:\n  Class:            ELF64\n"));
    CHECK(contains(text, "  Interpreter:      /lib/ld-sample.so.1\n"));
    CHECK(contains(text, "  Build ID:         1011121314151617"));
    CHECK(contains(text, "  Needed:           libm.so.6\n"));
    CHECK(contains(text, "  RUNPATH:          $ORIGIN/../lib\n"));
    CHECK(contains(text, "\nDynamic section (7 entries):\n"));
    CHECK(contains(text, "NEEDED   [libc.so.6]"));
    CHECK(contains(text, "\nSections (12):\n"));
    CHECK(contains(text, "  Nr  Name                Type      Address"));
    CHECK(contains(text, "   5  .text               PROGBITS  0000000000400"));
    CHECK(contains(text, "\nProgram headers (5):\n"));
    CHECK(contains(text, "  LOAD     000000  0000000000400000"));
    CHECK(contains(text, "\nSymbol table .symtab (8 entries):\n"));
    CHECK(contains(text, "FUNC     GLOBAL  PROTECTED    5  protected_fn\n"));
    CHECK(contains(text, "\nSymbol table .dynsym (6 entries):\n"));
    CHECK(contains(text, "\nNeeded libraries (2):\n  libc.so.6\n  libm.so.6\n"));
    CHECK(contains(text, "\nImported symbols (2):\n"));
    CHECK(contains(text, "\nExported symbols (2):\n"));  // the hidden symbol is not exported
    CHECK_FALSE(contains(text, "internal_fn\n  "));
    CHECK_FALSE(contains(text, " \n"));  // no trailing spaces
}

TEST_CASE("PE text report") {
    const ParsedFile f = parse(make_sample_pe(false).bytes);
    const std::string text = text_report(f, ReportOptions::everything());
    CHECK(contains(text, "\nDOS header:\n  Magic:             MZ\n  PE header offset:  0x80\n"));
    CHECK(contains(text, "  Time stamp:            0x65000000 (2023-09-12 06:06:56 UTC)\n"));
    CHECK(contains(text, "  Characteristics:       0x2102 EXECUTABLE_IMAGE 32BIT_MACHINE DLL\n"));
    CHECK(contains(text, "  Magic:                 0x10b (PE32)\n"));
    CHECK(contains(text, "  Base of data:          0x2000\n"));
    CHECK(contains(text, "   1  Import           0x00005000"));
    CHECK(contains(text, ".idata\n"));
    CHECK(contains(text, "   1  .text   00000040  00001000  00000200  00000400       0  R-X   0x60000020 CODE\n"));
    CHECK(contains(text, "\nImports from KERNEL32.dll (2 functions):\n"));
    CHECK(contains(text, "        ordinal 17\n"));
    CHECK(contains(text, "\nExports from sample.dll (5 entries, ordinal base 5):\n"));
    CHECK(contains(text, "        9  0x00004"));
    CHECK(contains(text, "Quit        KERNEL32.ExitProcess\n"));
    CHECK(contains(text, "\nNo COFF symbol table.\n"));
    CHECK_FALSE(contains(text, "No program headers"));  // --all leaves out what does not apply

    ReportOptions r;
    r.segments = true;
    r.dynamic_symbols = true;
    const std::string notes = text_report(f, r);
    CHECK(contains(notes, "No program headers: PE/COFF files have sections only."));
    CHECK(contains(notes, "No dynamic symbol table"));
}

TEST_CASE("COFF text report") {
    const ParsedFile f = parse(make_sample_coff(pe::machine_amd64).bytes);
    ReportOptions r;
    r.sections = true;
    r.symbols = true;
    const std::string text = text_report(f, r);
    CHECK(contains(text, "   4  .debug_long_section"));
    CHECK(contains(text, "\nCOFF symbol table (7 symbols, 9 records):\n"));
    CHECK(contains(text, "      0  00000000    DEBUG  0000  FILE        1  .file\n"));
    CHECK(contains(text, "  00001234      ABS  0000  EXTERNAL    0  abs_value\n"));
}

TEST_CASE("text reports escape control characters in names") {
    ElfImage img = make_sample_elf(true, Endian::Little);
    // Rename "main" in .strtab to "m\x1b[n".
    const std::string strtab(reinterpret_cast<const char*>(img.bytes.data() + img.data_offset(".strtab")), 64);
    const std::size_t at = img.data_offset(".strtab") + strtab.find("main");
    poke_u8(img.bytes, at + 1, 0x1b);
    poke_u8(img.bytes, at + 2, '[');
    ReportOptions r;
    r.symbols = true;
    const ParsedFile f = parse(img.bytes);
    const std::string text = text_report(f, r);
    CHECK(contains(text, "m\\x1b[n\n"));
    CHECK_FALSE(contains(text, "\x1b"));
    CHECK(contains(json_report(f, r), "\"name\": \"m\\u001b[n\""));
    CHECK(printable("ok\xc2\x85\xc3\xa9\xff") == "ok\\xc2\\x85\xc3\xa9\\xff");
}

TEST_CASE("JSON report") {
    const ParsedFile elf_file = parse(make_sample_elf(false, Endian::Big).bytes);
    const std::string elf_json = json_report(elf_file, ReportOptions::everything(), "sample.elf");
    CHECK(elf_json.starts_with("{\n  \"file\": \"sample.elf\",\n  \"format\": \"ELF\",\n"));
    CHECK(contains(elf_json, "\"endian\": \"big\""));
    CHECK(contains(elf_json, "\"build_id\": \"101112131415161718191a1b1c1d1e1f20212223\""));
    CHECK(contains(elf_json, "\"needed\": [\n      \"libc.so.6\",\n      \"libm.so.6\"\n    ]"));
    CHECK(contains(elf_json, "\"type_name\": \"NOBITS\""));
    CHECK(contains(elf_json, "\"visibility\": \"HIDDEN\""));
    CHECK(contains(elf_json, "\"exports\": ["));

    const ParsedFile pe_file = parse(make_sample_pe(true).bytes);
    ReportOptions r;
    r.imports = true;
    r.exports = true;
    const std::string pe_json = json_report(pe_file, r);
    CHECK_FALSE(contains(pe_json, "\"file\""));
    CHECK(contains(pe_json, "\"format\": \"PE\""));
    CHECK(contains(pe_json, "\"dll\": \"USER32.dll\""));
    CHECK(contains(pe_json, "\"ordinal\": 17"));
    CHECK(contains(pe_json, "\"forwarder\": \"KERNEL32.ExitProcess\""));
    CHECK(contains(pe_json, "\"name\": null"));
    CHECK_FALSE(contains(pe_json, "\"sections\""));

    const std::string coff_json =
        json_report(parse(make_sample_coff(pe::machine_i386).bytes), ReportOptions::everything());
    CHECK(contains(coff_json, "\"format\": \"COFF\""));
    CHECK(contains(coff_json, "\"short_name\": \"/4\""));
    CHECK(contains(coff_json, "\"exports\": null"));
}
