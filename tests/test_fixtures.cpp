// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Real files from tests/data, built by tools/make_fixtures.sh.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::test;

namespace {

bool has(const std::vector<std::string>& names, const std::string& name) {
    return std::find(names.begin(), names.end(), name) != names.end();
}

}  // namespace

TEST_CASE("fixture: ELF executable (hello.elf)") {
    const Bytes data = load_fixture("hello.elf");
    const ParsedFile parsed = parse(data);
    const auto& f = as<elf::ElfFile>(parsed);

    CHECK(f.header.is64);
    CHECK(f.header.endian == Endian::Little);
    CHECK(f.header.type == elf::et_dyn);  // position-independent
    CHECK(f.header.machine == elf::em_x86_64);
    CHECK(f.header.shnum == f.sections.size());

    const auto names = section_names(f);
    for (const char* name : {".interp", ".note.gnu.build-id", ".dynsym", ".dynstr", ".text", ".dynamic", ".shstrtab"}) {
        CAPTURE(name);
        CHECK(has(names, name));
    }
    CHECK_FALSE(has(names, ".comment"));
    CHECK_FALSE(has(names, ".symtab"));  // stripped
    CHECK(f.symbols.empty());
    const elf::Section* text = f.find_section(".text");
    REQUIRE(text != nullptr);
    CHECK(text->flags == (elf::shf_alloc | elf::shf_execinstr));
    CHECK(f.header.entry == text->addr);  // _start is all there is

    std::size_t loads = 0;
    for (const elf::Segment& p : f.segments) loads += p.type == elf::pt_load ? 1 : 0;
    CHECK(loads == 2u);

    CHECK(f.interpreter == "/lib64/ld-linux-x86-64.so.2");
    CHECK(f.needed == std::vector<std::string>{"libc.so.6", "libm.so.6"});
    CHECK(f.runpath == "$ORIGIN/lib");
    CHECK_FALSE(f.rpath);
    CHECK_FALSE(f.soname);
    CHECK(f.build_id.size() == 20u);  // SHA-1

    REQUIRE(f.dynamic_symbols.size() == 4u);
    for (const char* name : {"puts", "exit", "sqrt"}) {
        CAPTURE(name);
        const elf::Symbol* s = find_symbol(f.dynamic_symbols, name);
        REQUIRE(s != nullptr);
        CHECK(s->is_undefined());
        CHECK(s->type == elf::stt_func);
        CHECK(s->bind == elf::stb_global);
    }
}

TEST_CASE("fixture: ELF relocatable object (sample.o)") {
    const ParsedFile parsed = parse(load_fixture("sample.o"));
    const auto& f = as<elf::ElfFile>(parsed);
    CHECK(f.header.type == elf::et_rel);
    CHECK(f.header.machine == elf::em_x86_64);
    CHECK(f.segments.empty());
    CHECK(f.dynamic.empty());
    CHECK_FALSE(f.interpreter);
    CHECK(section_names(f) == std::vector<std::string>{"", ".text", ".rela.text", ".data", ".bss", ".note.GNU-stack",
                                                       ".note.gnu.property", ".symtab", ".strtab", ".shstrtab"});

    const elf::Symbol* helper = find_symbol(f.symbols, "helper");
    REQUIRE(helper != nullptr);
    CHECK(helper->type == elf::stt_func);
    CHECK(helper->bind == elf::stb_global);
    CHECK(helper->visibility == elf::stv_hidden);
    CHECK(helper->section_index == 1u);
    const elf::Symbol* fallback = find_symbol(f.symbols, "fallback");
    REQUIRE(fallback != nullptr);
    CHECK(fallback->bind == elf::stb_weak);
    const elf::Symbol* counter = find_symbol(f.symbols, "counter");
    REQUIRE(counter != nullptr);
    CHECK(counter->type == elf::stt_object);
    CHECK(counter->size == 4u);
    CHECK(f.sections[counter->section_index].name == ".data");
    const elf::Symbol* total = find_symbol(f.symbols, "total");
    REQUIRE(total != nullptr);
    CHECK(total->bind == elf::stb_local);
    CHECK(f.sections[total->section_index].name == ".bss");
    const elf::Symbol* puts = find_symbol(f.symbols, "puts");
    REQUIRE(puts != nullptr);
    CHECK(puts->is_undefined());
    CHECK(find_symbol(f.symbols, "greet") != nullptr);
}

TEST_CASE("fixture: PE executable (hello.exe)") {
    const ParsedFile parsed = parse(load_fixture("hello.exe"));
    const auto& f = as<pe::PeFile>(parsed);
    CHECK(f.is_image());
    CHECK_FALSE(f.is_dll());
    CHECK(f.is_pe32_plus());
    CHECK(f.header.machine == pe::machine_amd64);
    CHECK(f.header.timestamp == 0u);
    REQUIRE(f.optional_header);
    CHECK(f.optional_header->subsystem == pe::subsystem_windows_cui);
    CHECK(f.optional_header->image_base == 0x140000000u);
    CHECK(section_names(f) == std::vector<std::string>{".text", ".rdata", ".pdata", ".xdata", ".idata"});
    const pe::Section* text = f.find_section(".text");
    REQUIRE(text != nullptr);
    CHECK(f.optional_header->entry_point >= text->virtual_address);
    CHECK(f.optional_header->entry_point < text->virtual_address + text->virtual_size);
    CHECK_FALSE(f.exports);

    REQUIRE(f.imports.size() == 2u);
    const pe::ImportedDll* greet = find_import(f, "greet.dll");
    REQUIRE(greet != nullptr);
    REQUIRE(greet->functions.size() == 3u);
    CHECK(greet->functions[0].name == "add");
    CHECK(greet->functions[1].name == "greet");
    REQUIRE(greet->functions[2].ordinal);
    CHECK(*greet->functions[2].ordinal == 7u);

    const pe::ImportedDll* kernel32 = find_import(f, "KERNEL32.dll");
    REQUIRE(kernel32 != nullptr);
    std::vector<std::string> names;
    for (const pe::ImportedFunction& fn : kernel32->functions) names.push_back(fn.name);
    CHECK(names == std::vector<std::string>{"ExitProcess", "GetStdHandle", "WriteFile", "lstrlenA"});
    // Every IAT slot is inside .idata.
    const pe::Section* idata = f.find_section(".idata");
    REQUIRE(idata != nullptr);
    for (const pe::ImportedFunction& fn : kernel32->functions) {
        CHECK(fn.iat_rva >= idata->virtual_address);
        CHECK(fn.iat_rva < idata->virtual_address + idata->virtual_size);
    }
}

TEST_CASE("fixture: PE DLL (greet.dll)") {
    const ParsedFile parsed = parse(load_fixture("greet.dll"));
    const auto& f = as<pe::PeFile>(parsed);
    CHECK(f.is_dll());
    CHECK(f.header.machine == pe::machine_amd64);
    REQUIRE(f.exports);
    const pe::ExportDirectory& e = *f.exports;
    CHECK(e.dll_name == "greet.dll");
    CHECK(e.ordinal_base == 1u);
    CHECK(e.function_count == 7u);
    CHECK(e.name_count == 3u);
    REQUIRE(e.functions.size() == 4u);
    CHECK(e.functions[0].ordinal == 1u);
    CHECK(e.functions[0].name == "add");
    CHECK(e.functions[1].ordinal == 2u);
    CHECK(e.functions[1].name == "greet");
    CHECK(e.functions[2].ordinal == 3u);
    CHECK(e.functions[2].name == "ExitNow");
    CHECK(e.functions[2].forwarder == "KERNEL32.ExitProcess");
    CHECK(e.functions[3].ordinal == 7u);  // secret, exported by ordinal only
    CHECK(e.functions[3].name.empty());
    CHECK(e.functions[3].forwarder.empty());
    const pe::Section* text = f.find_section(".text");
    REQUIRE(text != nullptr);
    CHECK(e.functions[0].rva >= text->virtual_address);
    CHECK(e.functions[0].rva < text->virtual_address + text->virtual_size);

    REQUIRE(f.imports.size() == 1u);
    CHECK(f.imports[0].name == "KERNEL32.dll");
    REQUIRE(f.imports[0].functions.size() == 1u);
    CHECK(f.imports[0].functions[0].name == "lstrcpyA");
}

TEST_CASE("fixture: COFF object (greet.obj)") {
    const Bytes data = load_fixture("greet.obj");
    CHECK(detect_format(data) == FileFormat::Coff);
    const ParsedFile parsed = parse(data);
    const auto& f = as<pe::PeFile>(parsed);
    CHECK_FALSE(f.is_image());
    CHECK(f.header.machine == pe::machine_amd64);
    const auto names = section_names(f);
    CHECK(has(names, ".text"));
    CHECK(has(names, ".drectve"));
    const pe::Section* greeting = f.find_section(".rdata$greeting");
    REQUIRE(greeting != nullptr);
    CHECK(greeting->short_name.starts_with("/"));  // a long name, from the string table

    auto symbol = [&](const std::string& name) -> const pe::Symbol* {
        for (const pe::Symbol& s : f.symbols) {
            if (s.name == name) return &s;
        }
        return nullptr;
    };
    for (const char* name : {"add", "greet", "secret", "DllMain"}) {
        CAPTURE(name);
        const pe::Symbol* s = symbol(name);
        REQUIRE(s != nullptr);
        CHECK(s->storage_class == pe::class_external);
        CHECK(s->section_number == 1);
        CHECK(s->type == pe::sym_dtype_function);
    }
    const pe::Symbol* buffer = symbol("buffer");
    REQUIRE(buffer != nullptr);
    CHECK(buffer->storage_class == pe::class_static);
    const pe::Symbol* import = symbol("__imp_lstrcpyA");
    REQUIRE(import != nullptr);
    CHECK(import->section_number == pe::sym_undefined);
    const pe::Symbol* file = symbol(".file");
    REQUIRE(file != nullptr);
    CHECK(file->aux_count >= 1u);
}

TEST_CASE("fixture: truncated ELF") {
    const auto e = parse_error(load_fixture("truncated.elf"));
    REQUIRE(e);
    const ParsedFile parsed_full = parse(load_fixture("hello.elf"));
    const auto& full = as<elf::ElfFile>(parsed_full);
    CHECK(e->offset() == full.header.shoff);
}
