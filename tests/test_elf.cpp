// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::elf;
using namespace binpeek::test;

namespace {

struct Variant {
    bool is64;
    Endian endian;
    std::uint16_t machine;
};

const Variant kVariants[] = {
    {false, Endian::Little, em_386},
    {false, Endian::Big, em_mips},
    {true, Endian::Little, em_x86_64},
    {true, Endian::Big, em_ppc64},
};

const std::vector<std::string> kSampleSections = {
    "",       ".interp", ".note.gnu.build-id", ".dynsym", ".dynstr", ".text",
    ".dynamic", ".data", ".bss",               ".symtab", ".strtab", ".shstrtab",
};

}  // namespace

TEST_CASE("ELF sample images: 32/64-bit, little/big-endian") {
    for (const Variant& v : kVariants) {
        CAPTURE(v.is64);
        CAPTURE(v.machine);
        const ElfImage img = make_sample_elf(v.is64, v.endian);
        const ElfFile f = parse_elf(img.bytes);

        const FileHeader& h = f.header;
        CHECK(h.is64 == v.is64);
        CHECK(h.endian == v.endian);
        CHECK(h.ident_version == 1u);
        CHECK(h.type == et_exec);
        CHECK(h.machine == v.machine);
        CHECK(h.version == 1u);
        CHECK(h.entry == 0x401000u);
        CHECK(h.phoff == img.phoff);
        CHECK(h.shoff == img.shoff);
        CHECK(h.phnum == 5u);
        CHECK(h.shnum == 12u);
        CHECK(h.shstrndx == 11u);

        CHECK(section_names(f) == kSampleSections);
        const Section* text = f.find_section(".text");
        REQUIRE(text != nullptr);
        CHECK(text->type == sht_progbits);
        CHECK(text->flags == (shf_alloc | shf_execinstr));
        CHECK(text->addr == ElfBuilder::base_address + img.data_offset(".text"));
        CHECK(text->size == 32u);
        CHECK(text->addralign == 16u);
        const Section* bss = f.find_section(".bss");
        REQUIRE(bss != nullptr);
        CHECK(bss->type == sht_nobits);
        CHECK(bss->size == 32u);
        CHECK_FALSE(bss->has_file_data());
        CHECK(f.sections[3].link == 4u);  // .dynsym -> .dynstr
        CHECK(f.find_section(".missing") == nullptr);

        REQUIRE(f.segments.size() == 5u);
        CHECK(f.segments[0].type == pt_phdr);
        CHECK(f.segments[0].offset == img.phoff);
        CHECK(f.segments[1].type == pt_interp);
        CHECK(f.segments[1].offset == img.data_offset(".interp"));
        CHECK(f.segments[2].type == pt_load);
        CHECK(f.segments[2].flags == (pf_r | pf_w | pf_x));
        CHECK(f.segments[2].vaddr == ElfBuilder::base_address);
        CHECK(f.segments[2].filesz == img.data_offset(".data") + 8);
        CHECK(f.segments[2].memsz == img.data_offset(".bss") + 32);
        CHECK(f.segments[2].align == 0x1000u);
        CHECK(f.segments[3].type == pt_dynamic);
        CHECK(f.segments[4].type == pt_note);

        REQUIRE(f.interpreter);
        CHECK(*f.interpreter == "/lib/ld-sample.so.1");
        CHECK(f.build_id == sample_build_id());
        CHECK(f.needed == std::vector<std::string>{"libc.so.6", "libm.so.6"});
        CHECK(f.soname == "libsample.so.1");
        CHECK(f.rpath == "/opt/old/lib");
        CHECK(f.runpath == "$ORIGIN/../lib");
        REQUIRE(f.dynamic.size() == 7u);
        CHECK(f.dynamic[0].tag == dt_needed);
        CHECK(f.dynamic[5].tag == dt_strtab);
        CHECK(f.dynamic[5].value == ElfBuilder::base_address + img.data_offset(".dynstr"));

        REQUIRE(f.dynamic_symbols.size() == 6u);
        CHECK(f.dynamic_symbols[0].name.empty());
        CHECK(f.dynamic_symbols[1].name == "puts");
        CHECK(f.dynamic_symbols[1].is_undefined());
        CHECK(f.dynamic_symbols[1].type == stt_func);
        CHECK(f.dynamic_symbols[1].bind == stb_global);
        const Symbol* data = find_symbol(f.dynamic_symbols, "sample_data");
        REQUIRE(data != nullptr);
        CHECK(data->bind == stb_weak);
        CHECK(data->type == stt_object);
        CHECK(data->size == 4u);
        CHECK(data->section_index == 7u);
        const Symbol* internal = find_symbol(f.dynamic_symbols, "internal_fn");
        REQUIRE(internal != nullptr);
        CHECK(internal->visibility == stv_hidden);
        CHECK(internal->other == stv_hidden);

        REQUIRE(f.symbols.size() == 8u);
        CHECK(f.symbols[1].name == "sample.c");
        CHECK(f.symbols[1].type == stt_file);
        CHECK(f.symbols[1].section_index == shn_abs);
        CHECK(f.symbols[2].type == stt_section);
        CHECK(f.symbols[2].section_index == 5u);
        CHECK(f.symbols[3].name == "local_counter");
        CHECK(f.symbols[3].bind == stb_local);
        CHECK(f.symbols[3].section_index == 8u);
        const Symbol* main_fn = find_symbol(f.symbols, "main");
        REQUIRE(main_fn != nullptr);
        CHECK(main_fn->value == 0x401000u);
        CHECK(main_fn->size == 16u);
        CHECK(main_fn->type == stt_func);
        const Symbol* prot = find_symbol(f.symbols, "protected_fn");
        REQUIRE(prot != nullptr);
        CHECK(prot->visibility == stv_protected);
    }
}

TEST_CASE("ELF without section headers uses the program headers") {
    for (const Variant& v : kVariants) {
        CAPTURE(v.is64);
        ElfImage img = make_sample_elf(v.is64, v.endian);
        const ElfFields fields = img.fields();
        poke_word(img.bytes, fields.e_shoff, 0, v.is64, v.endian);
        poke_u16(img.bytes, fields.e_shnum, 0, v.endian);
        poke_u16(img.bytes, fields.e_shstrndx, 0, v.endian);

        const ElfFile f = parse_elf(img.bytes);
        CHECK(f.sections.empty());
        CHECK(f.header.shnum == 0u);
        CHECK(f.segments.size() == 5u);
        // DT_STRTAB is found through PT_LOAD, the build ID through PT_NOTE.
        CHECK(f.needed == std::vector<std::string>{"libc.so.6", "libm.so.6"});
        CHECK(f.runpath == "$ORIGIN/../lib");
        CHECK(f.interpreter == "/lib/ld-sample.so.1");
        CHECK(f.build_id == sample_build_id());
        // Without section headers the dynamic symbol count is unknown.
        CHECK(f.dynamic_symbols.empty());
        CHECK(f.symbols.empty());
    }
}

TEST_CASE("ELF extended numbering keeps counts in section header 0") {
    for (const Variant& v : kVariants) {
        CAPTURE(v.is64);
        ElfImage img = make_sample_elf(v.is64, v.endian);
        const ElfFields fields = img.fields();
        const std::uint64_t first = img.section_header(0);
        poke_u16(img.bytes, fields.e_shnum, 0, v.endian);
        poke_word(img.bytes, first + fields.sh_size, 12, v.is64, v.endian);
        poke_u16(img.bytes, fields.e_shstrndx, shn_xindex, v.endian);
        poke_u32(img.bytes, first + fields.sh_link, 11, v.endian);
        poke_u16(img.bytes, fields.e_phnum, pn_xnum, v.endian);
        poke_u32(img.bytes, first + fields.sh_info, 5, v.endian);

        const ElfFile f = parse_elf(img.bytes);
        CHECK(f.header.shnum == 12u);
        CHECK(f.header.shstrndx == 11u);
        CHECK(f.header.phnum == 5u);
        CHECK(section_names(f) == kSampleSections);
        CHECK(f.segments.size() == 5u);
        CHECK(f.needed.size() == 2u);
    }
}

TEST_CASE("ELF SHN_XINDEX symbols resolve through SHT_SYMTAB_SHNDX") {
    for (const Variant& v : kVariants) {
        CAPTURE(v.is64);
        StringTableWriter strings;
        const Bytes symtab = elf_symbols(v.is64, v.endian,
                                         {{"plain", 0, 0, stt_object, stb_global, stv_default, 2},
                                          {"extended", 8, 0, stt_object, stb_global, stv_default, shn_xindex}},
                                         strings);
        ByteWriter shndx(v.endian);
        shndx.u32(0);
        shndx.u32(0);
        shndx.u32(2);
        ElfBuilder b(v.is64, v.endian, et_rel, v.machine);
        b.add_section({".text", sht_progbits, shf_alloc | shf_execinstr, Bytes(4)});
        b.add_section({".data", sht_progbits, shf_alloc | shf_write, Bytes(16)});
        b.add_section({".symtab", sht_symtab, 0, symtab, 0, ".strtab", 1, 8, v.is64 ? 24u : 16u});
        b.add_section({".strtab", sht_strtab, 0, strings.bytes()});
        b.add_section({".symtab_shndx", sht_symtab_shndx, 0, shndx.take(), 0, ".symtab", 0, 4, 4});
        const ElfImage img = b.build();

        const ElfFile f = parse_elf(img.bytes);
        REQUIRE(f.symbols.size() == 3u);
        CHECK(f.symbols[1].section_index == 2u);
        CHECK(f.symbols[2].name == "extended");
        CHECK(f.symbols[2].section_index == 2u);
        CHECK(f.header.type == et_rel);
        CHECK(f.segments.empty());

        // The same table without its SHT_SYMTAB_SHNDX section.
        Bytes broken = img.bytes;
        poke_u32(broken, img.section_header(".symtab_shndx") + img.fields().sh_type, sht_progbits, v.endian);
        const auto e = parse_error(broken);
        REQUIRE(e);
        CHECK(e->offset() == img.data_offset(".symtab") + 2 * img.fields().sym_size);
        CHECK(std::string(e->message()).find("SHN_XINDEX") != std::string::npos);
    }
}

TEST_CASE("ELF parse options skip and do not validate unrequested parts") {
    ElfImage img = make_sample_elf(true, Endian::Little);
    // Point .symtab's string table link out of range.
    poke_u32(img.bytes, img.section_header(".symtab") + img.fields().sh_link, 99);
    CHECK(parse_error(img.bytes));

    ParseOptions options;
    options.symbols = false;
    const ElfFile f = parse_elf(img.bytes, options);
    CHECK(f.symbols.empty());
    CHECK(f.dynamic_symbols.size() == 6u);
    CHECK(f.needed.size() == 2u);

    options.dynamic_symbols = false;
    options.dynamic = false;
    const ElfFile bare = parse_elf(img.bytes, options);
    CHECK(bare.dynamic_symbols.empty());
    CHECK(bare.needed.empty());
    CHECK(bare.dynamic.empty());
    CHECK_FALSE(bare.interpreter);
    CHECK(bare.build_id.empty());
    CHECK(bare.sections.size() == 12u);
}

TEST_CASE("ELF display names") {
    CHECK(file_type_name(et_dyn) == "DYN");
    CHECK(file_type_name(0xfe00) == "0xfe00");
    CHECK(machine_name(em_aarch64) == "AArch64");
    CHECK(machine_name(em_x86_64) == "x86-64");
    CHECK(machine_name(9999) == "machine 9999");
    CHECK(os_abi_name(3) == "GNU");
    CHECK(os_abi_name(200) == "OS/ABI 200");
    CHECK(section_type_name(sht_gnu_hash, em_x86_64) == "GNU_HASH");
    CHECK(section_type_name(sht_x86_64_unwind, em_x86_64) == "X86_64_UNWIND");
    CHECK(section_type_name(sht_arm_exidx, em_arm) == "ARM_EXIDX");
    CHECK(section_type_name(0x70000001, em_386) == "LOPROC+0x1");
    CHECK(section_type_name(0x60000010, em_386) == "LOOS+0x10");
    CHECK(section_type_name(0x80000002, em_386) == "LOUSER+0x2");
    CHECK(section_type_name(42, em_386) == "0x2a");
    CHECK(segment_type_name(pt_gnu_stack) == "GNU_STACK");
    CHECK(segment_type_name(0x12345) == "0x12345");
    CHECK(symbol_type_name(stt_gnu_ifunc) == "GNU_IFUNC");
    CHECK(symbol_type_name(13) == "13");
    CHECK(symbol_bind_name(stb_weak) == "WEAK");
    CHECK(visibility_name(stv_protected) == "PROTECTED");
    CHECK(dynamic_tag_name(dt_runpath) == "RUNPATH");
    CHECK(dynamic_tag_name(dt_flags_1) == "FLAGS_1");
    CHECK(dynamic_tag_name(0x7000000a) == "0x7000000a");
    CHECK(section_flags_string(shf_write | shf_alloc | shf_execinstr) == "WAX");
    CHECK(section_flags_string(shf_merge | shf_strings) == "MS");
    CHECK(section_flags_string(shf_alloc | 0x00100000) == "Ax");
    CHECK(section_flags_string(0).empty());
    CHECK(segment_flags_string(pf_r | pf_x) == "R-X");
    CHECK(segment_flags_string(pf_r | pf_w) == "RW-");
    CHECK(section_index_name(shn_undef) == "UND");
    CHECK(section_index_name(shn_abs) == "ABS");
    CHECK(section_index_name(shn_common) == "COM");
    CHECK(section_index_name(7) == "7");
    CHECK(section_index_name(0xff10) == "0xff10");
    CHECK(section_index_name(70000) == "70000");
}
