// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstdint>
#include <string>
#include <vector>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::pe;
using namespace binpeek::test;

TEST_CASE("COFF objects for x86, x64 and ARM64") {
    for (const std::uint16_t machine : {machine_i386, machine_amd64, machine_arm64}) {
        CAPTURE(machine);
        const CoffImage img = make_sample_coff(machine);
        const PeFile f = parse_coff_object(img.bytes);

        CHECK_FALSE(f.is_image());
        CHECK_FALSE(f.dos);
        CHECK_FALSE(f.optional_header);
        CHECK(f.header.machine == machine);
        CHECK(f.header.section_count == 4u);
        CHECK(f.header.symbol_table_offset == img.symbol_table);
        CHECK(f.header.symbol_count == 9u);
        CHECK(f.header.optional_header_size == 0u);

        CHECK(section_names(f) ==
              std::vector<std::string>{".text", ".data", ".bss", ".debug_long_section"});
        CHECK(f.sections[0].short_name == ".text");
        CHECK(f.sections[3].short_name == "/4");
        CHECK(f.sections[0].raw_offset == img.raw_offsets[0]);
        CHECK(f.sections[0].raw_size == 16u);
        CHECK(f.sections[0].characteristics == (scn_cnt_code | scn_mem_execute | scn_mem_read | 0x00500000u));
        CHECK(f.sections[2].raw_size == 16u);  // .bss: a size with no data
        CHECK(f.sections[2].raw_offset == 0u);
        CHECK_FALSE(f.sections[2].has_file_data());

        REQUIRE(f.symbols.size() == 7u);
        CHECK(f.symbols[0].name == ".file");
        CHECK(f.symbols[0].index == 0u);
        CHECK(f.symbols[0].section_number == sym_debug);
        CHECK(f.symbols[0].storage_class == class_file);
        CHECK(f.symbols[0].aux_count == 1u);
        CHECK(f.symbols[1].name == ".text");
        CHECK(f.symbols[1].index == 2u);  // after .file and its auxiliary record
        CHECK(f.symbols[2].name == "main");
        CHECK(f.symbols[2].index == 4u);
        CHECK(f.symbols[2].type == sym_dtype_function);
        CHECK(f.symbols[2].section_number == 1);
        CHECK(f.symbols[3].name == "a_long_external_name");
        CHECK(f.symbols[3].value == 4u);
        CHECK(f.symbols[4].name == "puts");
        CHECK(f.symbols[4].section_number == sym_undefined);
        CHECK(f.symbols[5].name == "abs_value");
        CHECK(f.symbols[5].section_number == sym_absolute);
        CHECK(f.symbols[5].value == 0x1234u);
        CHECK(f.symbols[6].name == "counter");
        CHECK(f.symbols[6].storage_class == class_static);
        CHECK(f.symbols[6].index == 8u);
    }
}

TEST_CASE("COFF long section names") {
    const CoffImage img = make_sample_coff(machine_amd64);
    const std::uint32_t name_field = img.section_table + 3 * 40;

    // "//" and base 64 digits name the same offset (4) as "/4".
    Bytes base64 = img.bytes;
    for (std::size_t i = 0; i < 8; ++i) poke_u8(base64, name_field + i, static_cast<std::uint8_t>("//AAAAAE"[i]));
    CHECK(parse_coff_object(base64).sections[3].name == ".debug_long_section");

    // Names that only look like long names stay as they are.
    Bytes literal = img.bytes;
    for (std::size_t i = 0; i < 8; ++i) poke_u8(literal, name_field + i, static_cast<std::uint8_t>("/4x\0\0\0\0\0"[i]));
    CHECK(parse_coff_object(literal).sections[3].name == "/4x");

    // Without a symbol table there is no string table, and "/4" is literal.
    Bytes no_symbols = img.bytes;
    poke_u32(no_symbols, 8, 0);
    const PeFile f = parse_coff_object(no_symbols);
    CHECK(f.sections[3].name == "/4");
    CHECK(f.symbols.empty());

    // An offset past the string table.
    Bytes far = img.bytes;
    poke_u8(far, name_field + 1, '9');
    poke_u8(far, name_field + 2, '9');
    const auto e = parse_error(far);
    REQUIRE(e);
    CHECK(e->offset() == img.string_table);
    CHECK(std::string(e->message()).find("outside the table") != std::string::npos);
}

TEST_CASE("COFF string table edge cases") {
    // A string table size of 0 means an empty table: fine without long names.
    CoffBuilder b(machine_amd64);
    b.add_section({".text", scn_cnt_code, Bytes(4)});
    b.add_symbol({"main", 0, 1, sym_dtype_function, class_external, 0});
    CoffImage img = b.build();
    poke_u32(img.bytes, img.string_table, 0);
    const PeFile f = parse_coff_object(img.bytes);
    REQUIRE(f.symbols.size() == 1u);
    CHECK(f.symbols[0].name == "main");

    // A symbol name offset inside the size field.
    CoffImage sample = make_sample_coff(machine_amd64);
    const std::uint32_t long_symbol = sample.symbol_table + 5 * 18;  // a_long_external_name
    REQUIRE(peek_u32(sample.bytes, long_symbol) == 0u);
    poke_u32(sample.bytes, long_symbol + 4, 2);
    const auto e = parse_error(sample.bytes);
    REQUIRE(e);
    CHECK(e->offset() == sample.string_table);
    CHECK(std::string(e->message()).find("size field") != std::string::npos);
}

TEST_CASE("COFF parse options") {
    const CoffImage img = make_sample_coff(machine_i386);
    ParseOptions options;
    options.symbols = false;
    const PeFile f = parse_coff_object(img.bytes, options);
    CHECK(f.symbols.empty());
    CHECK(f.sections[3].name == ".debug_long_section");

    // Unsupported machines are rejected by the object parser.
    Bytes other = img.bytes;
    poke_u16(other, 0, machine_riscv64);
    const auto e = format_error([&] { (void)parse_coff_object(other); });
    REQUIRE(e);
    CHECK(e->offset() == 0u);
}
