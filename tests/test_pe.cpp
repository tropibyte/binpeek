// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstdint>
#include <string>
#include <vector>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::pe;
using namespace binpeek::test;

TEST_CASE("PE sample images: PE32 and PE32+") {
    for (const bool plus : {false, true}) {
        CAPTURE(plus);
        const PeImage img = make_sample_pe(plus);
        const PeFile f = parse_pe(img.bytes);

        REQUIRE(f.dos);
        CHECK(f.dos->magic == 0x5a4du);
        CHECK(f.dos->pe_offset == 0x80u);
        CHECK(f.dos->last_page_bytes == 0x90u);
        CHECK(f.dos->page_count == 3u);
        CHECK(f.is_image());
        CHECK(f.is_dll());
        CHECK(f.is_pe32_plus() == plus);

        CHECK(f.header.machine == (plus ? machine_amd64 : machine_i386));
        CHECK(f.header.section_count == 5u);
        CHECK(f.header.timestamp == 0x65000000u);
        CHECK(f.header.symbol_table_offset == 0u);
        CHECK(f.header.optional_header_size == (plus ? 240u : 224u));
        CHECK((f.header.characteristics & file_dll) != 0);

        REQUIRE(f.optional_header);
        const OptionalHeader& o = *f.optional_header;
        CHECK(o.magic == (plus ? magic_pe32_plus : magic_pe32));
        CHECK(o.linker_major == 14u);
        CHECK(o.linker_minor == 38u);
        CHECK(o.size_of_code == 0x200u);
        CHECK(o.size_of_uninitialized_data == 0x80u);
        CHECK(o.entry_point == 0x1000u);
        CHECK(o.base_of_code == 0x1000u);
        CHECK(o.base_of_data == (plus ? 0u : 0x2000u));
        CHECK(o.image_base == (plus ? 0x180000000u : 0x10000000u));
        CHECK(o.section_alignment == 0x1000u);
        CHECK(o.file_alignment == 0x200u);
        CHECK(o.os_major == 6u);
        CHECK(o.image_major == 1u);
        CHECK(o.image_minor == 2u);
        CHECK(o.size_of_image == 0x6000u);
        CHECK(o.size_of_headers == 0x400u);
        CHECK(o.subsystem == subsystem_windows_gui);
        CHECK((o.dll_characteristics & dllchar_nx_compat) != 0);
        CHECK(((o.dll_characteristics & dllchar_high_entropy_va) != 0) == plus);
        CHECK(o.stack_reserve == 0x100000u);
        CHECK(o.heap_commit == 0x1000u);
        CHECK(o.rva_count == 16u);
        CHECK(o.directories.size() == 16u);
        CHECK(o.directory(dir_export).rva == 0x4000u);
        CHECK(o.directory(dir_import).rva == 0x5000u);
        CHECK(o.directory(dir_resource).rva == 0u);
        CHECK(o.directory(40).rva == 0u);

        CHECK(section_names(f) == std::vector<std::string>{".text", ".data", ".bss", ".edata", ".idata"});
        const Section* text = f.find_section(".text");
        REQUIRE(text != nullptr);
        CHECK(text->virtual_address == 0x1000u);
        CHECK(text->virtual_size == 64u);
        CHECK(text->raw_offset == 0x400u);
        CHECK(text->raw_size == 0x200u);
        CHECK(text->characteristics == (scn_cnt_code | scn_mem_execute | scn_mem_read));
        const Section* bss = f.find_section(".bss");
        REQUIRE(bss != nullptr);
        CHECK(bss->virtual_size == 0x80u);
        CHECK_FALSE(bss->has_file_data());
        CHECK(f.find_section(".rsrc") == nullptr);
        CHECK(f.symbols.empty());

        // Imports
        REQUIRE(f.imports.size() == 2u);
        const ImportedDll& k32 = f.imports[0];
        CHECK(k32.name == "KERNEL32.dll");
        REQUIRE(k32.functions.size() == 2u);
        CHECK(k32.functions[0].name == "ExitProcess");
        CHECK(k32.functions[0].hint == 0x163u);
        CHECK_FALSE(k32.functions[0].ordinal);
        CHECK(k32.functions[0].iat_rva == k32.address_table_rva);
        CHECK(k32.functions[1].name == "GetStdHandle");
        CHECK(k32.functions[1].iat_rva == k32.address_table_rva + (plus ? 8u : 4u));
        CHECK(k32.lookup_table_rva != k32.address_table_rva);
        const ImportedDll* user32 = find_import(f, "USER32.dll");
        REQUIRE(user32 != nullptr);
        REQUIRE(user32->functions.size() == 2u);
        CHECK(user32->functions[0].name == "MessageBoxA");
        CHECK(user32->functions[0].hint == 0x285u);
        CHECK(user32->functions[1].name.empty());
        REQUIRE(user32->functions[1].ordinal);
        CHECK(*user32->functions[1].ordinal == 17u);

        // Exports
        REQUIRE(f.exports);
        const ExportDirectory& e = *f.exports;
        CHECK(e.dll_name == "sample.dll");
        CHECK(e.ordinal_base == 5u);
        CHECK(e.function_count == 5u);
        CHECK(e.name_count == 4u);
        CHECK(e.major_version == 1u);
        REQUIRE(e.functions.size() == 5u);
        CHECK(e.functions[0].ordinal == 5u);
        CHECK(e.functions[0].name == "alpha");
        CHECK(e.functions[0].rva == 0x1000u);
        CHECK(e.functions[1].ordinal == 6u);
        CHECK(e.functions[1].name == "beta");
        CHECK(e.functions[2].ordinal == 6u);
        CHECK(e.functions[2].name == "beta_alias");
        CHECK(e.functions[2].rva == 0x1010u);
        // Ordinal 7 is an unused slot and is left out.
        CHECK(e.functions[3].ordinal == 8u);
        CHECK(e.functions[3].name.empty());
        CHECK(e.functions[3].rva == 0x1020u);
        CHECK(e.functions[4].ordinal == 9u);
        CHECK(e.functions[4].name == "Quit");
        CHECK(e.functions[4].forwarder == "KERNEL32.ExitProcess");
        CHECK(e.functions[4].rva > 0x4000u);
        CHECK(e.functions[4].rva < 0x5000u);
    }
}

TEST_CASE("PE RVA to file offset") {
    const PeImage img = make_sample_pe(true);
    const PeFile f = parse_pe(img.bytes);
    CHECK(rva_to_offset(f, 0x1000) == 0x400u);
    CHECK(rva_to_offset(f, 0x103f) == 0x43fu);
    CHECK_FALSE(rva_to_offset(f, 0x1040).has_value());  // past VirtualSize
    CHECK(rva_to_offset(f, 0x2008) == 0x608u);
    CHECK_FALSE(rva_to_offset(f, 0x3010).has_value());  // .bss has no file data
    CHECK(rva_to_offset(f, 0x5000) == img.import_directory);
    CHECK(rva_to_offset(f, 0x3c) == 0x3cu);              // headers map to themselves
    CHECK_FALSE(rva_to_offset(f, 0x400).has_value());   // past SizeOfHeaders
    CHECK_FALSE(rva_to_offset(f, 0x90000).has_value());
    CHECK_FALSE(rva_to_offset(f, 0xffffffff).has_value());

    // VirtualSize 0 means SizeOfRawData.
    Bytes zero = img.bytes;
    poke_u32(zero, img.section_header(0) + 8, 0);
    const PeFile z = parse_pe(zero);
    CHECK(rva_to_offset(z, 0x11ff) == 0x5ffu);
    CHECK_FALSE(rva_to_offset(z, 0x1200).has_value());
}

TEST_CASE("PE overlapping sections") {
    PeImage img = make_sample_pe(false);
    // Move .data onto .text's addresses.
    poke_u32(img.bytes, img.section_header(1) + 12, 0x1000);
    const auto e = parse_error(img.bytes);
    REQUIRE(e);
    CHECK(e->offset() == img.section_header(1));
    CHECK(std::string(e->message()).find("overlap in memory") != std::string::npos);

    // Only the RVA-based tables need the mapping.
    ParseOptions options;
    options.imports = false;
    options.exports = false;
    const PeFile f = parse_pe(img.bytes, options);
    CHECK(f.sections.size() == 5u);
    CHECK(rva_to_offset(f, 0x1000) == 0x400u);  // the first section in table order
}

TEST_CASE("PE parse options") {
    const PeImage img = make_sample_pe(true);
    ParseOptions options;
    options.imports = false;
    const PeFile no_imports = parse_pe(img.bytes, options);
    CHECK(no_imports.imports.empty());
    CHECK(no_imports.exports);
    options.exports = false;
    const PeFile neither = parse_pe(img.bytes, options);
    CHECK_FALSE(neither.exports);
}

TEST_CASE("PE images without imports or exports") {
    PeBuilder b(true, machine_arm64);
    b.add_section({".text", scn_cnt_code | scn_mem_execute | scn_mem_read, Bytes(8, std::byte{0x1f})});
    const PeImage img = b.build();
    const PeFile f = parse_pe(img.bytes);
    CHECK(f.header.machine == machine_arm64);
    CHECK(f.imports.empty());
    CHECK_FALSE(f.exports);
    CHECK_FALSE(f.is_dll());
    CHECK(f.sections.size() == 1u);
}

TEST_CASE("PE display names") {
    CHECK(machine_name(machine_amd64) == "AMD64");
    CHECK(machine_name(machine_arm64) == "ARM64");
    CHECK(machine_name(0x1234) == "machine 0x1234");
    CHECK(subsystem_name(subsystem_windows_cui) == "Windows CUI");
    CHECK(subsystem_name(subsystem_efi_application) == "EFI application");
    CHECK(subsystem_name(99) == "subsystem 99");
    CHECK(directory_name(dir_import) == "Import");
    CHECK(directory_name(dir_clr_runtime) == "CLR runtime");
    CHECK(directory_name(20) == "#20");
    CHECK(storage_class_name(class_external) == "EXTERNAL");
    CHECK(storage_class_name(class_end_of_function) == "END_OF_FUNCTION");
    CHECK(storage_class_name(200) == "200");
    CHECK(symbol_section_name(sym_undefined) == "UNDEF");
    CHECK(symbol_section_name(sym_absolute) == "ABS");
    CHECK(symbol_section_name(sym_debug) == "DEBUG");
    CHECK(symbol_section_name(3) == "3");
    CHECK(file_characteristics_string(0x2022) == "EXECUTABLE_IMAGE LARGE_ADDRESS_AWARE DLL");
    CHECK(file_characteristics_string(0).empty());
    CHECK(dll_characteristics_string(0x8160) == "HIGH_ENTROPY_VA DYNAMIC_BASE NX_COMPAT TERMINAL_SERVER_AWARE");
    CHECK(dll_characteristics_string(0x0141) == "DYNAMIC_BASE NX_COMPAT 0x1");
    CHECK(section_characteristics_string(0x60500020) == "CODE ALIGN_16BYTES");
    CHECK(section_characteristics_string(0x42000040) == "INITIALIZED_DATA DISCARDABLE");
    CHECK(section_characteristics_string(0x00e00000) == "ALIGN_8192BYTES");
    CHECK(section_characteristics_string(0x00f00000) == "ALIGN_0xf");
    CHECK(section_permissions(0xc0000040) == "RW-");
    CHECK(section_permissions(0x60000020) == "R-X");
    CHECK(section_permissions(0) == "---");
}
