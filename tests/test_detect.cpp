// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <string>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::test;

TEST_CASE("format detection") {
    CHECK(detect_format(make_sample_elf(true, Endian::Little).bytes) == FileFormat::Elf);
    CHECK(detect_format(make_sample_elf(false, Endian::Big).bytes) == FileFormat::Elf);
    CHECK(detect_format(make_sample_pe(true).bytes) == FileFormat::Pe);
    CHECK(detect_format(make_sample_pe(false).bytes) == FileFormat::Pe);
    CHECK(detect_format(make_sample_coff(pe::machine_amd64).bytes) == FileFormat::Coff);
    CHECK(detect_format(make_sample_coff(pe::machine_i386).bytes) == FileFormat::Coff);
    CHECK(detect_format(make_sample_coff(pe::machine_arm64).bytes) == FileFormat::Coff);

    CHECK(detect_format({}) == FileFormat::Unknown);
    CHECK(detect_format(to_bytes("\x7f" "EL")) == FileFormat::Unknown);
    CHECK(detect_format(to_bytes("\x7f" "ELF")) == FileFormat::Elf);
    CHECK(detect_format(to_bytes("#!/bin/sh\necho hello world\n")) == FileFormat::Unknown);
    CHECK(detect_format(Bytes(19, std::byte{0})) == FileFormat::Unknown);

    // A COFF header for a machine other than x86, x64 and ARM64.
    Bytes coff = make_sample_coff(pe::machine_amd64).bytes;
    poke_u16(coff, 0, pe::machine_riscv64);
    CHECK(detect_format(coff) == FileFormat::Unknown);

    CHECK(format_name(FileFormat::Elf) == "ELF");
    CHECK(format_name(FileFormat::Pe) == "PE");
    CHECK(format_name(FileFormat::Coff) == "COFF");
    CHECK(format_name(FileFormat::Unknown) == "unknown");
}

TEST_CASE("parse dispatches on the format") {
    CHECK(std::holds_alternative<elf::ElfFile>(parse(make_sample_elf(true, Endian::Little).bytes)));
    const ParsedFile pe_file = parse(make_sample_pe(true).bytes);
    CHECK(as<pe::PeFile>(pe_file).is_image());
    const ParsedFile obj = parse(make_sample_coff(pe::machine_amd64).bytes);
    CHECK_FALSE(as<pe::PeFile>(obj).is_image());

    auto e = parse_error(to_bytes("plain text, not a binary"));
    REQUIRE(e);
    CHECK(e->offset() == 0u);
    CHECK(std::string(e->message()) == "unrecognized file format (not ELF, PE or COFF)");

    e = parse_error({});
    REQUIRE(e);
    CHECK(e->offset() == 0u);
}

TEST_CASE("MZ files without a PE header") {
    // A DOS program: e_lfanew points at something other than "PE\0\0".
    Bytes dos = make_sample_pe(false).bytes;
    poke_u8(dos, 0x80, 'X');
    CHECK(detect_format(dos) == FileFormat::Unknown);
    auto e = parse_error(dos);
    REQUIRE(e);
    CHECK(e->offset() == 0x80u);
    CHECK(std::string(e->message()).find("PE\\0\\0") != std::string::npos);

    // e_lfanew past the end: the error points at the e_lfanew field.
    Bytes far = make_sample_pe(false).bytes;
    poke_u32(far, 0x3c, 0x7ffffff0);
    e = parse_error(far);
    REQUIRE(e);
    CHECK(e->offset() == 0x3cu);
    CHECK(std::string(e->message()).find("e_lfanew 0x7ffffff0") != std::string::npos);

    // Too short for a DOS header.
    e = parse_error(to_bytes("MZ"));
    REQUIRE(e);
    CHECK(e->offset() == 0u);
}

TEST_CASE("read_file") {
    const Bytes data = read_file(data_path("hello.exe"));
    CHECK(data.size() == 3584u);
    CHECK(detect_format(data) == FileFormat::Pe);
    CHECK_THROWS_AS(read_file(data_path("no-such-file.bin")), std::filesystem::filesystem_error);
    CHECK_THROWS_AS(read_file(data_path("src")), std::filesystem::filesystem_error);  // a directory
}
