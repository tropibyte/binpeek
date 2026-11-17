// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Truncated and corrupted input must raise FormatError and never read out of
// bounds. Every mutated image is a fresh, exactly-sized buffer, so that
// AddressSanitizer (the asan preset) reports any read past its end.

#include <cstddef>
#include <cstdint>
#include <exception>
#include <random>
#include <string>
#include <vector>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::test;

namespace {

struct Sample {
    std::string name;
    Bytes bytes;
};

std::vector<Sample> samples() {
    std::vector<Sample> out;
    out.push_back({"ELF32 LE", make_sample_elf(false, Endian::Little).bytes});
    out.push_back({"ELF32 BE", make_sample_elf(false, Endian::Big).bytes});
    out.push_back({"ELF64 LE", make_sample_elf(true, Endian::Little).bytes});
    out.push_back({"ELF64 BE", make_sample_elf(true, Endian::Big).bytes});
    out.push_back({"PE32", make_sample_pe(false).bytes});
    out.push_back({"PE32+", make_sample_pe(true).bytes});
    out.push_back({"COFF i386", make_sample_coff(pe::machine_i386).bytes});
    out.push_back({"COFF ARM64", make_sample_coff(pe::machine_arm64).bytes});
    return out;
}

// Parses data; true when it parsed, false when it was rejected with
// FormatError. Anything else fails the test.
bool try_parse(const Bytes& data, const std::string& what) {
    try {
        (void)parse(data);
        return true;
    } catch (const FormatError&) {
        return false;
    } catch (const std::exception& e) {
        FAIL_CHECK(what << ": unexpected exception: " << e.what());
        return false;
    }
}

std::string contains(const std::optional<FormatError>& e) { return e ? std::string(e->message()) : "(no error)"; }

}  // namespace

TEST_CASE("every truncation of every sample is rejected") {
    for (const Sample& s : samples()) {
        CAPTURE(s.name);
        CHECK(try_parse(s.bytes, s.name));
        std::size_t rejected = 0;
        for (std::size_t n = 0; n < s.bytes.size(); ++n) {
            const Bytes prefix(s.bytes.begin(), s.bytes.begin() + static_cast<std::ptrdiff_t>(n));
            if (!try_parse(prefix, s.name + " cut to " + std::to_string(n))) ++rejected;
        }
        CHECK(rejected == s.bytes.size());
    }
}

TEST_CASE("single-byte corruption anywhere") {
    for (const Sample& s : samples()) {
        CAPTURE(s.name);
        std::size_t parsed = 0, rejected = 0;
        for (std::size_t at = 0; at < s.bytes.size(); ++at) {
            const unsigned original = std::to_integer<unsigned>(s.bytes[at]);
            for (const unsigned value : {0x00u, 0xffu, original ^ 0x01u}) {
                if (original == value) continue;
                Bytes copy = s.bytes;
                copy[at] = static_cast<std::byte>(value);
                (try_parse(copy, s.name + " byte " + std::to_string(at)) ? parsed : rejected)++;
            }
        }
        // Most bytes are data or padding; the headers' bytes are not.
        CHECK(parsed > 0);
        CHECK(rejected > 0);
    }
}

TEST_CASE("boundary values in every 16-, 32- and 64-bit field position") {
    for (const Sample& s : samples()) {
        CAPTURE(s.name);
        const Endian endian = s.name.ends_with("BE") ? Endian::Big : Endian::Little;
        const auto size = static_cast<std::uint64_t>(s.bytes.size());
        // Truncated to the field width: 0xffff... for counts, the high bit,
        // offsets at and just past the end, and a count whose size overflows.
        const std::uint64_t values[] = {0, 0x80000000, 0xffffffffffffffff, size, size + 1, 0x0400000000000001};
        for (std::size_t at = 0; at + 2 <= s.bytes.size(); at += 2) {
            for (const std::uint64_t v : values) {
                Bytes copy = s.bytes;
                if (at % 8 == 0 && at + 8 <= copy.size()) {
                    poke_u64(copy, at, v, endian);
                } else if (at % 4 == 0 && at + 4 <= copy.size()) {
                    poke_u32(copy, at, static_cast<std::uint32_t>(v), endian);
                } else {
                    poke_u16(copy, at, static_cast<std::uint16_t>(v), endian);
                }
                (void)try_parse(copy, s.name + " field at " + std::to_string(at));
            }
        }
    }
}

TEST_CASE("random multi-byte corruption (fixed seed)") {
    // mt19937's output sequence is fixed by the standard; distributions are
    // not, so the raw values are used directly.
    std::mt19937 rng(20261117);
    for (const Sample& s : samples()) {
        CAPTURE(s.name);
        for (int round = 0; round < 1500; ++round) {
            Bytes copy = s.bytes;
            const unsigned changes = 1 + rng() % 8;
            for (unsigned i = 0; i < changes; ++i) {
                copy[rng() % copy.size()] = static_cast<std::byte>(rng() & 0xff);
            }
            (void)try_parse(copy, s.name + " round " + std::to_string(round));
        }
    }
}

// ---- ELF -------------------------------------------------------------------

TEST_CASE("ELF: offsets and sizes past the end") {
    for (const bool is64 : {false, true}) {
        for (const Endian endian : {Endian::Little, Endian::Big}) {
            CAPTURE(is64);
            const ElfImage img = make_sample_elf(is64, endian);
            const ElfFields f = img.fields();
            const std::uint64_t past = img.bytes.size() + 0x100;

            Bytes b = img.bytes;
            poke_word(b, f.e_shoff, past, is64, endian);
            auto e = parse_error(b);
            REQUIRE(e);
            CHECK(e->offset() == past);
            CHECK(contains(e).find("section header table starts past the end") != std::string::npos);

            b = img.bytes;
            poke_word(b, f.e_phoff, past, is64, endian);
            e = parse_error(b);
            REQUIRE(e);
            CHECK(e->offset() == past);
            CHECK(contains(e).find("program header table") != std::string::npos);

            b = img.bytes;
            poke_word(b, img.section_header(".text") + f.sh_offset, past, is64, endian);
            e = parse_error(b);
            REQUIRE(e);
            CHECK(e->offset() == img.section_header(".text"));
            CHECK(contains(e).find("section 5 (.text): data at") != std::string::npos);

            b = img.bytes;
            poke_word(b, img.section_header(".dynstr") + f.sh_size, 0x7fffffff, is64, endian);
            e = parse_error(b);
            REQUIRE(e);
            CHECK(e->offset() == img.section_header(".dynstr"));

            b = img.bytes;
            poke_word(b, img.program_header(1) + f.p_filesz, past, is64, endian);
            e = parse_error(b);
            REQUIRE(e);
            CHECK(e->offset() == img.program_header(1));
            CHECK(contains(e).find("program header 1 (INTERP)") != std::string::npos);

            // NOBITS sections may claim any size.
            b = img.bytes;
            poke_word(b, img.section_header(".bss") + f.sh_size, 0x7fffffff, is64, endian);
            CHECK_FALSE(parse_error(b));
        }
    }
}

TEST_CASE("ELF: counts larger than the file and counts whose sizes overflow") {
    for (const bool is64 : {false, true}) {
        CAPTURE(is64);
        const Endian endian = Endian::Little;
        const ElfImage img = make_sample_elf(is64, endian);
        const ElfFields f = img.fields();

        Bytes b = img.bytes;
        poke_u16(b, f.e_shnum, 0xffff, endian);
        auto e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.shoff);
        CHECK(contains(e).find("section header table (65535 entries") != std::string::npos);

        // Extended section count: sh_size of section 0, times e_shentsize.
        b = img.bytes;
        poke_u16(b, f.e_shnum, 0, endian);
        poke_word(b, img.section_header(0) + f.sh_size, is64 ? 0x0400000000000001ull : 0xffffffffull, is64, endian);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.shoff);
        if (is64) CHECK(contains(e).find("overflow") != std::string::npos);

        // Extended program header count: sh_info of section 0.
        b = img.bytes;
        poke_u16(b, f.e_phnum, elf::pn_xnum, endian);
        poke_u32(b, img.section_header(0) + f.sh_info, 0xffffffff, endian);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.phoff);

        b = img.bytes;
        poke_u16(b, f.e_shentsize, 10, endian);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == f.e_shentsize);

        b = img.bytes;
        poke_u16(b, f.e_shstrndx, 40, endian);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == f.e_shstrndx);
        CHECK(contains(e).find("out of range") != std::string::npos);

        b = img.bytes;
        poke_word(b, img.section_header(".symtab") + f.sh_entsize, 4, is64, endian);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.section_header(".symtab"));
    }
}

TEST_CASE("ELF: string tables without a terminator") {
    for (const bool is64 : {false, true}) {
        CAPTURE(is64);
        const Endian endian = Endian::Big;
        const ElfImage img = make_sample_elf(is64, endian);
        const ElfFields f = img.fields();

        // The last byte of each table is the NUL that ends its last string.
        auto last_byte = [&](std::string_view section) {
            const std::uint64_t header = img.section_header(section);
            const ByteView view(img.bytes);
            const std::uint64_t offset =
                is64 ? view.u64(header + f.sh_offset, endian) : view.u32(header + f.sh_offset, endian);
            const std::uint64_t size =
                is64 ? view.u64(header + f.sh_size, endian) : view.u32(header + f.sh_size, endian);
            return offset + size - 1;
        };
        for (const char* table : {".shstrtab", ".dynstr", ".strtab"}) {
            CAPTURE(table);
            Bytes b = img.bytes;
            poke_u8(b, last_byte(table), 'X');
            const auto e = parse_error(b);
            REQUIRE(e);
            CHECK(contains(e).find("is not NUL-terminated") != std::string::npos);
            CHECK(e->offset() >= img.data_offset(table));
            CHECK(e->offset() < last_byte(table));
        }

        // A name index past the end of its table.
        Bytes b = img.bytes;
        poke_u32(b, img.section_header(".text") + f.sh_name, 0x10000, endian);
        auto e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.data_offset(".shstrtab"));
        CHECK(contains(e).find("outside the table") != std::string::npos);

        // The interpreter path must end in a NUL within PT_INTERP.
        b = img.bytes;
        poke_u8(b, img.data_offset(".interp") + 19, 'x');
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.data_offset(".interp"));
    }
}

TEST_CASE("ELF: malformed identification, notes and dynamic entries") {
    const ElfImage img = make_sample_elf(true, Endian::Little);
    const ElfFields f = img.fields();

    Bytes b = img.bytes;
    poke_u8(b, 4, 3);
    auto e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == 4u);
    CHECK(contains(e) == "invalid ELF class 3");

    b = img.bytes;
    poke_u8(b, 5, 0);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == 5u);

    // A note descriptor that runs past its section.
    b = img.bytes;
    poke_u32(b, img.data_offset(".note.gnu.build-id") + 4, 0x1000);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == img.data_offset(".note.gnu.build-id"));
    CHECK(contains(e).find("note") != std::string::npos);

    // DT_NEEDED naming an offset past .dynstr.
    b = img.bytes;
    poke_u64(b, img.data_offset(".dynamic") + 8, 0x5000);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == img.data_offset(".dynstr"));

    // Without section headers, DT_STRTAB must lie in a loadable segment.
    b = img.bytes;
    poke_u64(b, f.e_shoff, 0);
    poke_u64(b, img.data_offset(".dynamic") + 5 * 16 + 8, 0x10);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == img.data_offset(".dynamic"));
    CHECK(contains(e).find("DT_STRTAB 0x10") != std::string::npos);

    // .symtab linked to a string table index that does not exist.
    b = img.bytes;
    poke_u32(b, img.section_header(".symtab") + f.sh_link, 1000);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == img.section_header(".symtab"));
}

// ---- PE --------------------------------------------------------------------

TEST_CASE("PE: headers, section table and section data") {
    for (const bool plus : {false, true}) {
        CAPTURE(plus);
        const PeImage img = make_sample_pe(plus);

        Bytes b = img.bytes;
        poke_u16(b, img.pe_offset + 6, 0xffff);  // NumberOfSections
        auto e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.section_table);
        CHECK(contains(e).find("section table (65535 entries of 40 bytes)") != std::string::npos);

        b = img.bytes;
        poke_u16(b, img.pe_offset + 20, 0xfff0);  // SizeOfOptionalHeader
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.optional_header);

        b = img.bytes;
        poke_u32(b, img.data_directory(0) - 4, 0x7fffffff);  // NumberOfRvaAndSizes
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.data_directory(0) - 4);

        b = img.bytes;
        poke_u16(b, img.optional_header, 0x107);  // a ROM image
        e = parse_error(b);
        REQUIRE(e);
        CHECK(contains(e) == "unknown optional header magic 0x107");

        const std::size_t idata = 4;
        b = img.bytes;
        poke_u32(b, img.section_header(idata) + 16, 0x7ffff000);  // SizeOfRawData
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.section_header(idata));
        CHECK(contains(e).find("section 5 (.idata): raw data") != std::string::npos);

        b = img.bytes;
        poke_u32(b, img.section_header(idata) + 20, 0x7ffff000);  // PointerToRawData
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.section_header(idata));
    }
}

TEST_CASE("PE: import directory corruption") {
    for (const bool plus : {false, true}) {
        CAPTURE(plus);
        const PeImage img = make_sample_pe(plus);
        const std::uint32_t idata_rva = img.rvas[4];
        const std::uint32_t idata_end = img.raw_offsets[4] + img.raw_sizes[4];

        // RVA outside every section.
        Bytes b = img.bytes;
        poke_u32(b, img.data_directory(pe::dir_import), 0x90000);
        auto e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.data_directory(pe::dir_import));
        CHECK(contains(e) == "import directory RVA 0x90000 is not inside any section's data in the file");

        // RVA inside .bss, which has no file data.
        b = img.bytes;
        poke_u32(b, img.data_directory(pe::dir_import), img.rvas[2]);
        CHECK(parse_error(b));

        // DLL name RVA outside every section.
        b = img.bytes;
        poke_u32(b, img.import_directory + 12, 0x123456);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == img.import_directory + 12);

        // Descriptors that run into the end of the section (made as large in
        // memory as in the file, so the RVA stays inside it).
        b = img.bytes;
        poke_u32(b, img.section_header(4) + 8, img.raw_sizes[4]);
        poke_u32(b, img.data_directory(pe::dir_import), idata_rva + img.raw_sizes[4] - 10);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(contains(e).find("no null terminator") != std::string::npos);

        // A lookup table that never ends within the file: fill everything
        // from KERNEL32's table to the end of the file with ordinal entries.
        b = img.bytes;
        const std::uint32_t table = img.lookup_tables[0];
        for (std::uint32_t at = table; at + (plus ? 8 : 4) <= idata_end; at += plus ? 8 : 4) {
            poke_word(b, at, plus ? 0x8000000000000001ull : 0x80000001ull, plus, Endian::Little);
        }
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == table);
        CHECK(contains(e).find("has no null terminator within its section") != std::string::npos);

        // A hint/name RVA outside every section.
        b = img.bytes;
        poke_word(b, table, 0x7ffffff0, plus, Endian::Little);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == table);

        // A DLL name that runs to the end of the section without a NUL.
        b = img.bytes;
        const std::uint32_t user32_name =
            img.raw_offsets[4] + (peek_u32(img.bytes, img.import_directory + 20 + 12) - idata_rva);
        for (std::uint32_t at = user32_name; at < idata_end; ++at) poke_u8(b, at, 'A');
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == user32_name);
        CHECK(contains(e).find("not NUL-terminated") != std::string::npos);
    }

    // PE32+ lookup entries keep bits 31 to 62 clear.
    const PeImage img = make_sample_pe(true);
    Bytes b = img.bytes;
    poke_u64(b, img.lookup_tables[0], 0x0000000100005000);
    const auto e = parse_error(b);
    REQUIRE(e);
    CHECK(contains(e).find("neither an ordinal nor a hint/name RVA") != std::string::npos);
}

TEST_CASE("PE: export directory corruption") {
    for (const bool plus : {false, true}) {
        CAPTURE(plus);
        const PeImage img = make_sample_pe(plus);
        const std::uint32_t dir = img.export_directory;
        const std::uint32_t edata_end = img.raw_offsets[3] + img.raw_sizes[3];

        // NumberOfFunctions whose table size overflows 32 bits.
        Bytes b = img.bytes;
        poke_u32(b, dir + 20, 0x40000001);
        auto e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == dir + 40);
        CHECK(contains(e).find("export address table (1073741825 entries)") != std::string::npos);

        b = img.bytes;
        poke_u32(b, dir + 24, 0x40000001);  // NumberOfNames
        e = parse_error(b);
        REQUIRE(e);
        CHECK(contains(e).find("export name pointer table") != std::string::npos);

        b = img.bytes;
        poke_u32(b, dir + 32, 0xdead0000);  // AddressOfNames
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == dir + 32);

        // A name whose ordinal is past the address table.
        b = img.bytes;
        const std::uint32_t ordinals = dir + 40 + 5 * 4 + 4 * 4;
        poke_u16(b, ordinals, 5);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == ordinals);
        CHECK(contains(e).find("refers to function 5") != std::string::npos);

        b = img.bytes;
        poke_u32(b, dir + 16, 0xfffffffe);  // Base
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == dir + 16);

        // The directory itself cut off by the end of its section.
        b = img.bytes;
        poke_u32(b, img.section_header(3) + 8, img.raw_sizes[3]);
        poke_u32(b, img.data_directory(pe::dir_export), img.rvas[3] + img.raw_sizes[3] - 20);
        e = parse_error(b);
        REQUIRE(e);
        CHECK(contains(e).find("cut off") != std::string::npos);

        // The forwarder string, last in the section, without its NUL.
        b = img.bytes;
        const std::uint32_t forwarder = dir + static_cast<std::uint32_t>(
            peek_u32(img.bytes, dir + 40 + 4 * 4) - img.rvas[3]);
        for (std::uint32_t at = forwarder; at < edata_end; ++at) poke_u8(b, at, 'F');
        e = parse_error(b);
        REQUIRE(e);
        CHECK(e->offset() == forwarder);
    }
}

// ---- COFF ------------------------------------------------------------------

TEST_CASE("COFF: symbol and string table corruption") {
    // Without long section names, so the symbol table is the first thing
    // that needs the string table.
    CoffBuilder builder(pe::machine_amd64);
    builder.add_section({".text", pe::scn_cnt_code, Bytes(8)});
    builder.add_symbol({"main", 0, 1, pe::sym_dtype_function, pe::class_external, 0});
    builder.add_symbol({"a_long_external_name", 0, 0, 0, pe::class_external, 0});
    const CoffImage simple = builder.build();
    const auto simple_size = static_cast<std::uint32_t>(simple.bytes.size());

    Bytes b = simple.bytes;
    poke_u32(b, 8, simple_size + 0x40);  // PointerToSymbolTable
    auto e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == simple_size + 0x40);

    // NumberOfSymbols * 18 does not fit in 32 bits.
    b = simple.bytes;
    poke_u32(b, 12, 0xffffffff);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == simple.symbol_table);
    CHECK(contains(e).find("COFF symbol table (4294967295 entries") != std::string::npos);

    // With a long section name the string table is read for the sections.
    const CoffImage img = make_sample_coff(pe::machine_amd64);
    const auto size = static_cast<std::uint32_t>(img.bytes.size());
    b = img.bytes;
    poke_u32(b, 8, size + 0x40);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == size + 0x40 + 9 * 18);
    CHECK(contains(e).find("COFF string table size") != std::string::npos);

    b = img.bytes;
    poke_u32(b, img.string_table, 0x10000);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == img.string_table);

    // The last string loses its terminator.
    b = img.bytes;
    poke_u8(b, size - 1, 'X');
    e = parse_error(b);
    REQUIRE(e);
    CHECK(contains(e).find("is not NUL-terminated") != std::string::npos);

    // The last symbol claims auxiliary records past the end of the table.
    b = img.bytes;
    const std::uint32_t last = img.symbol_table + 8 * 18;
    poke_u8(b, last + 17, 5);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == last + 17);
    CHECK(contains(e).find("auxiliary records") != std::string::npos);

    // Section table larger than the file.
    b = img.bytes;
    poke_u16(b, 2, 0xffff);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == 20u);

    // Section data past the end.
    b = img.bytes;
    poke_u32(b, img.section_table + 16, 0x100000);
    e = parse_error(b);
    REQUIRE(e);
    CHECK(e->offset() == img.section_table);
}
