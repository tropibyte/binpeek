// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Builds small ELF, PE and COFF images in memory for the tests, and records
// where their structures are so that tests can corrupt them.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "binpeek/bytes.hpp"

namespace binpeek::test {

using Bytes = std::vector<std::byte>;

Bytes to_bytes(std::string_view s);

/// Appends integers in a fixed byte order.
class ByteWriter {
public:
    explicit ByteWriter(Endian endian = Endian::Little) : endian_(endian) {}

    std::size_t size() const noexcept { return data_.size(); }
    void u8(std::uint8_t v);
    void u16(std::uint16_t v);
    void u32(std::uint32_t v);
    void u64(std::uint64_t v);
    /// u64 when wide, else u32 (the value must fit).
    void word(std::uint64_t v, bool wide);
    void raw(std::span<const std::byte> bytes);
    void text(std::string_view s);   ///< without a terminator
    void cstr(std::string_view s);   ///< with a NUL
    void zeros(std::size_t count);
    void align(std::size_t alignment);
    void pad_to(std::size_t offset);
    Bytes take() { return std::move(data_); }

private:
    Endian endian_;
    Bytes data_;
};

void poke_u8(Bytes& image, std::uint64_t at, std::uint8_t v);
void poke_u16(Bytes& image, std::uint64_t at, std::uint16_t v, Endian endian = Endian::Little);
void poke_u32(Bytes& image, std::uint64_t at, std::uint32_t v, Endian endian = Endian::Little);
void poke_u64(Bytes& image, std::uint64_t at, std::uint64_t v, Endian endian = Endian::Little);
void poke_word(Bytes& image, std::uint64_t at, std::uint64_t v, bool wide, Endian endian);
std::uint32_t peek_u32(const Bytes& image, std::uint64_t at, Endian endian = Endian::Little);

/// A string table under construction; offset 0 is the empty string.
class StringTableWriter {
public:
    std::uint32_t add(std::string_view s);
    Bytes bytes() const { return to_bytes(text_); }

private:
    std::string text_{std::string(1, '\0')};
};

// ---- ELF -------------------------------------------------------------------

/// Offsets of ELF header and table fields for one class.
struct ElfFields {
    std::size_t e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
    std::size_t sh_name, sh_type, sh_offset, sh_size, sh_link, sh_info, sh_entsize;
    std::size_t p_offset, p_filesz;
    std::size_t sym_size, dyn_size;
};

ElfFields elf_fields(bool is64);

struct ElfSymbolSpec {
    std::string name{};
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t type = 0;
    std::uint8_t bind = 0;
    std::uint8_t visibility = 0;
    std::uint16_t shndx = 0;
};

/// A symbol table (null symbol first), adding the names to strings.
Bytes elf_symbols(bool is64, Endian endian, const std::vector<ElfSymbolSpec>& symbols, StringTableWriter& strings);
/// Dynamic entries followed by DT_NULL.
Bytes elf_dynamic(bool is64, Endian endian, const std::vector<std::pair<std::int64_t, std::uint64_t>>& entries);
Bytes elf_note(Endian endian, std::string_view owner, std::uint32_t type, std::span<const std::byte> desc);

struct ElfSectionSpec {
    std::string name{};
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    Bytes data{};
    std::uint64_t nobits_size = 0;  ///< size of an SHT_NOBITS section
    std::string link{};               ///< name of the linked section
    std::uint32_t info = 0;
    std::uint64_t align = 1;
    std::uint64_t entsize = 0;
};

struct ElfSegmentSpec {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    /// The section the segment covers; empty for a PT_LOAD of the whole
    /// file up to the end of the last SHF_ALLOC section.
    std::string section{};
    std::uint64_t align = 1;
};

struct ElfImage {
    Bytes bytes{};
    bool is64 = false;
    Endian endian = Endian::Little;
    std::uint64_t phoff = 0;
    std::uint64_t shoff = 0;
    std::vector<std::string> names{};  ///< section names by index
    std::vector<std::uint64_t> data_offsets{};

    ElfFields fields() const { return elf_fields(is64); }
    std::size_t index_of(std::string_view name) const;
    std::uint64_t section_header(std::size_t index) const;
    std::uint64_t section_header(std::string_view name) const { return section_header(index_of(name)); }
    std::uint64_t program_header(std::size_t index) const;
    std::uint64_t data_offset(std::string_view name) const { return data_offsets[index_of(name)]; }
};

/// Lays out the ELF header, program headers, section data in order,
/// .shstrtab and, last, the section header table. SHF_ALLOC sections get
/// the address base_address + file offset.
class ElfBuilder {
public:
    static constexpr std::uint64_t base_address = 0x400000;

    ElfBuilder(bool is64, Endian endian, std::uint16_t type, std::uint16_t machine);
    void add_section(ElfSectionSpec spec) { sections_.push_back(std::move(spec)); }
    void add_segment(ElfSegmentSpec spec) { segments_.push_back(std::move(spec)); }
    void set_entry(std::uint64_t entry) { entry_ = entry; }
    ElfImage build() const;

private:
    bool is64_;
    Endian endian_;
    std::uint16_t type_;
    std::uint16_t machine_;
    std::uint64_t entry_ = 0;
    std::vector<ElfSectionSpec> sections_;
    std::vector<ElfSegmentSpec> segments_;
};

/// An executable with .interp, a GNU build-ID note, .dynsym/.dynstr, .text,
/// .dynamic (NEEDED libc.so.6 and libm.so.6, SONAME, RPATH, RUNPATH), .data,
/// .bss, .symtab/.strtab, and PT_PHDR, PT_INTERP, PT_LOAD, PT_DYNAMIC and
/// PT_NOTE. The machine is i386, x86-64, MIPS or PowerPC64 by class and
/// byte order.
ElfImage make_sample_elf(bool is64, Endian endian);

/// The build ID make_sample_elf() stores: bytes 0x10 to 0x23.
std::vector<std::uint8_t> sample_build_id();

// ---- PE/COFF ---------------------------------------------------------------

struct PeSectionSpec {
    std::string name{};  ///< longer than 8 bytes only in COFF objects
    std::uint32_t characteristics = 0;
    Bytes data{};
    std::uint32_t uninitialized_size = 0;  ///< for a section with no data
};

struct PeImportFunctionSpec {
    std::string name{};
    std::uint16_t hint = 0;
    std::optional<std::uint16_t> ordinal{};
};

struct PeImportSpec {
    std::string dll{};
    std::vector<PeImportFunctionSpec> functions{};
};

struct PeExportSlot {
    std::uint32_t rva = 0;   ///< ignored for forwarders
    std::string forwarder{};   ///< "DLL.Function"
    std::vector<std::string> names{};
};

struct PeExportSpec {
    std::string dll_name{};
    std::uint32_t ordinal_base = 1;
    std::vector<PeExportSlot> slots{};
};

struct PeImage {
    Bytes bytes{};
    bool pe32_plus = false;
    std::uint32_t pe_offset = 0;
    std::uint32_t optional_header = 0;
    std::uint32_t section_table = 0;
    std::vector<std::uint32_t> raw_offsets{};  ///< per section
    std::vector<std::uint32_t> rvas{};         ///< per section
    std::vector<std::uint32_t> raw_sizes{};    ///< per section
    // File offsets of the tables, 0 when absent.
    std::uint32_t import_directory = 0;
    std::vector<std::uint32_t> lookup_tables{};  ///< per imported DLL
    std::uint32_t export_directory = 0;

    std::uint32_t data_directory(std::size_t index) const {
        return optional_header + (pe32_plus ? 112u : 96u) + 8u * static_cast<std::uint32_t>(index);
    }
    std::uint32_t section_header(std::size_t index) const {
        return section_table + 40u * static_cast<std::uint32_t>(index);
    }
};

/// A PE image: DOS header, PE signature at 0x80, COFF and optional headers,
/// the section table, then each section's data padded to 0x200. Sections
/// are 0x1000 apart in memory from RVA 0x1000; exports go in ".edata" and
/// imports in ".idata", which comes last and ends the file.
class PeBuilder {
public:
    PeBuilder(bool pe32_plus, std::uint16_t machine) : pe32_plus_(pe32_plus), machine_(machine) {}
    void add_section(PeSectionSpec spec) { sections_.push_back(std::move(spec)); }
    void set_imports(std::vector<PeImportSpec> imports) { imports_ = std::move(imports); }
    void set_exports(PeExportSpec exports) { exports_ = std::move(exports); }
    void set_characteristics(std::uint16_t c) { characteristics_ = c; }
    void set_subsystem(std::uint16_t s) { subsystem_ = s; }
    void set_dll_characteristics(std::uint16_t c) { dll_characteristics_ = c; }
    PeImage build() const;

private:
    bool pe32_plus_;
    std::uint16_t machine_;
    std::uint16_t characteristics_ = 0x0022;  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    std::uint16_t subsystem_ = 3;
    std::uint16_t dll_characteristics_ = 0x0140;
    std::vector<PeSectionSpec> sections_;
    std::vector<PeImportSpec> imports_;
    std::optional<PeExportSpec> exports_;
};

/// A DLL with .text, .data, exports from "sample.dll" (base 5: alpha, beta
/// and its alias beta_alias, an unused slot, ordinal 8 with no name, and Quit
/// forwarded to KERNEL32.ExitProcess) and imports from KERNEL32.dll
/// (ExitProcess, GetStdHandle) and USER32.dll (MessageBoxA, ordinal 17).
PeImage make_sample_pe(bool pe32_plus);

struct CoffSymbolSpec {
    std::string name{};  ///< longer than 8 bytes goes to the string table
    std::uint32_t value = 0;
    std::int16_t section = 0;
    std::uint16_t type = 0;
    std::uint8_t storage_class = 0;
    std::uint8_t aux_count = 0;  ///< zero-filled auxiliary records follow
};

struct CoffImage {
    Bytes bytes{};
    std::uint32_t section_table = 0;
    std::uint32_t symbol_table = 0;
    std::uint32_t string_table = 0;
    std::vector<std::uint32_t> raw_offsets{};
};

/// A COFF object: header, section table, section data, symbol table and
/// string table, in that order.
class CoffBuilder {
public:
    explicit CoffBuilder(std::uint16_t machine) : machine_(machine) {}
    void add_section(PeSectionSpec spec) { sections_.push_back(std::move(spec)); }
    void add_symbol(CoffSymbolSpec spec) { symbols_.push_back(std::move(spec)); }
    CoffImage build() const;

private:
    std::uint16_t machine_;
    std::vector<PeSectionSpec> sections_;
    std::vector<CoffSymbolSpec> symbols_;
};

/// Sections .text, .data, .bss (no data) and .debug_long_section (a long
/// name); symbols .file (1 aux), .text (1 aux), main, a long-named external,
/// an undefined external, an absolute symbol and a static.
CoffImage make_sample_coff(std::uint16_t machine);

}  // namespace binpeek::test
