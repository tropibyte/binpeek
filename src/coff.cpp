// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// COFF file header, section table, symbol table and string table, and COFF
// object files.

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "binpeek/error.hpp"
#include "binpeek/pe.hpp"
#include "coff.hpp"

namespace binpeek::pe {

namespace detail {

namespace {

// A NUL-padded fixed-size name field: the bytes up to the first NUL.
std::string_view fixed_name(std::span<const std::byte> field) noexcept {
    const std::string_view text(reinterpret_cast<const char*>(field.data()), field.size());
    return text.substr(0, text.find('\0'));
}

int base64_digit(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::string section_label(const Section& s, std::size_t index) {
    return std::format("section {} ({})", index + 1, s.name);
}

}  // namespace

FileHeader read_file_header(ByteView view, std::uint64_t offset) {
    view.require(offset, file_header_size, "COFF file header");
    Cursor c(view, offset, Endian::Little);
    FileHeader h;
    h.machine = c.u16();
    h.section_count = c.u16();
    h.timestamp = c.u32();
    h.symbol_table_offset = c.u32();
    h.symbol_count = c.u32();
    h.optional_header_size = c.u16();
    h.characteristics = c.u16();
    return h;
}

std::vector<Section> read_section_table(ByteView view, std::uint64_t offset, std::uint16_t count,
                                        binpeek::detail::StringBudget& budget) {
    view.require_array(offset, count, section_header_size, "section table");
    std::vector<Section> sections;
    sections.reserve(count);
    for (std::uint64_t i = 0; i < count; ++i) {
        const std::uint64_t at = offset + i * section_header_size;
        Cursor c(view, at, Endian::Little);
        Section s;
        s.short_name = budget.take(fixed_name(c.bytes(8)), at);
        s.name = s.short_name;
        s.virtual_size = c.u32();
        s.virtual_address = c.u32();
        s.raw_size = c.u32();
        s.raw_offset = c.u32();
        s.relocations_offset = c.u32();
        s.line_numbers_offset = c.u32();
        s.relocation_count = c.u16();
        s.line_number_count = c.u16();
        s.characteristics = c.u32();
        sections.push_back(std::move(s));
    }
    return sections;
}

std::optional<StringTable> read_string_table(ByteView view, const FileHeader& header) {
    if (header.symbol_table_offset == 0) return std::nullopt;
    const std::uint64_t offset =
        std::uint64_t{header.symbol_table_offset} + std::uint64_t{header.symbol_count} * symbol_record_size;
    view.require(offset, 4, "COFF string table size");
    // The size counts its own four bytes; writers that leave it 0 mean "empty".
    const std::uint32_t size = view.u32(offset, Endian::Little);
    return StringTable(view, offset, size < 4 ? 4 : size, "COFF string table");
}

std::string string_at(const StringTable& strings, std::uint64_t offset, binpeek::detail::StringBudget& budget) {
    if (offset < 4) {
        throw FormatError(strings.offset(),
                          std::format("COFF string table offset {} points into the table's size field", offset));
    }
    return budget.take(strings.get(offset), strings.offset());
}

std::optional<std::uint64_t> long_name_offset(std::string_view short_name) noexcept {
    if (short_name.size() < 2 || short_name[0] != '/') return std::nullopt;
    if (short_name[1] == '/') {
        // "//" and up to six base-64 digits, for offsets past 9,999,999.
        const std::string_view digits = short_name.substr(2);
        if (digits.empty() || digits.size() > 6) return std::nullopt;
        std::uint64_t value = 0;
        for (const char c : digits) {
            const int d = base64_digit(c);
            if (d < 0) return std::nullopt;
            value = value * 64 + static_cast<std::uint64_t>(d);
        }
        return value;
    }
    const std::string_view digits = short_name.substr(1);
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (ec != std::errc{} || end != digits.data() + digits.size()) return std::nullopt;
    return value;
}

void finish_sections(ByteView view, const FileHeader& header, std::uint64_t table_offset,
                     std::vector<Section>& sections, binpeek::detail::StringBudget& budget) {
    std::optional<StringTable> strings;
    bool loaded = false;
    for (std::size_t i = 0; i < sections.size(); ++i) {
        Section& s = sections[i];
        const auto offset = long_name_offset(s.short_name);
        if (!offset || header.symbol_table_offset == 0) continue;
        if (!loaded) {
            strings = read_string_table(view, header);
            loaded = true;
        }
        s.name = string_at(*strings, *offset, budget);
    }
    for (std::size_t i = 0; i < sections.size(); ++i) {
        const Section& s = sections[i];
        if (!s.has_file_data() || view.contains(s.raw_offset, s.raw_size)) continue;
        throw FormatError(table_offset + i * section_header_size,
                          std::format("{}: raw data at {:#x} ({:#x} bytes) extends past the end of the file "
                                      "(size {:#x})",
                                      section_label(s, i), s.raw_offset, s.raw_size, view.size()));
    }
}

std::vector<Symbol> read_symbols(ByteView view, const FileHeader& header, binpeek::detail::StringBudget& budget) {
    std::vector<Symbol> symbols;
    if (header.symbol_table_offset == 0) return symbols;
    const std::uint64_t offset = header.symbol_table_offset;
    view.require_array(offset, header.symbol_count, symbol_record_size, "COFF symbol table");
    std::optional<StringTable> strings;

    for (std::uint32_t i = 0; i < header.symbol_count;) {
        const std::uint64_t at = offset + std::uint64_t{i} * symbol_record_size;
        Cursor c(view, at, Endian::Little);
        Symbol s;
        s.index = i;
        const auto name_field = c.bytes(8);
        s.value = c.u32();
        s.section_number = static_cast<std::int16_t>(c.u16());
        s.type = c.u16();
        s.storage_class = c.u8();
        s.aux_count = c.u8();

        // A name whose first four bytes are zero is a string table offset.
        if (view.u32(at, Endian::Little) == 0) {
            if (!strings) strings = read_string_table(view, header);
            s.name = string_at(*strings, view.u32(at + 4, Endian::Little), budget);
        } else {
            s.name = budget.take(fixed_name(name_field), at);
        }
        if (std::uint32_t{s.aux_count} > header.symbol_count - i - 1) {
            throw FormatError(at + 17, std::format("symbol {}: {} auxiliary records run past the end of the symbol "
                                                   "table ({} records)",
                                                   i, s.aux_count, header.symbol_count));
        }
        i += 1u + s.aux_count;
        symbols.push_back(std::move(s));
    }
    return symbols;
}

}  // namespace detail

bool is_coff_object(std::span<const std::byte> data) noexcept {
    if (data.size() < detail::file_header_size) return false;
    const auto machine = static_cast<std::uint16_t>(std::to_integer<unsigned>(data[0]) |
                                                    (std::to_integer<unsigned>(data[1]) << 8));
    return machine == machine_i386 || machine == machine_amd64 || machine == machine_arm64;
}

PeFile parse_coff_object(std::span<const std::byte> data, const ParseOptions& options) {
    const ByteView view(data);
    binpeek::detail::StringBudget budget(view.size(), options.max_string_bytes);
    PeFile file;
    file.header = detail::read_file_header(view, 0);
    const std::uint16_t machine = file.header.machine;
    if (machine != machine_i386 && machine != machine_amd64 && machine != machine_arm64) {
        throw FormatError(0, std::format("not a COFF object file for x86, x64 or ARM64 (machine {:#x})", machine));
    }
    const std::uint64_t table = detail::file_header_size + file.header.optional_header_size;
    file.sections = detail::read_section_table(view, table, file.header.section_count, budget);
    detail::finish_sections(view, file.header, table, file.sections, budget);
    if (options.symbols) file.symbols = detail::read_symbols(view, file.header, budget);
    return file;
}

const Section* PeFile::find_section(std::string_view name) const noexcept {
    for (const Section& s : sections) {
        if (s.name == name) return &s;
    }
    return nullptr;
}

}  // namespace binpeek::pe
