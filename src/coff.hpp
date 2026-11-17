// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// The COFF parts shared by PE images and object files. Not installed.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "binpeek/bytes.hpp"
#include "binpeek/pe.hpp"
#include "detail.hpp"

namespace binpeek::pe::detail {

inline constexpr std::uint64_t file_header_size = 20;
inline constexpr std::uint64_t section_header_size = 40;

FileHeader read_file_header(ByteView view, std::uint64_t offset);

/// Reads count section headers at offset. Names are the raw 8-byte fields;
/// see resolve_section_names().
std::vector<Section> read_section_table(ByteView view, std::uint64_t offset, std::uint16_t count,
                                        binpeek::detail::StringBudget& budget);

/// The string table that follows the symbol table, or nullopt when the file
/// has no symbol table. Throws when it does not fit in the file.
std::optional<StringTable> read_string_table(ByteView view, const FileHeader& header);

/// The string at offset in the COFF string table (offsets count from the
/// start of the table, including its 4-byte size field).
std::string string_at(const StringTable& strings, std::uint64_t offset, binpeek::detail::StringBudget& budget);

/// The string table offset named by a "/123" or "//BASE64" section name, or
/// nullopt for an ordinary name.
std::optional<std::uint64_t> long_name_offset(std::string_view short_name) noexcept;

/// Resolves long names when the file has a string table (loading it only if
/// a section needs it), then checks that every section's raw data lies
/// inside the file. table_offset locates the section table for messages.
void finish_sections(ByteView view, const FileHeader& header, std::uint64_t table_offset,
                     std::vector<Section>& sections, binpeek::detail::StringBudget& budget);

std::vector<Symbol> read_symbols(ByteView view, const FileHeader& header, binpeek::detail::StringBudget& budget);

}  // namespace binpeek::pe::detail
