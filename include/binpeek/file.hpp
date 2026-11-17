// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Reading files and parsing them whatever their format.

#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

#include "binpeek/elf.hpp"
#include "binpeek/options.hpp"
#include "binpeek/pe.hpp"

namespace binpeek {

enum class FileFormat {
    Unknown,
    Elf,   // "\x7f" "ELF"
    Pe,    // MZ header with a "PE\0\0" signature
    Coff,  // COFF object file (x86, x64, ARM64)
};

std::string_view format_name(FileFormat format) noexcept;

/// Recognizes a file from its first bytes. Never throws; a file it
/// recognizes may still fail to parse.
FileFormat detect_format(std::span<const std::byte> data) noexcept;

/// A parsed file. PE images and COFF objects share pe::PeFile.
using ParsedFile = std::variant<elf::ElfFile, pe::PeFile>;

/// Detects the format and parses the data. Throws FormatError when the
/// format is not recognized or the file is malformed. The result owns its
/// strings and does not refer to data afterwards.
ParsedFile parse(std::span<const std::byte> data, const ParseOptions& options = {});

/// Reads a whole file in binary mode. Throws std::filesystem::filesystem_error
/// when it cannot be opened or read.
std::vector<std::byte> read_file(const std::filesystem::path& path);

}  // namespace binpeek
