// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <limits>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

#include "binpeek/error.hpp"
#include "binpeek/file.hpp"

namespace binpeek {

std::string_view format_name(FileFormat format) noexcept {
    switch (format) {
        case FileFormat::Elf: return "ELF";
        case FileFormat::Pe: return "PE";
        case FileFormat::Coff: return "COFF";
        case FileFormat::Unknown: break;
    }
    return "unknown";
}

FileFormat detect_format(std::span<const std::byte> data) noexcept {
    if (elf::is_elf(data)) return FileFormat::Elf;
    if (pe::is_pe(data)) return FileFormat::Pe;
    if (pe::is_coff_object(data)) return FileFormat::Coff;
    return FileFormat::Unknown;
}

ParsedFile parse(std::span<const std::byte> data, const ParseOptions& options) {
    switch (detect_format(data)) {
        case FileFormat::Elf: return elf::parse_elf(data, options);
        case FileFormat::Pe: return pe::parse_pe(data, options);
        case FileFormat::Coff: return pe::parse_coff_object(data, options);
        case FileFormat::Unknown: break;
    }
    // An MZ file without a usable PE header: let the PE parser say what is wrong.
    if (data.size() >= 2 && data[0] == std::byte{'M'} && data[1] == std::byte{'Z'}) return pe::parse_pe(data, options);
    throw FormatError(0, "unrecognized file format (not ELF, PE or COFF)");
}

std::vector<std::byte> read_file(const std::filesystem::path& path) {
    std::error_code ec;
    // file_size() of a directory is implementation-defined; reject it first.
    if (std::filesystem::is_directory(path, ec)) {
        throw std::filesystem::filesystem_error("cannot read file", path,
                                                std::make_error_code(std::errc::is_a_directory));
    }
    const std::uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec) throw std::filesystem::filesystem_error("cannot read file", path, ec);
    if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max()) ||
        size > std::vector<std::byte>().max_size()) {
        throw std::filesystem::filesystem_error("file too large to read into memory", path,
                                                std::make_error_code(std::errc::file_too_large));
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::filesystem::filesystem_error("cannot open file", path,
                                                std::make_error_code(std::errc::permission_denied));
    }
    std::vector<std::byte> data(static_cast<std::size_t>(size));
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
    if (in.gcount() != static_cast<std::streamsize>(size)) {
        throw std::filesystem::filesystem_error("short read", path, std::make_error_code(std::errc::io_error));
    }
    return data;
}

}  // namespace binpeek
