// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Shared test helpers.

#pragma once

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "binpeek/binpeek.hpp"
#include "doctest.h"
#include "image_builder.hpp"

namespace binpeek::test {

/// A file in tests/data. The directory comes from the build as UTF-8.
inline std::filesystem::path data_path(std::string_view name) {
    return std::filesystem::path(std::u8string_view(u8"" BINPEEK_TEST_DATA_DIR)) / std::filesystem::path(name);
}

inline Bytes load_fixture(std::string_view name) { return read_file(data_path(name)); }

/// The FormatError f throws, or nullopt when it returns normally. Any other
/// exception propagates and fails the test.
template <typename F>
std::optional<FormatError> format_error(F&& f) {
    try {
        f();
    } catch (const FormatError& e) {
        return e;
    }
    return std::nullopt;
}

inline std::optional<FormatError> parse_error(std::span<const std::byte> data, const ParseOptions& options = {}) {
    return format_error([&] { (void)parse(data, options); });
}

template <typename T>
const T& as(const ParsedFile& file) {
    REQUIRE(std::holds_alternative<T>(file));
    return std::get<T>(file);
}

inline const pe::ImportedDll* find_import(const pe::PeFile& file, std::string_view dll) {
    for (const pe::ImportedDll& d : file.imports) {
        if (d.name == dll) return &d;
    }
    return nullptr;
}

inline std::vector<std::string> section_names(const elf::ElfFile& file) {
    std::vector<std::string> names;
    for (const elf::Section& s : file.sections) names.push_back(s.name);
    return names;
}

inline std::vector<std::string> section_names(const pe::PeFile& file) {
    std::vector<std::string> names;
    for (const pe::Section& s : file.sections) names.push_back(s.name);
    return names;
}

inline const elf::Symbol* find_symbol(const std::vector<elf::Symbol>& symbols, std::string_view name) {
    for (const elf::Symbol& s : symbols) {
        if (s.name == name) return &s;
    }
    return nullptr;
}

}  // namespace binpeek::test
