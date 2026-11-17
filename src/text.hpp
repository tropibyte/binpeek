// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Text formatting for reports. Not installed.

#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binpeek::detail {

/// Length of the well-formed UTF-8 sequence at s[i], or 0 when the bytes
/// there are not one.
std::size_t utf8_sequence_length(std::string_view s, std::size_t i) noexcept;

/// s with control characters and bytes that are not UTF-8 written as \xNN,
/// safe to print to a terminal.
std::string printable(std::string_view s);

/// "0x1a2b".
std::string hex(std::uint64_t value);

/// Zero-padded hexadecimal without a prefix: hex_digits(0x1a, 4) is "001a".
std::string hex_digits(std::uint64_t value, int digits);

/// Lower-case hex of each byte, as for a build ID.
std::string hex_bytes(std::span<const std::uint8_t> bytes);

/// "1 entry", "2 entries": n and the noun, plural unless n is 1.
std::string counted(std::size_t n, std::string_view singular, std::string_view plural);

/// "2026-11-17 08:30:00 UTC" for seconds since 1970.
std::string utc_time(std::uint32_t value);

enum class Align { Left, Right };

struct Column {
    std::string title;
    Align align = Align::Left;
};

/// Rows of cells printed in aligned columns under a title row and a rule.
class Table {
public:
    explicit Table(std::vector<Column> columns) : columns_(std::move(columns)) {}

    void add(std::vector<std::string> row);
    bool empty() const noexcept { return rows_.empty(); }
    void write(std::ostream& out, std::string_view indent = "  ") const;

private:
    std::vector<Column> columns_;
    std::vector<std::vector<std::string>> rows_;
};

/// "Label:  value" lines with the values aligned.
class Fields {
public:
    void add(std::string label, std::string value);
    void write(std::ostream& out, std::string_view indent = "  ") const;

private:
    std::vector<std::pair<std::string, std::string>> rows_;
};

}  // namespace binpeek::detail
