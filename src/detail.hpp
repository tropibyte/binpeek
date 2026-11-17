// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Helpers shared by the parsers. Not installed.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace binpeek::detail {

/// Charges every name copied out of a file against ParseOptions::max_string_bytes,
/// so that many records naming one long string cannot multiply the input.
class StringBudget {
public:
    StringBudget(std::uint64_t file_size, std::uint64_t configured) noexcept;

    /// A copy of s. Throws FormatError at offset when the budget is spent.
    std::string take(std::string_view s, std::uint64_t offset);

    /// Charges bytes without copying, for strings duplicated by the caller.
    void charge(std::uint64_t bytes, std::uint64_t offset);

private:
    std::uint64_t remaining_;
};

/// x rounded up to a power-of-two alignment. x must be far from overflow,
/// which holds for anything bounded by a file size.
constexpr std::uint64_t align_up(std::uint64_t x, std::uint64_t alignment) noexcept {
    return (x + alignment - 1) & ~(alignment - 1);
}

}  // namespace binpeek::detail
