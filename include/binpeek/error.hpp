// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// The exception thrown for malformed input.

#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace binpeek {

/// The input is not a well-formed file of the format being parsed. offset()
/// is the file offset of the field or structure at fault; what() reads
/// "offset 0x1c: message".
class FormatError : public std::runtime_error {
public:
    FormatError(std::uint64_t offset, const std::string& message);

    std::uint64_t offset() const noexcept { return offset_; }

    /// The message without the "offset 0x...: " prefix.
    std::string_view message() const noexcept;

private:
    std::uint64_t offset_;
    std::size_t prefix_length_;
};

}  // namespace binpeek
