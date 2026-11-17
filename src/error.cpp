// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <algorithm>
#include <format>

#include "binpeek/error.hpp"

namespace binpeek {

namespace {

std::string prefix(std::uint64_t offset) { return std::format("offset {:#x}: ", offset); }

}  // namespace

FormatError::FormatError(std::uint64_t offset, const std::string& message)
    : std::runtime_error(prefix(offset) + message), offset_(offset), prefix_length_(prefix(offset).size()) {}

std::string_view FormatError::message() const noexcept {
    const std::string_view text(what());
    return text.substr(std::min(prefix_length_, text.size()));
}

}  // namespace binpeek
