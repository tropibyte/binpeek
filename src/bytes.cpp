// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "binpeek/bytes.hpp"
#include "binpeek/error.hpp"
#include "detail.hpp"

namespace binpeek {

namespace {

template <std::size_t N>
std::uint64_t decode(std::span<const std::byte> b, Endian endian) noexcept {
    std::uint64_t v = 0;
    if (endian == Endian::Little) {
        for (std::size_t i = N; i-- > 0;) v = (v << 8) | std::to_integer<std::uint64_t>(b[i]);
    } else {
        for (std::size_t i = 0; i < N; ++i) v = (v << 8) | std::to_integer<std::uint64_t>(b[i]);
    }
    return v;
}

}  // namespace

bool ByteView::contains(std::uint64_t offset, std::uint64_t length) const noexcept {
    return offset <= size() && length <= size() - offset;
}

void ByteView::require(std::uint64_t offset, std::uint64_t length, std::string_view what) const {
    if (contains(offset, length)) return;
    if (offset >= size()) {
        throw FormatError(offset, std::format("{} starts past the end of the file (size {:#x})", what, size()));
    }
    throw FormatError(offset, std::format("{} ({:#x} bytes) extends past the end of the file (size {:#x})", what,
                                          length, size()));
}

void ByteView::require_array(std::uint64_t offset, std::uint64_t count, std::uint64_t entry_size,
                             std::string_view what) const {
    const auto total = checked_mul(count, entry_size);
    if (!total) {
        throw FormatError(offset,
                          std::format("{}: {} entries of {} bytes overflow a 64-bit size", what, count, entry_size));
    }
    if (contains(offset, *total)) return;
    if (offset >= size()) {
        throw FormatError(offset, std::format("{} starts past the end of the file (size {:#x})", what, size()));
    }
    throw FormatError(offset, std::format("{} ({} entries of {} bytes) extends past the end of the file (size {:#x})",
                                          what, count, entry_size, size()));
}

std::span<const std::byte> ByteView::bytes(std::uint64_t offset, std::uint64_t length, std::string_view what) const {
    require(offset, length, what);
    // Both values are at most size(), which fits in size_t.
    return data_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(length));
}

std::uint8_t ByteView::u8(std::uint64_t offset) const {
    return static_cast<std::uint8_t>(decode<1>(bytes(offset, 1, "1-byte field"), Endian::Little));
}

std::uint16_t ByteView::u16(std::uint64_t offset, Endian endian) const {
    return static_cast<std::uint16_t>(decode<2>(bytes(offset, 2, "2-byte field"), endian));
}

std::uint32_t ByteView::u32(std::uint64_t offset, Endian endian) const {
    return static_cast<std::uint32_t>(decode<4>(bytes(offset, 4, "4-byte field"), endian));
}

std::uint64_t ByteView::u64(std::uint64_t offset, Endian endian) const {
    return decode<8>(bytes(offset, 8, "8-byte field"), endian);
}

void Cursor::skip(std::uint64_t count) {
    const auto next = checked_add(offset_, count);
    if (!next) throw FormatError(offset_, "offset overflows");
    offset_ = *next;
}

// A successful read leaves offset_ at most size(), so the increments below
// cannot overflow.
std::uint8_t Cursor::u8() {
    const std::uint8_t v = view_.u8(offset_);
    offset_ += 1;
    return v;
}

std::uint16_t Cursor::u16() {
    const std::uint16_t v = view_.u16(offset_, endian_);
    offset_ += 2;
    return v;
}

std::uint32_t Cursor::u32() {
    const std::uint32_t v = view_.u32(offset_, endian_);
    offset_ += 4;
    return v;
}

std::uint64_t Cursor::u64() {
    const std::uint64_t v = view_.u64(offset_, endian_);
    offset_ += 8;
    return v;
}

std::span<const std::byte> Cursor::bytes(std::uint64_t count) {
    const auto b = view_.bytes(offset_, count, "field");
    offset_ += count;
    return b;
}

StringTable::StringTable(ByteView view, std::uint64_t offset, std::uint64_t size, std::string_view what)
    : offset_(offset), what_(what) {
    const auto b = view.bytes(offset, size, what);
    text_ = std::string_view(reinterpret_cast<const char*>(b.data()), b.size());
}

std::string_view StringTable::get(std::uint64_t index) const {
    if (index == 0 && text_.empty()) return {};
    if (index >= text_.size()) {
        throw FormatError(offset_, std::format("{}: string index {:#x} is outside the table ({:#x} bytes)", what_,
                                               index, text_.size()));
    }
    const std::string_view rest = text_.substr(static_cast<std::size_t>(index));
    const std::size_t end = rest.find('\0');
    if (end == std::string_view::npos) {
        throw FormatError(offset_ + index,
                          std::format("{}: string at index {:#x} is not NUL-terminated", what_, index));
    }
    return rest.substr(0, end);
}

namespace detail {

StringBudget::StringBudget(std::uint64_t file_size, std::uint64_t configured) noexcept
    : remaining_(configured) {
    if (remaining_ == 0) {
        const auto scaled = checked_mul(file_size, 4);
        const auto total = scaled ? checked_add(*scaled, std::uint64_t{1} << 20) : std::nullopt;
        remaining_ = total ? *total : std::numeric_limits<std::uint64_t>::max();
    }
}

void StringBudget::charge(std::uint64_t bytes, std::uint64_t offset) {
    if (bytes > remaining_) {
        throw FormatError(offset, "names in the file add up to more than the string budget "
                                  "(ParseOptions::max_string_bytes)");
    }
    remaining_ -= bytes;
}

std::string StringBudget::take(std::string_view s, std::uint64_t offset) {
    charge(s.size(), offset);
    return std::string(s);
}

}  // namespace detail

}  // namespace binpeek
