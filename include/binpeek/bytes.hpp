// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Bounds-checked access to untrusted bytes. Every read names a file offset
// and is checked against the end of the data; nothing is read through a
// struct overlaid on the buffer, and multi-byte fields are decoded with an
// explicit byte order.

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace binpeek {

enum class Endian { Little, Big };

/// a + b, or nullopt when the sum does not fit in 64 bits.
constexpr std::optional<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) noexcept {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) return std::nullopt;
    return a + b;
}

/// a * b, or nullopt when the product does not fit in 64 bits.
constexpr std::optional<std::uint64_t> checked_mul(std::uint64_t a, std::uint64_t b) noexcept {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) return std::nullopt;
    return a * b;
}

/// A read-only view of a whole file. Offsets are 64-bit file offsets; reads
/// outside the view throw FormatError carrying the offending offset.
class ByteView {
public:
    ByteView() noexcept = default;
    explicit ByteView(std::span<const std::byte> data) noexcept : data_(data) {}

    std::uint64_t size() const noexcept { return data_.size(); }
    std::span<const std::byte> data() const noexcept { return data_; }

    /// True when [offset, offset + length) lies inside the view.
    bool contains(std::uint64_t offset, std::uint64_t length) const noexcept;

    /// Throws FormatError at offset unless contains(offset, length). what
    /// names the structure in the message ("section header table").
    void require(std::uint64_t offset, std::uint64_t length, std::string_view what) const;

    /// Same for count entries of entry_size bytes each; also throws when the
    /// total size overflows.
    void require_array(std::uint64_t offset, std::uint64_t count, std::uint64_t entry_size,
                       std::string_view what) const;

    /// The bytes [offset, offset + length), checked as by require().
    std::span<const std::byte> bytes(std::uint64_t offset, std::uint64_t length, std::string_view what) const;

    std::uint8_t u8(std::uint64_t offset) const;
    std::uint16_t u16(std::uint64_t offset, Endian endian) const;
    std::uint32_t u32(std::uint64_t offset, Endian endian) const;
    std::uint64_t u64(std::uint64_t offset, Endian endian) const;

private:
    std::span<const std::byte> data_;
};

/// Sequential reads from a ByteView in one byte order.
class Cursor {
public:
    Cursor(ByteView view, std::uint64_t offset, Endian endian) noexcept
        : view_(view), offset_(offset), endian_(endian) {}

    std::uint64_t offset() const noexcept { return offset_; }
    void seek(std::uint64_t offset) noexcept { offset_ = offset; }
    void skip(std::uint64_t count);

    std::uint8_t u8();
    std::uint16_t u16();
    std::uint32_t u32();
    std::uint64_t u64();
    /// An ELF address-sized word: u64() when wide, else u32().
    std::uint64_t word(bool wide) { return wide ? u64() : u32(); }
    std::span<const std::byte> bytes(std::uint64_t count);

private:
    ByteView view_;
    std::uint64_t offset_;
    Endian endian_;
};

/// A table of NUL-terminated strings occupying [offset, offset + size) of a
/// file, such as an ELF .strtab or the COFF string table. Lookups never read
/// outside the table.
class StringTable {
public:
    StringTable() noexcept = default;
    /// Throws FormatError when the range is outside the view. what names the
    /// table in messages.
    StringTable(ByteView view, std::uint64_t offset, std::uint64_t size, std::string_view what);

    std::uint64_t offset() const noexcept { return offset_; }
    std::uint64_t size() const noexcept { return text_.size(); }

    /// The string starting index bytes into the table. Index 0 of an empty
    /// table is the empty string. Throws FormatError when index is outside
    /// the table or the string has no terminator before the table ends.
    std::string_view get(std::uint64_t index) const;

private:
    std::string_view text_;
    std::uint64_t offset_ = 0;
    std::string what_;
};

}  // namespace binpeek
