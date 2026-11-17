// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "helpers.hpp"

using namespace binpeek;
using namespace binpeek::test;

namespace {
constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
}

TEST_CASE("checked arithmetic") {
    CHECK(checked_add(1, 2) == 3u);
    CHECK(checked_add(kMax, 0) == kMax);
    CHECK_FALSE(checked_add(kMax, 1).has_value());
    CHECK_FALSE(checked_add(kMax - 5, 6).has_value());
    CHECK(checked_mul(0, kMax) == 0u);
    CHECK(checked_mul(kMax, 1) == kMax);
    CHECK(checked_mul(std::uint64_t{1} << 32, std::uint64_t{1} << 31) == std::uint64_t{1} << 63);
    CHECK_FALSE(checked_mul(std::uint64_t{1} << 32, std::uint64_t{1} << 32).has_value());
    CHECK_FALSE(checked_mul(0x0400000000000001, 64).has_value());
}

TEST_CASE("ByteView bounds") {
    const Bytes data = to_bytes("0123456789");
    const ByteView view(data);
    CHECK(view.size() == 10u);
    CHECK(view.contains(0, 10));
    CHECK(view.contains(10, 0));
    CHECK(view.contains(3, 7));
    CHECK_FALSE(view.contains(3, 8));
    CHECK_FALSE(view.contains(11, 0));
    CHECK_FALSE(view.contains(1, kMax));
    CHECK_FALSE(view.contains(kMax, 2));

    auto e = format_error([&] { view.require(8, 4, "widget"); });
    REQUIRE(e);
    CHECK(e->offset() == 8u);
    CHECK(std::string(e->message()) == "widget (0x4 bytes) extends past the end of the file (size 0xa)");
    CHECK(std::string(e->what()) == "offset 0x8: widget (0x4 bytes) extends past the end of the file (size 0xa)");

    e = format_error([&] { view.require(20, 1, "widget"); });
    REQUIRE(e);
    CHECK(e->offset() == 20u);
    CHECK(std::string(e->message()) == "widget starts past the end of the file (size 0xa)");

    e = format_error([&] { view.require_array(2, 0x0400000000000001, 64, "table"); });
    REQUIRE(e);
    CHECK(e->offset() == 2u);
    CHECK(std::string(e->message()).find("overflow") != std::string::npos);

    CHECK_FALSE(format_error([&] { view.require_array(2, 4, 2, "table"); }));
    CHECK(format_error([&] { view.require_array(2, 5, 2, "table"); }));
    CHECK(view.bytes(4, 3, "x").size() == 3u);
}

TEST_CASE("ByteView integers in both byte orders") {
    const Bytes data{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
                     std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x88}};
    const ByteView view(data);
    CHECK(view.u8(7) == 0x88u);
    CHECK(view.u16(0, Endian::Little) == 0x0201u);
    CHECK(view.u16(0, Endian::Big) == 0x0102u);
    CHECK(view.u32(1, Endian::Little) == 0x05040302u);
    CHECK(view.u32(1, Endian::Big) == 0x02030405u);
    CHECK(view.u64(0, Endian::Little) == 0x8807060504030201u);
    CHECK(view.u64(0, Endian::Big) == 0x0102030405060788u);
    CHECK(format_error([&] { (void)view.u16(7, Endian::Little); }));
    CHECK(format_error([&] { (void)view.u32(5, Endian::Big); }));
    CHECK(format_error([&] { (void)view.u64(1, Endian::Little); }));
    CHECK(format_error([&] { (void)view.u8(8); }));
}

TEST_CASE("Cursor") {
    ByteWriter w(Endian::Big);
    w.u16(0xbeef);
    w.u32(0xdeadbeef);
    w.u64(0x0123456789abcdef);
    const Bytes data = w.take();
    Cursor c(ByteView(data), 0, Endian::Big);
    CHECK(c.u16() == 0xbeefu);
    CHECK(c.u32() == 0xdeadbeefu);
    CHECK(c.word(true) == 0x0123456789abcdefu);
    CHECK(c.offset() == 14u);
    c.seek(2);
    CHECK(c.word(false) == 0xdeadbeefu);
    CHECK(format_error([&] { c.skip(kMax); }));
    c.seek(12);
    CHECK(format_error([&] { (void)c.u32(); }));
    CHECK(c.offset() == 12u);  // a failed read does not move the cursor
}

TEST_CASE("StringTable") {
    const Bytes data = to_bytes(std::string("xx\0alpha\0beta", 13));
    const ByteView view(data);
    const StringTable table(view, 2, 11, "names");
    CHECK(table.offset() == 2u);
    CHECK(table.size() == 11u);
    CHECK(table.get(0).empty());
    CHECK(table.get(1) == "alpha");
    CHECK(table.get(3) == "pha");  // suffixes are strings too
    CHECK(table.get(6).empty());

    // "beta" runs to the end of the table without a terminator.
    auto e = format_error([&] { (void)table.get(7); });
    REQUIRE(e);
    CHECK(e->offset() == 9u);
    CHECK(std::string(e->message()) == "names: string at index 0x7 is not NUL-terminated");

    e = format_error([&] { (void)table.get(11); });
    REQUIRE(e);
    CHECK(e->offset() == 2u);
    CHECK(format_error([&] { (void)table.get(kMax); }));

    // Constructing a table that does not fit fails at once.
    CHECK(format_error([&] { StringTable(view, 5, 9, "names"); }));

    const StringTable empty;
    CHECK(empty.get(0).empty());
    CHECK(format_error([&] { (void)empty.get(1); }));
}

TEST_CASE("FormatError") {
    const FormatError e(0x1c, "bad thing");
    CHECK(e.offset() == 0x1cu);
    CHECK(e.message() == "bad thing");
    CHECK(std::string_view(e.what()) == "offset 0x1c: bad thing");
    const FormatError copy = e;
    CHECK(copy.message() == "bad thing");
}

TEST_CASE("string budget") {
    // The default budget is generous; a tiny one stops the parse.
    ElfImage img = make_sample_elf(true, Endian::Little);
    ParseOptions options;
    CHECK_FALSE(parse_error(img.bytes, options));
    options.max_string_bytes = 16;
    const auto e = parse_error(img.bytes, options);
    REQUIRE(e);
    CHECK(std::string(e->message()).find("string budget") != std::string::npos);
}
