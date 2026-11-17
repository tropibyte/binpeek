// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstdint>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

#include "helpers.hpp"

using namespace binpeek;

TEST_CASE("JSON strings") {
    CHECK(json_quote("plain") == "\"plain\"");
    CHECK(json_quote("a\"b\\c") == "\"a\\\"b\\\\c\"");
    CHECK(json_quote("tab\tnew\nret\r") == "\"tab\\tnew\\nret\\r\"");
    CHECK(json_quote(std::string("nul\0x\x01\x1f\x7f", 8)) == "\"nul\\u0000x\\u0001\\u001f\\u007f\"");
    // Well-formed UTF-8 passes through; anything else becomes U+FFFD.
    CHECK(json_quote("caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80") == "\"caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80\"");
    CHECK(json_quote("\xff") == "\"\\ufffd\"");
    CHECK(json_quote("a\xc3") == "\"a\\ufffd\"");              // truncated sequence
    CHECK(json_quote("\xc0\xaf") == "\"\\ufffd\\ufffd\"");     // overlong
    CHECK(json_quote("\xed\xa0\x80") == "\"\\ufffd\\ufffd\\ufffd\"");  // surrogate
    CHECK(json_quote("\xf4\x90\x80\x80") == "\"\\ufffd\\ufffd\\ufffd\\ufffd\"");  // past U+10FFFF
}

TEST_CASE("JSON writer layout") {
    std::ostringstream pretty;
    JsonWriter w(pretty);
    w.begin_object();
    w.field("name", ".text");
    w.field("size", std::uint64_t{32});
    w.field("delta", -5);
    w.field("ok", true);
    w.key("none");
    w.null();
    w.key("list");
    w.begin_array();
    w.value(1);
    w.value("two");
    w.end_array();
    w.key("empty");
    w.begin_array();
    w.end_array();
    w.key("nested");
    w.begin_object();
    w.end_object();
    w.end_object();
    CHECK(w.done());
    const std::string expected = "{\n"
                                 "  \"name\": \".text\",\n"
                                 "  \"size\": 32,\n"
                                 "  \"delta\": -5,\n"
                                 "  \"ok\": true,\n"
                                 "  \"none\": null,\n"
                                 "  \"list\": [\n"
                                 "    1,\n"
                                 "    \"two\"\n"
                                 "  ],\n"
                                 "  \"empty\": [],\n"
                                 "  \"nested\": {}\n"
                                 "}";
    CHECK(pretty.str() == expected);

    std::ostringstream compact;
    JsonWriter c(compact, 0);
    c.begin_array();
    c.value(std::numeric_limits<std::uint64_t>::max());
    c.value(std::numeric_limits<std::int64_t>::min());
    c.value(std::uint8_t{200});
    c.begin_object();
    c.field("k", "v");
    c.end_object();
    c.end_array();
    CHECK(compact.str() == "[18446744073709551615,-9223372036854775808,200,{\"k\":\"v\"}]");
}

TEST_CASE("JSON writer misuse") {
    std::ostringstream out;
    JsonWriter w(out);
    CHECK_THROWS_AS(w.key("x"), std::logic_error);
    CHECK_THROWS_AS(w.end_object(), std::logic_error);
    w.begin_object();
    CHECK_THROWS_AS(w.value(1), std::logic_error);  // no key
    w.key("a");
    CHECK_THROWS_AS(w.key("b"), std::logic_error);  // key after key
    CHECK_THROWS_AS(w.end_array(), std::logic_error);
    w.value(1);
    w.end_object();
    CHECK_THROWS_AS(w.value(2), std::logic_error);  // second top-level value
}
