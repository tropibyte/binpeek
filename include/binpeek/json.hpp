// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// A small streaming JSON writer.

#pragma once

#include <concepts>
#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace binpeek {

/// Writes one JSON value to a stream, pretty-printed with the given indent
/// (0 writes everything on one line). Strings are taken as UTF-8: control
/// characters are escaped, and bytes that are not well-formed UTF-8 become
/// U+FFFD, so the output is always valid JSON even for names read from
/// damaged files. Misuse (a value where a key is due, unbalanced ends) is a
/// programming error and throws std::logic_error.
class JsonWriter {
public:
    explicit JsonWriter(std::ostream& out, int indent = 2) : out_(out), indent_(indent) {}

    void begin_object();
    void end_object();
    void begin_array();
    void end_array();
    void key(std::string_view name);

    void value(std::string_view s);
    void value(const char* s) { value(std::string_view(s)); }
    void value(const std::string& s) { value(std::string_view(s)); }
    void value(bool b);
    void null();

    template <std::integral T>
        requires(!std::same_as<T, bool>)
    void value(T v) {
        if constexpr (std::is_signed_v<T>) {
            write_signed(static_cast<std::int64_t>(v));
        } else {
            write_unsigned(static_cast<std::uint64_t>(v));
        }
    }

    template <typename T>
    void field(std::string_view name, const T& v) {
        key(name);
        value(v);
    }

    /// True once a complete top-level value has been written.
    bool done() const noexcept { return stack_.empty() && wrote_root_; }

private:
    struct Level {
        bool is_object;
        bool empty = true;
        bool key_pending = false;
    };

    void before_value();
    void newline_indent(std::size_t depth);
    void write_signed(std::int64_t v);
    void write_unsigned(std::uint64_t v);
    void close(bool is_object);

    std::ostream& out_;
    int indent_;
    std::vector<Level> stack_;
    bool wrote_root_ = false;
};

/// s as a JSON string literal, quotes included (see JsonWriter).
std::string json_quote(std::string_view s);

}  // namespace binpeek
