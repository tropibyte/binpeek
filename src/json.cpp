// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "binpeek/json.hpp"
#include "text.hpp"

namespace binpeek {

std::string json_quote(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (std::size_t i = 0; i < s.size();) {
        const auto b = static_cast<unsigned char>(s[i]);
        switch (b) {
            case '"': out += "\\\""; ++i; continue;
            case '\\': out += "\\\\"; ++i; continue;
            case '\n': out += "\\n"; ++i; continue;
            case '\r': out += "\\r"; ++i; continue;
            case '\t': out += "\\t"; ++i; continue;
            default: break;
        }
        if (b < 0x20 || b == 0x7f) {
            out += std::format("\\u{:04x}", b);
            ++i;
            continue;
        }
        const std::size_t n = detail::utf8_sequence_length(s, i);
        if (n == 0) {
            out += "\\ufffd";
            ++i;
            continue;
        }
        out.append(s.substr(i, n));
        i += n;
    }
    out += '"';
    return out;
}

void JsonWriter::newline_indent(std::size_t depth) {
    if (indent_ <= 0) return;
    out_ << '\n';
    for (std::size_t i = 0; i < depth * static_cast<std::size_t>(indent_); ++i) out_ << ' ';
}

void JsonWriter::before_value() {
    if (stack_.empty()) {
        if (wrote_root_) throw std::logic_error("JsonWriter: a second top-level value");
        wrote_root_ = true;
        return;
    }
    Level& top = stack_.back();
    if (top.is_object) {
        if (!top.key_pending) throw std::logic_error("JsonWriter: a value in an object needs a key");
        top.key_pending = false;
        return;
    }
    if (!top.empty) out_ << ',';
    top.empty = false;
    newline_indent(stack_.size());
}

void JsonWriter::key(std::string_view name) {
    if (stack_.empty() || !stack_.back().is_object || stack_.back().key_pending) {
        throw std::logic_error("JsonWriter: a key outside an object or after another key");
    }
    Level& top = stack_.back();
    if (!top.empty) out_ << ',';
    top.empty = false;
    top.key_pending = true;
    newline_indent(stack_.size());
    out_ << json_quote(name) << (indent_ > 0 ? ": " : ":");
}

void JsonWriter::begin_object() {
    before_value();
    out_ << '{';
    stack_.push_back({true});
}

void JsonWriter::begin_array() {
    before_value();
    out_ << '[';
    stack_.push_back({false});
}

void JsonWriter::close(bool is_object) {
    if (stack_.empty() || stack_.back().is_object != is_object || stack_.back().key_pending) {
        throw std::logic_error("JsonWriter: unbalanced end of object or array");
    }
    const bool empty = stack_.back().empty;
    stack_.pop_back();
    if (!empty) newline_indent(stack_.size());
    out_ << (is_object ? '}' : ']');
}

void JsonWriter::end_object() { close(true); }

void JsonWriter::end_array() { close(false); }

void JsonWriter::value(std::string_view s) {
    before_value();
    out_ << json_quote(s);
}

void JsonWriter::value(bool b) {
    before_value();
    out_ << (b ? "true" : "false");
}

void JsonWriter::null() {
    before_value();
    out_ << "null";
}

void JsonWriter::write_signed(std::int64_t v) {
    before_value();
    char buffer[24];
    const auto result = std::to_chars(buffer, buffer + sizeof buffer, v);
    out_.write(buffer, result.ptr - buffer);
}

void JsonWriter::write_unsigned(std::uint64_t v) {
    before_value();
    char buffer[24];
    const auto result = std::to_chars(buffer, buffer + sizeof buffer, v);
    out_.write(buffer, result.ptr - buffer);
}

}  // namespace binpeek
