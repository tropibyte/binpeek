// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "text.hpp"

namespace binpeek::detail {

std::size_t utf8_sequence_length(std::string_view s, std::size_t i) noexcept {
    auto byte = [&](std::size_t k) { return static_cast<unsigned char>(s[k]); };
    auto continuation = [&](std::size_t k, unsigned lo = 0x80, unsigned hi = 0xbf) {
        return k < s.size() && byte(k) >= lo && byte(k) <= hi;
    };
    const unsigned b0 = byte(i);
    if (b0 < 0x80) return 1;
    if (b0 >= 0xc2 && b0 <= 0xdf) return continuation(i + 1) ? 2 : 0;
    if (b0 >= 0xe0 && b0 <= 0xef) {
        // No overlong forms (E0 80..9F) and no surrogates (ED A0..BF).
        const unsigned lo = b0 == 0xe0 ? 0xa0u : 0x80u;
        const unsigned hi = b0 == 0xed ? 0x9fu : 0xbfu;
        return continuation(i + 1, lo, hi) && continuation(i + 2) ? 3 : 0;
    }
    if (b0 >= 0xf0 && b0 <= 0xf4) {
        // No overlong forms (F0 80..8F) and nothing past U+10FFFF (F4 90..).
        const unsigned lo = b0 == 0xf0 ? 0x90u : 0x80u;
        const unsigned hi = b0 == 0xf4 ? 0x8fu : 0xbfu;
        return continuation(i + 1, lo, hi) && continuation(i + 2) && continuation(i + 3) ? 4 : 0;
    }
    return 0;
}

std::string printable(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        const auto b = static_cast<unsigned char>(s[i]);
        if (b >= 0x20 && b < 0x7f) {
            out += s[i++];
            continue;
        }
        const std::size_t n = b < 0x80 ? 0 : utf8_sequence_length(s, i);
        // C1 controls (U+0080 to U+009F) are escaped like C0 ones.
        const bool c1 = n == 2 && b == 0xc2 && static_cast<unsigned char>(s[i + 1]) < 0xa0;
        if (n == 0 || c1) {
            out += std::format("\\x{:02x}", b);
            ++i;
            continue;
        }
        out.append(s.substr(i, n));
        i += n;
    }
    return out;
}

std::string hex(std::uint64_t value) { return std::format("{:#x}", value); }

std::string hex_digits(std::uint64_t value, int digits) { return std::format("{:0{}x}", value, digits); }

std::string hex_bytes(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::uint8_t b : bytes) out += std::format("{:02x}", b);
    return out;
}

std::string counted(std::size_t n, std::string_view singular, std::string_view plural) {
    return std::format("{} {}", n, n == 1 ? singular : plural);
}

std::string utc_time(std::uint32_t value) {
    using namespace std::chrono;
    const sys_seconds t{seconds{value}};
    const sys_days day = floor<days>(t);
    const year_month_day ymd{day};
    const hh_mm_ss hms{t - day};
    return std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", static_cast<int>(ymd.year()),
                       static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()), hms.hours().count(),
                       hms.minutes().count(), hms.seconds().count());
}

void Table::add(std::vector<std::string> row) {
    row.resize(columns_.size());
    rows_.push_back(std::move(row));
}

void Table::write(std::ostream& out, std::string_view indent) const {
    std::vector<std::size_t> widths;
    for (const Column& c : columns_) widths.push_back(c.title.size());
    for (const auto& row : rows_) {
        for (std::size_t i = 0; i < row.size(); ++i) widths[i] = std::max(widths[i], row[i].size());
    }
    auto line = [&](auto cell, auto align) {
        std::string text(indent);
        for (std::size_t i = 0; i < columns_.size(); ++i) {
            const std::string& value = cell(i);
            const std::size_t pad = widths[i] - value.size();
            const bool last = i + 1 == columns_.size();
            if (i != 0) text += "  ";
            if (align(i) == Align::Right) text.append(pad, ' ');
            text += value;
            if (align(i) == Align::Left && !last) text.append(pad, ' ');
        }
        while (!text.empty() && text.back() == ' ') text.pop_back();
        out << text << '\n';
    };
    line([&](std::size_t i) -> const std::string& { return columns_[i].title; },
         [&](std::size_t i) { return columns_[i].align; });
    std::vector<std::string> rules;
    for (const std::size_t w : widths) rules.emplace_back(w, '-');
    line([&](std::size_t i) -> const std::string& { return rules[i]; }, [](std::size_t) { return Align::Left; });
    for (const auto& row : rows_) {
        line([&](std::size_t i) -> const std::string& { return row[i]; },
             [&](std::size_t i) { return columns_[i].align; });
    }
}

void Fields::add(std::string label, std::string value) { rows_.emplace_back(std::move(label), std::move(value)); }

void Fields::write(std::ostream& out, std::string_view indent) const {
    std::size_t width = 0;
    for (const auto& [label, value] : rows_) width = std::max(width, label.size());
    for (const auto& [label, value] : rows_) {
        std::string text(indent);
        text += label;
        text += ':';
        text.append(width - label.size() + 2, ' ');
        text += value;
        while (!text.empty() && text.back() == ' ') text.pop_back();
        out << text << '\n';
    }
}

}  // namespace binpeek::detail
