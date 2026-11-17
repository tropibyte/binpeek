// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <ostream>
#include <string>
#include <string_view>
#include <variant>

#include "binpeek/report.hpp"
#include "report_internal.hpp"
#include "text.hpp"

namespace binpeek {

namespace {

template <typename... F>
struct Overloaded : F... {
    using F::operator()...;
};
template <typename... F>
Overloaded(F...) -> Overloaded<F...>;

}  // namespace

ReportOptions ReportOptions::everything() noexcept {
    ReportOptions r;
    r.headers = r.sections = r.segments = r.symbols = r.dynamic_symbols = r.imports = r.exports = true;
    r.all = true;
    return r;
}

ParseOptions parse_options_for(const ReportOptions& report) {
    ParseOptions p;
    p.symbols = report.symbols;
    // ELF imports and exports are views of the dynamic symbol table.
    p.dynamic_symbols = report.dynamic_symbols || report.imports || report.exports;
    p.dynamic = report.headers || report.imports;
    p.imports = report.imports;
    p.exports = report.exports;
    return p;
}

std::string printable(std::string_view s) { return detail::printable(s); }

std::string describe(const ParsedFile& file) {
    return std::visit(Overloaded{[](const elf::ElfFile& f) { return detail::describe_elf(f); },
                                 [](const pe::PeFile& f) { return detail::describe_pe(f); }},
                      file);
}

void write_text(std::ostream& out, const ParsedFile& file, const ReportOptions& report) {
    std::visit(Overloaded{[&](const elf::ElfFile& f) { detail::write_elf_text(out, f, report); },
                          [&](const pe::PeFile& f) { detail::write_pe_text(out, f, report); }},
               file);
}

void write_json(JsonWriter& json, const ParsedFile& file, const ReportOptions& report, std::string_view file_name) {
    json.begin_object();
    if (!file_name.empty()) json.field("file", file_name);
    std::visit(Overloaded{[&](const elf::ElfFile& f) { detail::write_elf_json(json, f, report); },
                          [&](const pe::PeFile& f) { detail::write_pe_json(json, f, report); }},
               file);
    json.end_object();
}

}  // namespace binpeek
