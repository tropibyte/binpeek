// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Text and JSON reports of parsed files, as the command-line tool prints them.

#pragma once

#include <ostream>
#include <string>
#include <string_view>

#include "binpeek/file.hpp"
#include "binpeek/json.hpp"
#include "binpeek/options.hpp"

namespace binpeek {

/// The parts of a report. Parts that do not apply to a format (segments and
/// dynamic symbols for PE/COFF) are skipped; in text output a note says so
/// unless `all` is set.
struct ReportOptions {
    bool headers = false;
    bool sections = false;
    bool segments = false;
    bool symbols = false;
    bool dynamic_symbols = false;
    bool imports = false;  ///< ELF: needed libraries and undefined dynamic symbols
    bool exports = false;  ///< ELF: defined global and weak dynamic symbols
    bool all = false;      ///< set by everything(); silences the notes

    static ReportOptions everything() noexcept;
};

/// The ParseOptions that decode what a report shows, and nothing more.
ParseOptions parse_options_for(const ReportOptions& report);

/// s with control characters and bytes that are not UTF-8 written as \xNN,
/// as text reports print names, so it is safe to show on a terminal.
std::string printable(std::string_view s);

/// A one-line description: "ELF64 little-endian DYN (shared object or PIE), x86-64".
std::string describe(const ParsedFile& file);

/// Writes the requested parts as aligned tables. Names from the file are
/// escaped so control characters cannot reach the terminal.
void write_text(std::ostream& out, const ParsedFile& file, const ReportOptions& report);

/// Writes one JSON object with the requested parts. When file_name is not
/// empty it comes first, as "file".
void write_json(JsonWriter& json, const ParsedFile& file, const ReportOptions& report,
                std::string_view file_name = {});

}  // namespace binpeek
