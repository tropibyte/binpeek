// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// What to decode.

#pragma once

#include <cstdint>

namespace binpeek {

/// Selects the optional parts of a file to decode. Headers, section tables
/// and program headers are always decoded. A part that is not requested is
/// left empty and is not validated, so a damaged symbol table, for example,
/// does not stop a caller that only wants the sections.
struct ParseOptions {
    bool symbols = true;          ///< ELF .symtab; COFF symbol table
    bool dynamic_symbols = true;  ///< ELF .dynsym
    bool dynamic = true;          ///< ELF PT_INTERP, dynamic section and GNU build-id note
    bool imports = true;          ///< PE import directory
    bool exports = true;          ///< PE export directory

    /// Upper bound on the total length of names copied out of one file. Many
    /// records can point at one long string; the bound keeps the output
    /// proportional to the input. 0 means 1 MiB plus four times the file size.
    std::uint64_t max_string_bytes = 0;
};

}  // namespace binpeek
