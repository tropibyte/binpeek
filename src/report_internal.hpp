// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Per-format report writers. Not installed.

#pragma once

#include <ostream>
#include <string>

#include "binpeek/elf.hpp"
#include "binpeek/json.hpp"
#include "binpeek/pe.hpp"
#include "binpeek/report.hpp"

namespace binpeek::detail {

std::string describe_elf(const elf::ElfFile& file);
void write_elf_text(std::ostream& out, const elf::ElfFile& file, const ReportOptions& report);
void write_elf_json(JsonWriter& json, const elf::ElfFile& file, const ReportOptions& report);

std::string describe_pe(const pe::PeFile& file);
void write_pe_text(std::ostream& out, const pe::PeFile& file, const ReportOptions& report);
void write_pe_json(JsonWriter& json, const pe::PeFile& file, const ReportOptions& report);

}  // namespace binpeek::detail
