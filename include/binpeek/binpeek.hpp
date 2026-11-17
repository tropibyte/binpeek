// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// binpeek: read ELF and PE/COFF files from untrusted bytes. Includes every
// public header.

#pragma once

#include <string_view>

#include "binpeek/bytes.hpp"
#include "binpeek/elf.hpp"
#include "binpeek/error.hpp"
#include "binpeek/file.hpp"
#include "binpeek/json.hpp"
#include "binpeek/options.hpp"
#include "binpeek/pe.hpp"
#include "binpeek/report.hpp"

namespace binpeek {

inline constexpr std::string_view version = "0.1.0";

}  // namespace binpeek
