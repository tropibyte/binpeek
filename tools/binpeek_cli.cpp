// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// binpeek command-line tool.

#include <cstddef>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "binpeek/binpeek.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// shellapi.h needs windows.h first.
#include <shellapi.h>
#endif

namespace {

const char* const kUsage = R"USAGE(binpeek - inspect ELF and PE/COFF executables, libraries and object files

Usage:
  binpeek [options] FILE...

Options:
  -H, --headers    file header; for ELF also the interpreter, build ID and
                   dynamic section; for PE the DOS, COFF and optional headers
  -S, --sections   section table
  -l, --segments   program headers (ELF)
  -s, --symbols    symbol table (ELF .symtab, COFF symbol table)
      --dyn-syms   dynamic symbol table (ELF .dynsym)
  -i, --imports    needed libraries and imported symbols (ELF), import table (PE)
  -e, --exports    exported dynamic symbols (ELF), export table (PE)
  -a, --all        all of the above
  -j, --json       write JSON instead of text
  -h, --help       show this help
  -V, --version    show the version

With no part selected, --headers is shown. Short options can be combined
(-HS). Exit status: 0 on success, 1 when a file cannot be read or is
malformed, 2 for usage errors.
)USAGE";

class UsageError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// A command-line argument as UTF-8 text (for messages and options) and as a
// path (for opening files).
struct Argument {
    std::string text;
    std::filesystem::path path;
};

struct Options {
    binpeek::ReportOptions report;
    bool json = false;
    bool help = false;
    bool version = false;
    std::vector<Argument> files;
};

#ifdef _WIN32
std::string to_utf8(const std::filesystem::path& p) {
    const std::u8string u8 = p.u8string();
    std::string out;
    out.reserve(u8.size());
    for (const char8_t c : u8) out.push_back(static_cast<char>(c));
    return out;
}
#endif

// On Windows, argv is in the ANSI code page and cannot name every file; the
// wide command line can.
std::vector<Argument> arguments(int argc, char** argv) {
    std::vector<Argument> args;
#ifdef _WIN32
    int count = 0;
    if (LPWSTR* wide = CommandLineToArgvW(GetCommandLineW(), &count)) {
        for (int i = 1; i < count; ++i) {
            std::filesystem::path p(wide[i]);
            args.push_back({to_utf8(p), std::move(p)});
        }
        LocalFree(wide);
        return args;
    }
#endif
    for (int i = 1; i < argc; ++i) args.push_back({argv[i], std::filesystem::path(argv[i])});
    return args;
}

bool set_long_option(Options& o, std::string_view name) {
    binpeek::ReportOptions& r = o.report;
    if (name == "headers") r.headers = true;
    else if (name == "sections") r.sections = true;
    else if (name == "segments" || name == "program-headers") r.segments = true;
    else if (name == "symbols" || name == "syms") r.symbols = true;
    else if (name == "dyn-syms") r.dynamic_symbols = true;
    else if (name == "imports") r.imports = true;
    else if (name == "exports") r.exports = true;
    else if (name == "all") r = binpeek::ReportOptions::everything();
    else if (name == "json") o.json = true;
    else if (name == "help") o.help = true;
    else if (name == "version") o.version = true;
    else return false;
    return true;
}

bool set_short_option(Options& o, char c) {
    switch (c) {
        case 'H': return set_long_option(o, "headers");
        case 'S': return set_long_option(o, "sections");
        case 'l': return set_long_option(o, "segments");
        case 's': return set_long_option(o, "symbols");
        case 'i': return set_long_option(o, "imports");
        case 'e': return set_long_option(o, "exports");
        case 'a': return set_long_option(o, "all");
        case 'j': return set_long_option(o, "json");
        case 'h': return set_long_option(o, "help");
        case 'V': return set_long_option(o, "version");
        default: return false;
    }
}

Options parse_args(const std::vector<Argument>& args) {
    Options o;
    bool options_done = false;
    for (const Argument& arg : args) {
        const std::string_view a = arg.text;
        if (options_done || a.size() < 2 || a[0] != '-') {
            o.files.push_back(arg);
        } else if (a == "--") {
            options_done = true;
        } else if (a.starts_with("--")) {
            if (!set_long_option(o, a.substr(2))) throw UsageError("unknown option '" + std::string(a) + "'");
        } else {
            for (const char c : a.substr(1)) {
                if (!set_short_option(o, c)) throw UsageError(std::string("unknown option '-") + c + "'");
            }
        }
    }
    if (o.help || o.version) return o;
    if (o.files.empty()) throw UsageError("no input files");
    const binpeek::ReportOptions& r = o.report;
    if (!r.headers && !r.sections && !r.segments && !r.symbols && !r.dynamic_symbols && !r.imports && !r.exports) {
        o.report.headers = true;
    }
    return o;
}

int run(const Options& o) {
    if (o.help) {
        std::cout << kUsage;
        return 0;
    }
    if (o.version) {
        std::cout << "binpeek " << binpeek::version << '\n';
        return 0;
    }

    const binpeek::ParseOptions parse_options = binpeek::parse_options_for(o.report);
    const bool many = o.files.size() > 1;
    binpeek::JsonWriter json(std::cout);
    if (o.json && many) json.begin_array();

    int status = 0;
    for (std::size_t i = 0; i < o.files.size(); ++i) {
        const Argument& file = o.files[i];
        auto fail = [&](std::string_view message, const binpeek::FormatError* format_error) {
            std::cout.flush();
            std::cerr << "binpeek: " << binpeek::printable(file.text) << ": " << message << '\n';
            status = 1;
            if (!o.json) return;
            json.begin_object();
            json.field("file", file.text);
            json.field("error", format_error != nullptr ? format_error->message() : message);
            if (format_error != nullptr) json.field("offset", format_error->offset());
            json.end_object();
        };
        try {
            const std::vector<std::byte> data = binpeek::read_file(file.path);
            const binpeek::ParsedFile parsed = binpeek::parse(data, parse_options);
            if (o.json) {
                binpeek::write_json(json, parsed, o.report, file.text);
            } else {
                if (i != 0) std::cout << '\n';
                std::cout << binpeek::printable(file.text) << ": " << binpeek::describe(parsed) << '\n';
                binpeek::write_text(std::cout, parsed, o.report);
            }
        } catch (const binpeek::FormatError& e) {
            fail(e.what(), &e);
        } catch (const std::filesystem::filesystem_error& e) {
            fail(e.code().message(), nullptr);
        }
    }
    if (o.json) {
        if (many) json.end_array();
        std::cout << '\n';
    }
    std::cout.flush();
    return status;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(parse_args(arguments(argc, argv)));
    } catch (const UsageError& e) {
        std::cerr << "binpeek: " << e.what() << "\nTry 'binpeek --help' for more information.\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "binpeek: " << e.what() << '\n';
        return 1;
    }
}
