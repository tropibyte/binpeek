// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// Lists the libraries each file needs: DT_NEEDED entries for ELF, imported
// DLLs (with how many functions come from each) for PE.
//
//   binpeek_list_deps /bin/ls app.exe

#include <cstddef>
#include <exception>
#include <iostream>
#include <variant>
#include <vector>

#include "binpeek/binpeek.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: binpeek_list_deps FILE...\n";
        return 2;
    }

    // Only the dynamic section and the import directory are needed.
    binpeek::ParseOptions options;
    options.symbols = false;
    options.dynamic_symbols = false;
    options.exports = false;

    int status = 0;
    for (int i = 1; i < argc; ++i) {
        try {
            const std::vector<std::byte> data = binpeek::read_file(argv[i]);
            const binpeek::ParsedFile file = binpeek::parse(data, options);
            std::cout << argv[i] << ": " << binpeek::describe(file) << '\n';

            if (const auto* elf = std::get_if<binpeek::elf::ElfFile>(&file)) {
                for (const auto& lib : elf->needed) std::cout << "  " << binpeek::printable(lib) << '\n';
                if (elf->runpath) std::cout << "  (runpath " << binpeek::printable(*elf->runpath) << ")\n";
            } else if (const auto* pe = std::get_if<binpeek::pe::PeFile>(&file)) {
                for (const auto& dll : pe->imports) {
                    std::cout << "  " << binpeek::printable(dll.name) << " (" << dll.functions.size()
                              << " functions)\n";
                }
            }
        } catch (const std::exception& e) {
            std::cerr << argv[i] << ": " << e.what() << '\n';
            status = 1;
        }
    }
    return status;
}
