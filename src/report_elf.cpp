// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "binpeek/elf.hpp"
#include "report_internal.hpp"
#include "text.hpp"

namespace binpeek::detail {

namespace {

using elf::ElfFile;
using elf::Symbol;

std::string type_description(std::uint16_t type) {
    switch (type) {
        case elf::et_rel: return "REL (relocatable object)";
        case elf::et_exec: return "EXEC (executable)";
        case elf::et_dyn: return "DYN (shared object or PIE)";
        case elf::et_core: return "CORE (core dump)";
        default: return elf::file_type_name(type);
    }
}

int address_digits(const ElfFile& f) { return f.header.is64 ? 16 : 8; }

bool is_import(const Symbol& s) { return s.is_undefined() && s.bind != elf::stb_local; }

bool is_export(const Symbol& s) {
    return !s.is_undefined() && s.bind != elf::stb_local && s.type != elf::stt_section && s.type != elf::stt_file &&
           s.visibility != elf::stv_hidden && s.visibility != elf::stv_internal;
}

std::string symbol_table_name(const ElfFile& f, std::uint32_t type, std::string_view fallback) {
    for (const elf::Section& s : f.sections) {
        if (s.type == type) return printable(s.name);
    }
    return std::string(fallback);
}

// The value column of the dynamic table: strings for the tags that name one.
std::vector<std::string> dynamic_values(const ElfFile& f) {
    std::vector<std::string> values;
    std::size_t needed = 0;
    bool soname = false, rpath = false, runpath = false;
    auto named = [](bool& seen, const std::optional<std::string>& value) -> std::optional<std::string> {
        if (seen || !value) return std::nullopt;
        seen = true;
        return "[" + printable(*value) + "]";
    };
    for (const elf::DynamicEntry& e : f.dynamic) {
        std::optional<std::string> text;
        if (e.tag == elf::dt_needed && needed < f.needed.size()) text = "[" + printable(f.needed[needed++]) + "]";
        if (e.tag == elf::dt_soname) text = named(soname, f.soname);
        if (e.tag == elf::dt_rpath) text = named(rpath, f.rpath);
        if (e.tag == elf::dt_runpath) text = named(runpath, f.runpath);
        values.push_back(text ? *text : hex(e.value));
    }
    return values;
}

void write_header(std::ostream& out, const ElfFile& f) {
    const elf::FileHeader& h = f.header;
    Fields fields;
    fields.add("Class", h.is64 ? "ELF64" : "ELF32");
    fields.add("Data", h.endian == Endian::Little ? "little-endian" : "big-endian");
    fields.add("Version", h.ident_version == h.version
                              ? std::format("{}", h.version)
                              : std::format("{} (e_ident says {})", h.version, h.ident_version));
    fields.add("OS/ABI", std::format("{} ({})", elf::os_abi_name(h.os_abi), h.os_abi));
    fields.add("ABI version", std::format("{}", h.abi_version));
    fields.add("Type", type_description(h.type));
    fields.add("Machine", std::format("{} ({})", elf::machine_name(h.machine), h.machine));
    fields.add("Entry point", hex(h.entry));
    fields.add("Flags", hex(h.flags));
    fields.add("Header size", std::format("{} bytes", h.ehsize));
    fields.add("Program headers", std::format("{} at {}, {} bytes each", h.phnum, hex(h.phoff), h.phentsize));
    fields.add("Section headers", std::format("{} at {}, {} bytes each", h.shnum, hex(h.shoff), h.shentsize));
    std::string names = std::format("{}", h.shstrndx);
    if (h.shstrndx != 0 && h.shstrndx < f.sections.size()) names += " (" + printable(f.sections[h.shstrndx].name) + ")";
    fields.add("Section names", names);
    if (f.interpreter) fields.add("Interpreter", printable(*f.interpreter));
    if (!f.build_id.empty()) fields.add("Build ID", hex_bytes(f.build_id));
    if (f.soname) fields.add("SONAME", printable(*f.soname));
    for (const std::string& lib : f.needed) fields.add("Needed", printable(lib));
    if (f.rpath) fields.add("RPATH", printable(*f.rpath));
    if (f.runpath) fields.add("RUNPATH", printable(*f.runpath));
    out << "\nFile header:\n";
    fields.write(out);

    if (f.dynamic.empty()) return;
    Table table({{"Tag", Align::Left}, {"Type", Align::Left}, {"Value", Align::Left}});
    const std::vector<std::string> values = dynamic_values(f);
    for (std::size_t i = 0; i < f.dynamic.size(); ++i) {
        const elf::DynamicEntry& e = f.dynamic[i];
        table.add({hex_digits(static_cast<std::uint64_t>(e.tag), address_digits(f)), elf::dynamic_tag_name(e.tag),
                   values[i]});
    }
    out << std::format("\nDynamic section ({} entries):\n", f.dynamic.size());
    table.write(out);
}

void write_sections(std::ostream& out, const ElfFile& f) {
    if (f.sections.empty()) {
        out << "\nNo section headers.\n";
        return;
    }
    Table table({{"Nr", Align::Right},
                 {"Name"},
                 {"Type"},
                 {"Address"},
                 {"Offset"},
                 {"Size"},
                 {"ES", Align::Right},
                 {"Flg"},
                 {"Lk", Align::Right},
                 {"Inf", Align::Right},
                 {"Al", Align::Right}});
    for (std::size_t i = 0; i < f.sections.size(); ++i) {
        const elf::Section& s = f.sections[i];
        table.add({std::format("{}", i), printable(s.name), elf::section_type_name(s.type, f.header.machine),
                   hex_digits(s.addr, address_digits(f)), hex_digits(s.offset, 6), hex_digits(s.size, 6),
                   std::format("{}", s.entsize), elf::section_flags_string(s.flags), std::format("{}", s.link),
                   std::format("{}", s.info), std::format("{}", s.addralign)});
    }
    out << std::format("\nSections ({}):\n", f.sections.size());
    table.write(out);
    out << "  Flags: W write, A alloc, X execute, M merge, S strings, I info, L link order, O OS-specific,\n"
           "         G group, T TLS, C compressed, E exclude, x unknown\n";
}

void write_segments(std::ostream& out, const ElfFile& f) {
    if (f.segments.empty()) {
        out << "\nNo program headers.\n";
        return;
    }
    Table table({{"Type"},
                 {"Offset"},
                 {"VirtAddr"},
                 {"PhysAddr"},
                 {"FileSize"},
                 {"MemSize"},
                 {"Flg"},
                 {"Align", Align::Right}});
    for (const elf::Segment& p : f.segments) {
        table.add({elf::segment_type_name(p.type), hex_digits(p.offset, 6), hex_digits(p.vaddr, address_digits(f)),
                   hex_digits(p.paddr, address_digits(f)), hex_digits(p.filesz, 6), hex_digits(p.memsz, 6),
                   elf::segment_flags_string(p.flags), hex(p.align)});
    }
    out << std::format("\nProgram headers ({}):\n", f.segments.size());
    table.write(out);
}

void write_symbols(std::ostream& out, const ElfFile& f, const std::vector<Symbol>& symbols, std::string_view name) {
    if (symbols.empty()) {
        out << std::format("\nNo {} symbol table.\n", name);
        return;
    }
    Table table({{"Num", Align::Right},
                 {"Value"},
                 {"Size", Align::Right},
                 {"Type"},
                 {"Bind"},
                 {"Vis"},
                 {"Ndx", Align::Right},
                 {"Name"}});
    for (std::size_t i = 0; i < symbols.size(); ++i) {
        const Symbol& s = symbols[i];
        table.add({std::format("{}", i), hex_digits(s.value, address_digits(f)), std::format("{}", s.size),
                   elf::symbol_type_name(s.type), elf::symbol_bind_name(s.bind), elf::visibility_name(s.visibility),
                   elf::section_index_name(s.section_index), printable(s.name)});
    }
    out << std::format("\nSymbol table {} ({} entries):\n", name, symbols.size());
    table.write(out);
}

void write_imports(std::ostream& out, const ElfFile& f) {
    out << std::format("\nNeeded libraries ({}):\n", f.needed.size());
    for (const std::string& lib : f.needed) out << "  " << printable(lib) << '\n';
    if (f.rpath || f.runpath) {
        Fields paths;
        if (f.rpath) paths.add("RPATH", printable(*f.rpath));
        if (f.runpath) paths.add("RUNPATH", printable(*f.runpath));
        out << "\nLibrary search paths:\n";
        paths.write(out);
    }

    if (f.dynamic_symbols.empty()) {
        out << "\nNo dynamic symbol table.\n";
        return;
    }
    Table table({{"Type"}, {"Bind"}, {"Name"}});
    std::size_t count = 0;
    for (std::size_t i = 1; i < f.dynamic_symbols.size(); ++i) {
        const Symbol& s = f.dynamic_symbols[i];
        if (!is_import(s)) continue;
        ++count;
        table.add({elf::symbol_type_name(s.type), elf::symbol_bind_name(s.bind), printable(s.name)});
    }
    out << std::format("\nImported symbols ({}):\n", count);
    if (count != 0) table.write(out);
}

void write_exports(std::ostream& out, const ElfFile& f) {
    if (f.dynamic_symbols.empty()) {
        out << "\nNo dynamic symbol table.\n";
        return;
    }
    Table table({{"Value"}, {"Size", Align::Right}, {"Type"}, {"Bind"}, {"Ndx", Align::Right}, {"Name"}});
    std::size_t count = 0;
    for (std::size_t i = 1; i < f.dynamic_symbols.size(); ++i) {
        const Symbol& s = f.dynamic_symbols[i];
        if (!is_export(s)) continue;
        ++count;
        table.add({hex_digits(s.value, address_digits(f)), std::format("{}", s.size), elf::symbol_type_name(s.type),
                   elf::symbol_bind_name(s.bind), elf::section_index_name(s.section_index), printable(s.name)});
    }
    out << std::format("\nExported symbols ({}):\n", count);
    if (count != 0) table.write(out);
}

void json_symbol(JsonWriter& json, const Symbol& s, std::size_t index) {
    json.begin_object();
    json.field("index", index);
    json.field("name", s.name);
    json.field("value", s.value);
    json.field("size", s.size);
    json.field("type", elf::symbol_type_name(s.type));
    json.field("bind", elf::symbol_bind_name(s.bind));
    json.field("visibility", elf::visibility_name(s.visibility));
    json.field("section_index", s.section_index);
    json.end_object();
}

void json_symbols(JsonWriter& json, std::string_view key, const std::vector<Symbol>& symbols,
                  bool (*keep)(const Symbol&)) {
    json.key(key);
    json.begin_array();
    for (std::size_t i = 0; i < symbols.size(); ++i) {
        if (keep == nullptr || (i != 0 && keep(symbols[i]))) json_symbol(json, symbols[i], i);
    }
    json.end_array();
}

void json_optional(JsonWriter& json, std::string_view key, const std::optional<std::string>& value) {
    json.key(key);
    if (value) {
        json.value(*value);
    } else {
        json.null();
    }
}

void json_header(JsonWriter& json, const ElfFile& f) {
    const elf::FileHeader& h = f.header;
    json.key("header");
    json.begin_object();
    json.field("class", h.is64 ? "ELF64" : "ELF32");
    json.field("endian", h.endian == Endian::Little ? "little" : "big");
    json.field("ident_version", h.ident_version);
    json.field("os_abi", h.os_abi);
    json.field("os_abi_name", elf::os_abi_name(h.os_abi));
    json.field("abi_version", h.abi_version);
    json.field("type", h.type);
    json.field("type_name", elf::file_type_name(h.type));
    json.field("machine", h.machine);
    json.field("machine_name", elf::machine_name(h.machine));
    json.field("version", h.version);
    json.field("entry", h.entry);
    json.field("flags", h.flags);
    json.field("ehsize", h.ehsize);
    json.field("phoff", h.phoff);
    json.field("phentsize", h.phentsize);
    json.field("phnum", h.phnum);
    json.field("shoff", h.shoff);
    json.field("shentsize", h.shentsize);
    json.field("shnum", h.shnum);
    json.field("shstrndx", h.shstrndx);
    json_optional(json, "interpreter", f.interpreter);
    json.key("build_id");
    if (f.build_id.empty()) {
        json.null();
    } else {
        json.value(hex_bytes(f.build_id));
    }
    json_optional(json, "soname", f.soname);
    json.key("needed");
    json.begin_array();
    for (const std::string& lib : f.needed) json.value(lib);
    json.end_array();
    json_optional(json, "rpath", f.rpath);
    json_optional(json, "runpath", f.runpath);
    json.key("dynamic");
    json.begin_array();
    for (const elf::DynamicEntry& e : f.dynamic) {
        json.begin_object();
        json.field("tag", e.tag);
        json.field("tag_name", elf::dynamic_tag_name(e.tag));
        json.field("value", e.value);
        json.end_object();
    }
    json.end_array();
    json.end_object();
}

}  // namespace

std::string describe_elf(const ElfFile& f) {
    return std::format("{} {}-endian {}, {}", f.header.is64 ? "ELF64" : "ELF32",
                       f.header.endian == Endian::Little ? "little" : "big", type_description(f.header.type),
                       elf::machine_name(f.header.machine));
}

void write_elf_text(std::ostream& out, const ElfFile& f, const ReportOptions& report) {
    if (report.headers) write_header(out, f);
    if (report.sections) write_sections(out, f);
    if (report.segments) write_segments(out, f);
    if (report.symbols) write_symbols(out, f, f.symbols, symbol_table_name(f, elf::sht_symtab, ".symtab"));
    if (report.dynamic_symbols) {
        write_symbols(out, f, f.dynamic_symbols, symbol_table_name(f, elf::sht_dynsym, ".dynsym"));
    }
    if (report.imports) write_imports(out, f);
    if (report.exports) write_exports(out, f);
}

void write_elf_json(JsonWriter& json, const ElfFile& f, const ReportOptions& report) {
    json.field("format", "ELF");
    json.field("description", describe_elf(f));
    if (report.headers) json_header(json, f);
    if (report.sections) {
        json.key("sections");
        json.begin_array();
        for (std::size_t i = 0; i < f.sections.size(); ++i) {
            const elf::Section& s = f.sections[i];
            json.begin_object();
            json.field("index", i);
            json.field("name", s.name);
            json.field("type", s.type);
            json.field("type_name", elf::section_type_name(s.type, f.header.machine));
            json.field("flags", s.flags);
            json.field("flags_string", elf::section_flags_string(s.flags));
            json.field("address", s.addr);
            json.field("offset", s.offset);
            json.field("size", s.size);
            json.field("link", s.link);
            json.field("info", s.info);
            json.field("alignment", s.addralign);
            json.field("entry_size", s.entsize);
            json.end_object();
        }
        json.end_array();
    }
    if (report.segments) {
        json.key("segments");
        json.begin_array();
        for (const elf::Segment& p : f.segments) {
            json.begin_object();
            json.field("type", p.type);
            json.field("type_name", elf::segment_type_name(p.type));
            json.field("flags", elf::segment_flags_string(p.flags));
            json.field("offset", p.offset);
            json.field("vaddr", p.vaddr);
            json.field("paddr", p.paddr);
            json.field("filesz", p.filesz);
            json.field("memsz", p.memsz);
            json.field("align", p.align);
            json.end_object();
        }
        json.end_array();
    }
    if (report.symbols) json_symbols(json, "symbols", f.symbols, nullptr);
    if (report.dynamic_symbols) json_symbols(json, "dynamic_symbols", f.dynamic_symbols, nullptr);
    if (report.imports) {
        json.key("imports");
        json.begin_object();
        json.key("needed");
        json.begin_array();
        for (const std::string& lib : f.needed) json.value(lib);
        json.end_array();
        json_symbols(json, "symbols", f.dynamic_symbols, is_import);
        json.end_object();
    }
    if (report.exports) json_symbols(json, "exports", f.dynamic_symbols, is_export);
}

}  // namespace binpeek::detail
