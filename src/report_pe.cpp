// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <format>
#include <ostream>
#include <string>
#include <string_view>

#include "binpeek/pe.hpp"
#include "report_internal.hpp"
#include "text.hpp"

namespace binpeek::detail {

namespace {

using pe::PeFile;

std::string with_flags(std::uint64_t value, const std::string& names) {
    return names.empty() ? hex(value) : hex(value) + " " + names;
}

std::string timestamp(std::uint32_t t) { return std::format("{} ({})", hex(t), utc_time(t)); }

// The section whose virtual range holds rva, for the data directory table.
std::string section_of(const PeFile& f, std::uint32_t rva) {
    for (const pe::Section& s : f.sections) {
        const std::uint64_t span = s.virtual_size != 0 ? s.virtual_size : s.raw_size;
        if (rva >= s.virtual_address && rva - s.virtual_address < span) return printable(s.name);
    }
    return "";
}

void write_coff_header(std::ostream& out, const PeFile& f) {
    const pe::FileHeader& h = f.header;
    Fields fields;
    fields.add("Machine", std::format("{} ({})", pe::machine_name(h.machine), hex(h.machine)));
    fields.add("Sections", std::format("{}", h.section_count));
    fields.add("Time stamp", timestamp(h.timestamp));
    fields.add("Symbol table", std::format("{} records at {}", h.symbol_count, hex(h.symbol_table_offset)));
    fields.add("Optional header size", std::format("{} bytes", h.optional_header_size));
    fields.add("Characteristics", with_flags(h.characteristics, pe::file_characteristics_string(h.characteristics)));
    out << "\nCOFF file header:\n";
    fields.write(out);
}

void write_optional_header(std::ostream& out, const PeFile& f) {
    const pe::OptionalHeader& o = *f.optional_header;
    Fields fields;
    fields.add("Magic", std::format("{} ({})", hex(o.magic), o.is_pe32_plus() ? "PE32+" : "PE32"));
    fields.add("Linker version", std::format("{}.{}", o.linker_major, o.linker_minor));
    fields.add("Size of code", hex(o.size_of_code));
    fields.add("Initialized data", hex(o.size_of_initialized_data));
    fields.add("Uninitialized data", hex(o.size_of_uninitialized_data));
    fields.add("Entry point", hex(o.entry_point));
    fields.add("Base of code", hex(o.base_of_code));
    if (!o.is_pe32_plus()) fields.add("Base of data", hex(o.base_of_data));
    fields.add("Image base", hex(o.image_base));
    fields.add("Section alignment", hex(o.section_alignment));
    fields.add("File alignment", hex(o.file_alignment));
    fields.add("OS version", std::format("{}.{}", o.os_major, o.os_minor));
    fields.add("Image version", std::format("{}.{}", o.image_major, o.image_minor));
    fields.add("Subsystem version", std::format("{}.{}", o.subsystem_major, o.subsystem_minor));
    fields.add("Size of image", hex(o.size_of_image));
    fields.add("Size of headers", hex(o.size_of_headers));
    fields.add("Checksum", hex(o.checksum));
    fields.add("Subsystem", std::format("{} ({})", pe::subsystem_name(o.subsystem), o.subsystem));
    fields.add("DLL characteristics",
               with_flags(o.dll_characteristics, pe::dll_characteristics_string(o.dll_characteristics)));
    fields.add("Stack reserve/commit", std::format("{} / {}", hex(o.stack_reserve), hex(o.stack_commit)));
    fields.add("Heap reserve/commit", std::format("{} / {}", hex(o.heap_reserve), hex(o.heap_commit)));
    fields.add("Loader flags", hex(o.loader_flags));
    fields.add("Data directories", std::format("{}", o.rva_count));
    out << "\nOptional header:\n";
    fields.write(out);

    if (o.directories.empty()) return;
    Table table({{"Nr", Align::Right}, {"Name"}, {"RVA"}, {"Size"}, {"Section"}});
    for (std::size_t i = 0; i < o.directories.size(); ++i) {
        const pe::DataDirectory& d = o.directories[i];
        std::string where;
        if (i == pe::dir_security && d.rva != 0) {
            where = "(file offset)";  // the certificate table is not mapped
        } else if (d.rva != 0) {
            where = section_of(f, d.rva);
        }
        table.add({std::format("{}", i), pe::directory_name(i), "0x" + hex_digits(d.rva, 8),
                   "0x" + hex_digits(d.size, 8), where});
    }
    out << "\nData directories:\n";
    table.write(out);
}

void write_headers(std::ostream& out, const PeFile& f) {
    if (f.dos) {
        Fields fields;
        fields.add("Magic", "MZ");
        fields.add("PE header offset", hex(f.dos->pe_offset));
        out << "\nDOS header:\n";
        fields.write(out);
    }
    write_coff_header(out, f);
    if (f.optional_header) write_optional_header(out, f);
}

void write_sections(std::ostream& out, const PeFile& f) {
    if (f.sections.empty()) {
        out << "\nNo sections.\n";
        return;
    }
    Table table({{"Nr", Align::Right},
                 {"Name"},
                 {"VirtSize"},
                 {"VirtAddr"},
                 {"RawSize"},
                 {"RawPtr"},
                 {"Relocs", Align::Right},
                 {"Perm"},
                 {"Characteristics"}});
    for (std::size_t i = 0; i < f.sections.size(); ++i) {
        const pe::Section& s = f.sections[i];
        table.add({std::format("{}", i + 1), printable(s.name), hex_digits(s.virtual_size, 8),
                   hex_digits(s.virtual_address, 8), hex_digits(s.raw_size, 8), hex_digits(s.raw_offset, 8),
                   std::format("{}", s.relocation_count), pe::section_permissions(s.characteristics),
                   with_flags(s.characteristics, pe::section_characteristics_string(s.characteristics))});
    }
    out << std::format("\nSections ({}):\n", f.sections.size());
    table.write(out);
}

void write_symbols(std::ostream& out, const PeFile& f) {
    if (f.symbols.empty()) {
        out << "\nNo COFF symbol table.\n";
        return;
    }
    Table table({{"Index", Align::Right},
                 {"Value"},
                 {"Section", Align::Right},
                 {"Type"},
                 {"Class"},
                 {"Aux", Align::Right},
                 {"Name"}});
    for (const pe::Symbol& s : f.symbols) {
        table.add({std::format("{}", s.index), hex_digits(s.value, 8), pe::symbol_section_name(s.section_number),
                   hex_digits(s.type, 4), pe::storage_class_name(s.storage_class), std::format("{}", s.aux_count),
                   printable(s.name)});
    }
    out << std::format("\nCOFF symbol table ({} symbols, {} records):\n", f.symbols.size(), f.header.symbol_count);
    table.write(out);
}

void write_imports(std::ostream& out, const PeFile& f) {
    if (f.imports.empty()) {
        out << "\nNo imports.\n";
        return;
    }
    for (const pe::ImportedDll& dll : f.imports) {
        out << std::format("\nImports from {} ({}):\n", printable(dll.name),
                           counted(dll.functions.size(), "function", "functions"));
        Table table({{"IAT"}, {"Hint", Align::Right}, {"Name"}});
        for (const pe::ImportedFunction& fn : dll.functions) {
            if (fn.ordinal) {
                table.add({"0x" + hex_digits(fn.iat_rva, 8), "", std::format("ordinal {}", *fn.ordinal)});
            } else {
                table.add({"0x" + hex_digits(fn.iat_rva, 8), std::format("{}", fn.hint), printable(fn.name)});
            }
        }
        table.write(out);
    }
}

void write_exports(std::ostream& out, const PeFile& f) {
    if (!f.exports) {
        out << "\nNo exports.\n";
        return;
    }
    const pe::ExportDirectory& e = *f.exports;
    out << std::format("\nExports from {} ({}, ordinal base {}):\n", printable(e.dll_name),
                       counted(e.functions.size(), "entry", "entries"), e.ordinal_base);
    Table table({{"Ordinal", Align::Right}, {"RVA"}, {"Name"}, {"Forwarder"}});
    for (const pe::ExportedFunction& fn : e.functions) {
        table.add({std::format("{}", fn.ordinal), "0x" + hex_digits(fn.rva, 8), printable(fn.name),
                   printable(fn.forwarder)});
    }
    table.write(out);
}

void json_headers(JsonWriter& json, const PeFile& f) {
    json.key("header");
    json.begin_object();
    if (f.dos) {
        json.key("dos");
        json.begin_object();
        json.field("magic", f.dos->magic);
        json.field("pe_offset", f.dos->pe_offset);
        json.end_object();
    }
    const pe::FileHeader& h = f.header;
    json.key("coff");
    json.begin_object();
    json.field("machine", h.machine);
    json.field("machine_name", pe::machine_name(h.machine));
    json.field("section_count", h.section_count);
    json.field("timestamp", h.timestamp);
    json.field("symbol_table_offset", h.symbol_table_offset);
    json.field("symbol_count", h.symbol_count);
    json.field("optional_header_size", h.optional_header_size);
    json.field("characteristics", h.characteristics);
    json.field("characteristics_names", pe::file_characteristics_string(h.characteristics));
    json.end_object();
    if (f.optional_header) {
        const pe::OptionalHeader& o = *f.optional_header;
        json.key("optional");
        json.begin_object();
        json.field("magic", o.magic);
        json.field("linker_version", std::format("{}.{}", o.linker_major, o.linker_minor));
        json.field("size_of_code", o.size_of_code);
        json.field("size_of_initialized_data", o.size_of_initialized_data);
        json.field("size_of_uninitialized_data", o.size_of_uninitialized_data);
        json.field("entry_point", o.entry_point);
        json.field("base_of_code", o.base_of_code);
        if (!o.is_pe32_plus()) json.field("base_of_data", o.base_of_data);
        json.field("image_base", o.image_base);
        json.field("section_alignment", o.section_alignment);
        json.field("file_alignment", o.file_alignment);
        json.field("os_version", std::format("{}.{}", o.os_major, o.os_minor));
        json.field("image_version", std::format("{}.{}", o.image_major, o.image_minor));
        json.field("subsystem_version", std::format("{}.{}", o.subsystem_major, o.subsystem_minor));
        json.field("size_of_image", o.size_of_image);
        json.field("size_of_headers", o.size_of_headers);
        json.field("checksum", o.checksum);
        json.field("subsystem", o.subsystem);
        json.field("subsystem_name", pe::subsystem_name(o.subsystem));
        json.field("dll_characteristics", o.dll_characteristics);
        json.field("dll_characteristics_names", pe::dll_characteristics_string(o.dll_characteristics));
        json.field("stack_reserve", o.stack_reserve);
        json.field("stack_commit", o.stack_commit);
        json.field("heap_reserve", o.heap_reserve);
        json.field("heap_commit", o.heap_commit);
        json.field("loader_flags", o.loader_flags);
        json.key("data_directories");
        json.begin_array();
        for (std::size_t i = 0; i < o.directories.size(); ++i) {
            json.begin_object();
            json.field("index", i);
            json.field("name", pe::directory_name(i));
            json.field("rva", o.directories[i].rva);
            json.field("size", o.directories[i].size);
            json.end_object();
        }
        json.end_array();
        json.end_object();
    }
    json.end_object();
}

void json_sections(JsonWriter& json, const PeFile& f) {
    json.key("sections");
    json.begin_array();
    for (std::size_t i = 0; i < f.sections.size(); ++i) {
        const pe::Section& s = f.sections[i];
        json.begin_object();
        json.field("index", i + 1);
        json.field("name", s.name);
        json.field("short_name", s.short_name);
        json.field("virtual_size", s.virtual_size);
        json.field("virtual_address", s.virtual_address);
        json.field("raw_size", s.raw_size);
        json.field("raw_offset", s.raw_offset);
        json.field("relocations_offset", s.relocations_offset);
        json.field("relocation_count", s.relocation_count);
        json.field("line_numbers_offset", s.line_numbers_offset);
        json.field("line_number_count", s.line_number_count);
        json.field("characteristics", s.characteristics);
        json.field("characteristics_names", pe::section_characteristics_string(s.characteristics));
        json.field("permissions", pe::section_permissions(s.characteristics));
        json.end_object();
    }
    json.end_array();
}

void json_symbols(JsonWriter& json, const PeFile& f) {
    json.key("symbols");
    json.begin_array();
    for (const pe::Symbol& s : f.symbols) {
        json.begin_object();
        json.field("index", s.index);
        json.field("name", s.name);
        json.field("value", s.value);
        json.field("section_number", s.section_number);
        json.field("type", s.type);
        json.field("storage_class", s.storage_class);
        json.field("storage_class_name", pe::storage_class_name(s.storage_class));
        json.field("aux_count", s.aux_count);
        json.end_object();
    }
    json.end_array();
}

void json_imports(JsonWriter& json, const PeFile& f) {
    json.key("imports");
    json.begin_array();
    for (const pe::ImportedDll& dll : f.imports) {
        json.begin_object();
        json.field("dll", dll.name);
        json.field("lookup_table_rva", dll.lookup_table_rva);
        json.field("address_table_rva", dll.address_table_rva);
        json.field("timestamp", dll.timestamp);
        json.field("forwarder_chain", dll.forwarder_chain);
        json.key("functions");
        json.begin_array();
        for (const pe::ImportedFunction& fn : dll.functions) {
            json.begin_object();
            if (fn.ordinal) {
                json.field("ordinal", *fn.ordinal);
            } else {
                json.field("name", fn.name);
                json.field("hint", fn.hint);
            }
            json.field("iat_rva", fn.iat_rva);
            json.end_object();
        }
        json.end_array();
        json.end_object();
    }
    json.end_array();
}

void json_exports(JsonWriter& json, const PeFile& f) {
    json.key("exports");
    if (!f.exports) {
        json.null();
        return;
    }
    const pe::ExportDirectory& e = *f.exports;
    json.begin_object();
    json.field("dll_name", e.dll_name);
    json.field("ordinal_base", e.ordinal_base);
    json.field("timestamp", e.timestamp);
    json.field("version", std::format("{}.{}", e.major_version, e.minor_version));
    json.key("functions");
    json.begin_array();
    for (const pe::ExportedFunction& fn : e.functions) {
        json.begin_object();
        json.field("ordinal", fn.ordinal);
        json.field("rva", fn.rva);
        json.key("name");
        if (fn.name.empty()) {
            json.null();
        } else {
            json.value(fn.name);
        }
        json.key("forwarder");
        if (fn.forwarder.empty()) {
            json.null();
        } else {
            json.value(fn.forwarder);
        }
        json.end_object();
    }
    json.end_array();
    json.end_object();
}

}  // namespace

std::string describe_pe(const PeFile& f) {
    if (!f.is_image()) return std::format("COFF object, {}", pe::machine_name(f.header.machine));
    const pe::OptionalHeader& o = *f.optional_header;
    return std::format("{} {} ({}), {}", o.is_pe32_plus() ? "PE32+" : "PE32", f.is_dll() ? "DLL" : "executable",
                       pe::subsystem_name(o.subsystem), pe::machine_name(f.header.machine));
}

void write_pe_text(std::ostream& out, const PeFile& f, const ReportOptions& report) {
    if (report.headers) write_headers(out, f);
    if (report.sections) write_sections(out, f);
    // Parts that do not apply get a note when asked for by name.
    if (report.segments && !report.all) out << "\nNo program headers: PE/COFF files have sections only.\n";
    if (report.symbols) write_symbols(out, f);
    if (report.dynamic_symbols && !report.all) out << "\nNo dynamic symbol table: PE/COFF has imports/exports.\n";
    if (report.imports) write_imports(out, f);
    if (report.exports) write_exports(out, f);
}

void write_pe_json(JsonWriter& json, const PeFile& f, const ReportOptions& report) {
    json.field("format", f.is_image() ? "PE" : "COFF");
    json.field("description", describe_pe(f));
    if (report.headers) json_headers(json, f);
    if (report.sections) json_sections(json, f);
    if (report.symbols) json_symbols(json, f);
    if (report.imports) json_imports(json, f);
    if (report.exports) json_exports(json, f);
}

}  // namespace binpeek::detail
