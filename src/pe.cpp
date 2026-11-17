// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// PE images: DOS header, optional header, RVA mapping, imports and exports.
// Layouts are from the Microsoft PE/COFF specification.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "binpeek/error.hpp"
#include "binpeek/pe.hpp"
#include "coff.hpp"

namespace binpeek::pe {

namespace {

constexpr std::uint64_t dos_header_size = 64;
constexpr std::uint64_t lfanew_offset = 0x3c;
constexpr std::uint64_t import_descriptor_size = 20;
constexpr std::uint64_t export_directory_size = 40;
constexpr std::uint16_t mz = 0x5a4d;

// The part of the optional header before the data directories.
constexpr std::uint64_t fixed_optional_size(bool plus) noexcept { return plus ? 112 : 96; }

// The section's extent in memory: VirtualSize, or SizeOfRawData when that is 0.
constexpr std::uint64_t virtual_span(const Section& s) noexcept {
    return s.virtual_size != 0 ? s.virtual_size : s.raw_size;
}

// Where an RVA is in the file and how many bytes of file data follow it in
// the same section (or header region).
struct Location {
    std::uint64_t offset;
    std::uint64_t available;
};

// RVA lookup in O(log n) over sections sorted by address. Overlapping
// sections are rejected when the map is built, which makes the answer the
// same as rva_to_offset()'s first-match-in-table-order.
class RvaMap {
public:
    RvaMap(ByteView view, const std::vector<Section>& sections, std::uint32_t size_of_headers,
           std::uint64_t section_table_offset)
        : header_end_(std::min<std::uint64_t>(size_of_headers, view.size())) {
        for (std::size_t i = 0; i < sections.size(); ++i) {
            const Section& s = sections[i];
            const std::uint64_t span = virtual_span(s);
            if (span == 0) continue;
            ranges_.push_back({s.virtual_address, s.virtual_address + span, s.has_file_data() ? s.raw_offset : 0,
                               s.has_file_data() ? s.raw_size : 0, i});
        }
        std::sort(ranges_.begin(), ranges_.end(), [](const Range& a, const Range& b) {
            return a.start != b.start ? a.start < b.start : a.index < b.index;
        });
        for (std::size_t i = 1; i < ranges_.size(); ++i) {
            const Range& prev = ranges_[i - 1];
            const Range& next = ranges_[i];
            if (next.start < prev.end) {
                throw FormatError(section_table_offset + next.index * detail::section_header_size,
                                  std::format("sections {} ({}) and {} ({}) overlap in memory", prev.index + 1,
                                              sections[prev.index].name, next.index + 1, sections[next.index].name));
            }
        }
    }

    std::optional<Location> find(std::uint32_t rva) const noexcept {
        auto it = std::upper_bound(ranges_.begin(), ranges_.end(), std::uint64_t{rva},
                                   [](std::uint64_t value, const Range& r) { return value < r.start; });
        if (it != ranges_.begin()) {
            const Range& r = *std::prev(it);
            const std::uint64_t delta = rva - r.start;
            if (rva < r.end && delta < r.raw_size) return Location{r.raw_offset + delta, r.raw_size - delta};
        }
        if (rva < header_end_) return Location{rva, header_end_ - rva};
        return std::nullopt;
    }

    /// Like find(), but throws FormatError at error_offset naming what.
    Location locate(std::uint32_t rva, std::uint64_t error_offset, std::string_view what) const {
        if (const auto loc = find(rva)) return *loc;
        throw FormatError(error_offset,
                          std::format("{} RVA {:#x} is not inside any section's data in the file", what, rva));
    }

private:
    struct Range {
        std::uint64_t start;
        std::uint64_t end;
        std::uint64_t raw_offset;
        std::uint64_t raw_size;
        std::size_t index;
    };

    std::vector<Range> ranges_;
    std::uint64_t header_end_;
};

class ImageParser {
public:
    ImageParser(std::span<const std::byte> data, const ParseOptions& options)
        : view_(data), options_(options), budget_(data.size(), options.max_string_bytes) {}

    PeFile run();

private:
    DosHeader read_dos_header() const;
    OptionalHeader read_optional_header(std::uint64_t offset, std::uint64_t size) const;
    std::uint64_t directory_entry_offset(std::size_t index) const noexcept {
        return optional_offset_ + fixed_optional_size(file_.is_pe32_plus()) + index * 8;
    }
    std::string c_string(const Location& loc, std::uint32_t rva, std::string_view what);
    void read_imports(const RvaMap& map);
    void read_exports(const RvaMap& map);

    ByteView view_;
    ParseOptions options_;
    binpeek::detail::StringBudget budget_;
    PeFile file_;
    std::uint64_t optional_offset_ = 0;
};

PeFile ImageParser::run() {
    file_.dos = read_dos_header();
    const std::uint64_t pe_offset = file_.dos->pe_offset;
    if (!view_.contains(pe_offset, 4)) {
        throw FormatError(lfanew_offset, std::format("e_lfanew {:#x} points past the end of the file (size {:#x})",
                                                     pe_offset, view_.size()));
    }
    if (view_.u32(pe_offset, Endian::Little) != 0x00004550) {
        throw FormatError(pe_offset, "no \"PE\\0\\0\" signature at e_lfanew (an MS-DOS program?)");
    }
    file_.header = detail::read_file_header(view_, pe_offset + 4);
    optional_offset_ = pe_offset + 4 + detail::file_header_size;
    const std::uint16_t optional_size = file_.header.optional_header_size;
    if (optional_size == 0) throw FormatError(pe_offset + 20, "the image has no optional header");
    file_.optional_header = read_optional_header(optional_offset_, optional_size);

    const std::uint64_t table = optional_offset_ + optional_size;
    file_.sections = detail::read_section_table(view_, table, file_.header.section_count, budget_);
    detail::finish_sections(view_, file_.header, table, file_.sections, budget_);
    if (options_.symbols) file_.symbols = detail::read_symbols(view_, file_.header, budget_);

    if (options_.imports || options_.exports) {
        const RvaMap map(view_, file_.sections, file_.optional_header->size_of_headers, table);
        if (options_.imports) read_imports(map);
        if (options_.exports) read_exports(map);
    }
    return std::move(file_);
}

DosHeader ImageParser::read_dos_header() const {
    view_.require(0, dos_header_size, "DOS header");
    Cursor c(view_, 0, Endian::Little);
    DosHeader d;
    d.magic = c.u16();
    if (d.magic != mz) throw FormatError(0, "not a PE image (no MZ signature)");
    d.last_page_bytes = c.u16();
    d.page_count = c.u16();
    d.relocation_count = c.u16();
    d.header_paragraphs = c.u16();
    d.min_extra_paragraphs = c.u16();
    d.max_extra_paragraphs = c.u16();
    d.initial_ss = c.u16();
    d.initial_sp = c.u16();
    d.checksum = c.u16();
    d.initial_ip = c.u16();
    d.initial_cs = c.u16();
    d.relocation_table_offset = c.u16();
    d.overlay_number = c.u16();
    c.skip(8);  // e_res
    d.oem_id = c.u16();
    d.oem_info = c.u16();
    c.seek(lfanew_offset);
    d.pe_offset = c.u32();
    return d;
}

OptionalHeader ImageParser::read_optional_header(std::uint64_t offset, std::uint64_t size) const {
    view_.require(offset, size, "optional header");
    Cursor c(view_, offset, Endian::Little);
    OptionalHeader o;
    o.magic = c.u16();
    if (o.magic != magic_pe32 && o.magic != magic_pe32_plus) {
        throw FormatError(offset, std::format("unknown optional header magic {:#x}", o.magic));
    }
    const bool plus = o.is_pe32_plus();
    const std::uint64_t fixed = fixed_optional_size(plus);
    if (size < fixed) {
        throw FormatError(offset, std::format("the optional header ({} bytes) is too small for {} ({} bytes)", size,
                                              plus ? "PE32+" : "PE32", fixed));
    }
    o.linker_major = c.u8();
    o.linker_minor = c.u8();
    o.size_of_code = c.u32();
    o.size_of_initialized_data = c.u32();
    o.size_of_uninitialized_data = c.u32();
    o.entry_point = c.u32();
    o.base_of_code = c.u32();
    if (!plus) o.base_of_data = c.u32();
    o.image_base = c.word(plus);
    o.section_alignment = c.u32();
    o.file_alignment = c.u32();
    o.os_major = c.u16();
    o.os_minor = c.u16();
    o.image_major = c.u16();
    o.image_minor = c.u16();
    o.subsystem_major = c.u16();
    o.subsystem_minor = c.u16();
    o.win32_version = c.u32();
    o.size_of_image = c.u32();
    o.size_of_headers = c.u32();
    o.checksum = c.u32();
    o.subsystem = c.u16();
    o.dll_characteristics = c.u16();
    o.stack_reserve = c.word(plus);
    o.stack_commit = c.word(plus);
    o.heap_reserve = c.word(plus);
    o.heap_commit = c.word(plus);
    o.loader_flags = c.u32();
    o.rva_count = c.u32();
    const std::uint64_t room = (size - fixed) / 8;
    if (o.rva_count > room) {
        throw FormatError(offset + fixed - 4, std::format("NumberOfRvaAndSizes {} does not fit in the optional "
                                                          "header (room for {})",
                                                          o.rva_count, room));
    }
    o.directories.reserve(o.rva_count);
    for (std::uint32_t i = 0; i < o.rva_count; ++i) {
        DataDirectory d;
        d.rva = c.u32();
        d.size = c.u32();
        o.directories.push_back(d);
    }
    return o;
}

std::string ImageParser::c_string(const Location& loc, std::uint32_t rva, std::string_view what) {
    const auto b = view_.bytes(loc.offset, loc.available, what);
    const std::string_view text(reinterpret_cast<const char*>(b.data()), b.size());
    const std::size_t end = text.find('\0');
    if (end == std::string_view::npos) {
        throw FormatError(loc.offset,
                          std::format("{} at RVA {:#x} is not NUL-terminated within its section", what, rva));
    }
    return budget_.take(text.substr(0, end), loc.offset);
}

void ImageParser::read_imports(const RvaMap& map) {
    const DataDirectory dir = file_.optional_header->directory(dir_import);
    if (dir.rva == 0) return;
    const Location table = map.locate(dir.rva, directory_entry_offset(dir_import), "import directory");
    const bool plus = file_.is_pe32_plus();
    const std::uint64_t thunk_size = plus ? 8 : 4;
    const std::uint64_t ordinal_flag = plus ? std::uint64_t{1} << 63 : std::uint64_t{1} << 31;
    // Disjoint lookup tables cannot hold more entries than this; descriptors
    // sharing one table could otherwise multiply the output.
    std::uint64_t entries_left = view_.size() / thunk_size;

    for (std::uint64_t i = 0;; ++i) {
        const std::uint64_t pos = i * import_descriptor_size;
        const std::uint64_t at = table.offset + pos;
        if (table.available < import_descriptor_size || pos > table.available - import_descriptor_size) {
            throw FormatError(table.offset, "the import directory has no null terminator within its section");
        }
        Cursor c(view_, at, Endian::Little);
        ImportedDll dll;
        dll.lookup_table_rva = c.u32();
        dll.timestamp = c.u32();
        dll.forwarder_chain = c.u32();
        dll.name_rva = c.u32();
        dll.address_table_rva = c.u32();
        if (dll.lookup_table_rva == 0 && dll.timestamp == 0 && dll.forwarder_chain == 0 && dll.name_rva == 0 &&
            dll.address_table_rva == 0) {
            break;
        }
        dll.name = c_string(map.locate(dll.name_rva, at + 12, "imported DLL name"), dll.name_rva, "imported DLL name");

        const std::uint32_t lookup_rva = dll.lookup_table_rva != 0 ? dll.lookup_table_rva : dll.address_table_rva;
        if (lookup_rva == 0) {
            throw FormatError(at, std::format("the import descriptor for {} has no lookup table", dll.name));
        }
        const Location lookup = map.locate(lookup_rva, at, std::format("import lookup table for {}", dll.name));
        for (std::uint64_t j = 0;; ++j) {
            const std::uint64_t entry_pos = j * thunk_size;
            if (lookup.available < thunk_size || entry_pos > lookup.available - thunk_size) {
                throw FormatError(lookup.offset, std::format("the import lookup table for {} has no null terminator "
                                                             "within its section",
                                                             dll.name));
            }
            const std::uint64_t entry_at = lookup.offset + entry_pos;
            const std::uint64_t entry =
                plus ? view_.u64(entry_at, Endian::Little) : view_.u32(entry_at, Endian::Little);
            if (entry == 0) break;
            if (entries_left == 0) {
                throw FormatError(entry_at, "the import lookup tables hold more entries than the file has room for");
            }
            --entries_left;

            ImportedFunction fn;
            if (dll.address_table_rva != 0) {
                const std::uint64_t slot = dll.address_table_rva + entry_pos;
                if (slot > std::numeric_limits<std::uint32_t>::max()) {
                    throw FormatError(at + 16,
                                      std::format("the import address table for {} runs past 4 GiB", dll.name));
                }
                fn.iat_rva = static_cast<std::uint32_t>(slot);
            }
            if ((entry & ordinal_flag) != 0) {
                fn.ordinal = static_cast<std::uint16_t>(entry & 0xffff);
            } else {
                // A hint/name RVA has 31 bits; in PE32+ bits 31 to 62 must be clear.
                if (entry > 0x7fffffff) {
                    throw FormatError(entry_at, std::format("import lookup entry {:#x} for {} is neither an ordinal "
                                                            "nor a hint/name RVA",
                                                            entry, dll.name));
                }
                const auto hint_rva = static_cast<std::uint32_t>(entry);
                const Location hint =
                    map.locate(hint_rva, entry_at, std::format("import hint/name entry for {}", dll.name));
                if (hint.available < 2) {
                    throw FormatError(hint.offset, std::format("import hint/name entry for {} is truncated", dll.name));
                }
                fn.hint = view_.u16(hint.offset, Endian::Little);
                fn.name = c_string({hint.offset + 2, hint.available - 2}, hint_rva + 2, "imported function name");
            }
            dll.functions.push_back(std::move(fn));
        }
        file_.imports.push_back(std::move(dll));
    }
}

void ImageParser::read_exports(const RvaMap& map) {
    const DataDirectory dir = file_.optional_header->directory(dir_export);
    if (dir.rva == 0) return;
    const Location loc = map.locate(dir.rva, directory_entry_offset(dir_export), "export directory");
    if (loc.available < export_directory_size) {
        throw FormatError(loc.offset, std::format("the export directory ({} bytes) is cut off by the end of its "
                                                  "section ({} bytes left)",
                                                  export_directory_size, loc.available));
    }
    Cursor c(view_, loc.offset, Endian::Little);
    ExportDirectory e;
    e.characteristics = c.u32();
    e.timestamp = c.u32();
    e.major_version = c.u16();
    e.minor_version = c.u16();
    const std::uint32_t name_rva = c.u32();
    e.ordinal_base = c.u32();
    e.function_count = c.u32();
    e.name_count = c.u32();
    e.functions_rva = c.u32();
    e.names_rva = c.u32();
    e.name_ordinals_rva = c.u32();
    if (name_rva != 0) {
        e.dll_name = c_string(map.locate(name_rva, loc.offset + 12, "export DLL name"), name_rva, "export DLL name");
    }
    if (e.function_count != 0 &&
        std::uint64_t{e.ordinal_base} + e.function_count - 1 > std::numeric_limits<std::uint32_t>::max()) {
        throw FormatError(loc.offset + 16, std::format("ordinal base {} plus {} functions overflows 32 bits",
                                                       e.ordinal_base, e.function_count));
    }

    // Checks that an array of count entries fits in the data after its RVA.
    auto array = [&](std::uint32_t rva, std::uint64_t count, std::uint64_t entry_size, std::uint64_t field,
                     std::string_view what) {
        const Location at = map.locate(rva, loc.offset + field, what);
        if (count > at.available / entry_size) {
            throw FormatError(at.offset,
                              std::format("{} ({} entries) extends past the end of its section", what, count));
        }
        return at.offset;
    };

    std::vector<std::uint32_t> addresses;
    if (e.function_count != 0) {
        const std::uint64_t at = array(e.functions_rva, e.function_count, 4, 28, "export address table");
        addresses.reserve(e.function_count);
        for (std::uint64_t i = 0; i < e.function_count; ++i) addresses.push_back(view_.u32(at + i * 4, Endian::Little));
    }

    std::vector<std::pair<std::uint32_t, std::string>> names;  // (address table index, name)
    if (e.name_count != 0) {
        const std::uint64_t names_at = array(e.names_rva, e.name_count, 4, 32, "export name pointer table");
        const std::uint64_t ordinals_at = array(e.name_ordinals_rva, e.name_count, 2, 36, "export ordinal table");
        names.reserve(e.name_count);
        for (std::uint64_t i = 0; i < e.name_count; ++i) {
            const std::uint16_t index = view_.u16(ordinals_at + i * 2, Endian::Little);
            if (index >= e.function_count) {
                throw FormatError(ordinals_at + i * 2, std::format("export name {} refers to function {}, past the "
                                                                   "end of the address table ({} entries)",
                                                                   i, index, e.function_count));
            }
            const std::uint32_t rva = view_.u32(names_at + i * 4, Endian::Little);
            names.emplace_back(index, c_string(map.locate(rva, names_at + i * 4, "export name"), rva, "export name"));
        }
        std::stable_sort(names.begin(), names.end(),
                         [](const auto& a, const auto& b) { return a.first < b.first; });
    }

    auto next_name = names.begin();
    for (std::uint32_t i = 0; i < e.function_count; ++i) {
        const auto first_name = next_name;
        while (next_name != names.end() && next_name->first == i) ++next_name;
        const std::uint32_t rva = addresses[i];
        if (rva == 0 && first_name == next_name) continue;  // unused slot

        ExportedFunction fn;
        fn.ordinal = e.ordinal_base + i;
        fn.rva = rva;
        // An RVA inside the export directory points at a forwarder string.
        if (rva >= dir.rva && rva - dir.rva < dir.size) {
            fn.forwarder = c_string(map.locate(rva, loc.offset + 28, "export forwarder"), rva, "export forwarder");
        }
        if (first_name == next_name) {
            e.functions.push_back(std::move(fn));
            continue;
        }
        for (auto it = first_name; it != next_name; ++it) {
            ExportedFunction named = fn;
            named.name = std::move(it->second);
            if (it != first_name) budget_.charge(named.forwarder.size(), loc.offset);
            e.functions.push_back(std::move(named));
        }
    }
    file_.exports = std::move(e);
}

}  // namespace

DataDirectory OptionalHeader::directory(std::size_t index) const noexcept {
    return index < directories.size() ? directories[index] : DataDirectory{};
}

bool is_pe(std::span<const std::byte> data) noexcept {
    const ByteView view(data);
    if (!view.contains(0, dos_header_size)) return false;
    if (data[0] != std::byte{'M'} || data[1] != std::byte{'Z'}) return false;
    const std::uint64_t pe_offset = view.u32(lfanew_offset, Endian::Little);
    return view.contains(pe_offset, 4) && view.u32(pe_offset, Endian::Little) == 0x00004550;
}

PeFile parse_pe(std::span<const std::byte> data, const ParseOptions& options) {
    return ImageParser(data, options).run();
}

std::optional<std::uint64_t> rva_to_offset(const PeFile& file, std::uint32_t rva) noexcept {
    for (const Section& s : file.sections) {
        if (rva < s.virtual_address || !s.has_file_data()) continue;
        const std::uint64_t delta = rva - s.virtual_address;
        if (delta < virtual_span(s) && delta < s.raw_size) return std::uint64_t{s.raw_offset} + delta;
    }
    if (file.optional_header && rva < file.optional_header->size_of_headers) return rva;
    return std::nullopt;
}

}  // namespace binpeek::pe
