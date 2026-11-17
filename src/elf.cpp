// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// ELF parsing. Layouts are from the System V gABI; every field is decoded
// through a Cursor in the file's byte order.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "binpeek/elf.hpp"
#include "binpeek/error.hpp"
#include "detail.hpp"

namespace binpeek::elf {

namespace {

constexpr std::uint64_t ident_size = 16;

struct Sizes {
    std::uint64_t ehdr, phdr, shdr, sym, dyn;
};

constexpr Sizes sizes32{52, 32, 40, 16, 8};
constexpr Sizes sizes64{64, 56, 64, 24, 16};

// Offsets of ELF header fields, for error messages.
struct HeaderFields {
    std::uint64_t phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx;
};

constexpr HeaderFields fields32{28, 32, 42, 44, 46, 48, 50};
constexpr HeaderFields fields64{32, 40, 54, 56, 58, 60, 62};

class Parser {
public:
    Parser(std::span<const std::byte> data, const ParseOptions& options)
        : view_(data), options_(options), budget_(data.size(), options.max_string_bytes) {}

    ElfFile run();

private:
    const Sizes& sizes() const noexcept { return file_.header.is64 ? sizes64 : sizes32; }
    const HeaderFields& fields() const noexcept { return file_.header.is64 ? fields64 : fields32; }
    Cursor cursor(std::uint64_t offset) const noexcept { return Cursor(view_, offset, file_.header.endian); }
    std::uint64_t section_header_offset(std::size_t index) const noexcept {
        return file_.header.shoff + index * std::uint64_t{file_.header.shentsize};
    }
    std::string label(std::size_t index) const;

    void read_header();
    Section read_section_header(std::uint64_t offset) const;
    void read_section_headers();
    void read_program_headers();
    void name_sections();
    void check_ranges() const;
    std::optional<std::size_t> find_section_of_type(std::uint32_t type) const noexcept;
    StringTable linked_strings(std::size_t index) const;
    std::vector<Symbol> read_symbols(std::size_t index);
    std::uint32_t extended_section_index(std::size_t symtab, std::uint64_t symbol, std::uint64_t symbol_offset);
    void read_interpreter();
    void read_dynamic();
    std::optional<std::uint64_t> address_to_offset(std::uint64_t address, std::uint64_t size) const noexcept;
    void read_build_id();
    bool scan_notes(std::uint64_t offset, std::uint64_t size, std::uint64_t align, std::string_view where);

    ByteView view_;
    ParseOptions options_;
    detail::StringBudget budget_;
    ElfFile file_;
    std::optional<std::size_t> shndx_section_;  // SHT_SYMTAB_SHNDX for .symtab, looked up on demand
    bool shndx_looked_up_ = false;
    // Note sections may overlap; scanning more than the file's worth of
    // notes would only re-read the same bytes.
    std::uint64_t note_bytes_left_ = view_.size();
};

ElfFile Parser::run() {
    read_header();
    read_section_headers();
    read_program_headers();
    name_sections();
    check_ranges();
    if (options_.symbols) {
        if (const auto i = find_section_of_type(sht_symtab)) file_.symbols = read_symbols(*i);
    }
    if (options_.dynamic_symbols) {
        if (const auto i = find_section_of_type(sht_dynsym)) file_.dynamic_symbols = read_symbols(*i);
    }
    if (options_.dynamic) {
        read_interpreter();
        read_dynamic();
        read_build_id();
    }
    return std::move(file_);
}

std::string Parser::label(std::size_t index) const {
    const std::string& name = file_.sections[index].name;
    return name.empty() ? std::format("section {}", index) : std::format("section {} ({})", index, name);
}

void Parser::read_header() {
    view_.require(0, ident_size, "ELF identification");
    if (!is_elf(view_.data())) throw FormatError(0, "not an ELF file (bad magic number)");

    FileHeader& h = file_.header;
    const std::uint8_t elf_class = view_.u8(4);
    const std::uint8_t encoding = view_.u8(5);
    if (elf_class != elfclass32 && elf_class != elfclass64) {
        throw FormatError(4, std::format("invalid ELF class {}", elf_class));
    }
    if (encoding != elfdata2lsb && encoding != elfdata2msb) {
        throw FormatError(5, std::format("invalid ELF data encoding {}", encoding));
    }
    h.is64 = elf_class == elfclass64;
    h.endian = encoding == elfdata2lsb ? Endian::Little : Endian::Big;
    h.ident_version = view_.u8(6);
    h.os_abi = view_.u8(7);
    h.abi_version = view_.u8(8);

    view_.require(0, sizes().ehdr, "ELF header");
    Cursor c = cursor(ident_size);
    h.type = c.u16();
    h.machine = c.u16();
    h.version = c.u32();
    h.entry = c.word(h.is64);
    h.phoff = c.word(h.is64);
    h.shoff = c.word(h.is64);
    h.flags = c.u32();
    h.ehsize = c.u16();
    h.phentsize = c.u16();
    const std::uint16_t phnum = c.u16();
    h.shentsize = c.u16();
    const std::uint16_t shnum = c.u16();
    const std::uint16_t shstrndx = c.u16();

    // "No table" is a zero offset; the counts are then meaningless.
    h.phnum = h.phoff == 0 ? 0 : phnum;
    h.shnum = h.shoff == 0 ? 0 : shnum;
    h.shstrndx = h.shoff == 0 ? 0 : shstrndx;
    if (h.shoff == 0) return;

    // Extended numbering keeps the real values in section header 0.
    if (shnum == 0 || shstrndx == shn_xindex || (h.phoff != 0 && phnum == pn_xnum)) {
        if (h.shentsize < sizes().shdr) {
            throw FormatError(fields().shentsize, std::format("e_shentsize {} is smaller than a section header ({})",
                                                              h.shentsize, sizes().shdr));
        }
        view_.require(h.shoff, sizes().shdr, "section header 0");
        const Section first = read_section_header(h.shoff);
        if (shnum == 0) h.shnum = first.size;
        if (shstrndx == shn_xindex) h.shstrndx = first.link;
        if (h.phoff != 0 && phnum == pn_xnum) h.phnum = first.info;
    }
}

Section Parser::read_section_header(std::uint64_t offset) const {
    const bool wide = file_.header.is64;
    Cursor c = cursor(offset);
    Section s;
    s.name_offset = c.u32();
    s.type = c.u32();
    s.flags = c.word(wide);
    s.addr = c.word(wide);
    s.offset = c.word(wide);
    s.size = c.word(wide);
    s.link = c.u32();
    s.info = c.u32();
    s.addralign = c.word(wide);
    s.entsize = c.word(wide);
    return s;
}

void Parser::read_section_headers() {
    const FileHeader& h = file_.header;
    if (h.shnum == 0) return;
    if (h.shentsize < sizes().shdr) {
        throw FormatError(fields().shentsize, std::format("e_shentsize {} is smaller than a section header ({})",
                                                          h.shentsize, sizes().shdr));
    }
    view_.require_array(h.shoff, h.shnum, h.shentsize, "section header table");
    // The table fits in the file, so the count fits in size_t.
    file_.sections.reserve(static_cast<std::size_t>(h.shnum));
    for (std::size_t i = 0; i < h.shnum; ++i) file_.sections.push_back(read_section_header(section_header_offset(i)));
}

void Parser::read_program_headers() {
    const FileHeader& h = file_.header;
    if (h.phnum == 0) return;
    if (h.phentsize < sizes().phdr) {
        throw FormatError(fields().phentsize, std::format("e_phentsize {} is smaller than a program header ({})",
                                                          h.phentsize, sizes().phdr));
    }
    view_.require_array(h.phoff, h.phnum, h.phentsize, "program header table");
    file_.segments.reserve(h.phnum);
    for (std::uint64_t i = 0; i < h.phnum; ++i) {
        Cursor c = cursor(h.phoff + i * h.phentsize);
        Segment p;
        p.type = c.u32();
        if (h.is64) {
            p.flags = c.u32();
            p.offset = c.u64();
            p.vaddr = c.u64();
            p.paddr = c.u64();
            p.filesz = c.u64();
            p.memsz = c.u64();
            p.align = c.u64();
        } else {
            p.offset = c.u32();
            p.vaddr = c.u32();
            p.paddr = c.u32();
            p.filesz = c.u32();
            p.memsz = c.u32();
            p.flags = c.u32();
            p.align = c.u32();
        }
        file_.segments.push_back(p);
    }
}

void Parser::name_sections() {
    const std::uint32_t index = file_.header.shstrndx;
    if (index == shn_undef || file_.sections.empty()) return;
    if (index >= file_.sections.size()) {
        throw FormatError(fields().shstrndx, std::format("section name table index {} is out of range ({} sections)",
                                                         index, file_.sections.size()));
    }
    const Section& table_section = file_.sections[index];
    if (!table_section.has_file_data()) {
        throw FormatError(section_header_offset(index), "the section name table has no data in the file");
    }
    const StringTable table(view_, table_section.offset, table_section.size, "section name table");
    for (Section& s : file_.sections) s.name = budget_.take(table.get(s.name_offset), table.offset());
}

void Parser::check_ranges() const {
    for (std::size_t i = 0; i < file_.sections.size(); ++i) {
        const Section& s = file_.sections[i];
        if (!s.has_file_data() || view_.contains(s.offset, s.size)) continue;
        throw FormatError(section_header_offset(i),
                          std::format("{}: data at {:#x} ({:#x} bytes) extends past the end of the file (size {:#x})",
                                      label(i), s.offset, s.size, view_.size()));
    }
    for (std::size_t i = 0; i < file_.segments.size(); ++i) {
        const Segment& p = file_.segments[i];
        if (view_.contains(p.offset, p.filesz)) continue;
        throw FormatError(file_.header.phoff + i * std::uint64_t{file_.header.phentsize},
                          std::format("program header {} ({}): data at {:#x} ({:#x} bytes) extends past the end of "
                                      "the file (size {:#x})",
                                      i, segment_type_name(p.type), p.offset, p.filesz, view_.size()));
    }
}

std::optional<std::size_t> Parser::find_section_of_type(std::uint32_t type) const noexcept {
    for (std::size_t i = 0; i < file_.sections.size(); ++i) {
        if (file_.sections[i].type == type) return i;
    }
    return std::nullopt;
}

StringTable Parser::linked_strings(std::size_t index) const {
    const Section& s = file_.sections[index];
    if (s.link >= file_.sections.size()) {
        throw FormatError(section_header_offset(index), std::format("{}: linked string table index {} is out of range",
                                                                    label(index), s.link));
    }
    const Section& strings = file_.sections[s.link];
    if (s.link == shn_undef || !strings.has_file_data()) {
        return StringTable(view_, section_header_offset(index), 0, std::format("string table of {}", label(index)));
    }
    return StringTable(view_, strings.offset, strings.size, label(s.link));
}

std::vector<Symbol> Parser::read_symbols(std::size_t index) {
    const Section& s = file_.sections[index];
    if (!s.has_file_data()) return {};
    const std::uint64_t entsize = s.entsize == 0 ? sizes().sym : s.entsize;
    if (entsize < sizes().sym) {
        throw FormatError(section_header_offset(index), std::format("{}: entry size {} is smaller than a symbol ({})",
                                                                    label(index), s.entsize, sizes().sym));
    }
    const StringTable strings = linked_strings(index);
    const std::uint64_t count = s.size / entsize;

    std::vector<Symbol> symbols;
    symbols.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        const std::uint64_t at = s.offset + i * entsize;
        Cursor c = cursor(at);
        Symbol sym;
        const std::uint32_t name = c.u32();
        std::uint8_t info = 0;
        std::uint16_t shndx = 0;
        if (file_.header.is64) {
            info = c.u8();
            sym.other = c.u8();
            shndx = c.u16();
            sym.value = c.u64();
            sym.size = c.u64();
        } else {
            sym.value = c.u32();
            sym.size = c.u32();
            info = c.u8();
            sym.other = c.u8();
            shndx = c.u16();
        }
        sym.bind = static_cast<std::uint8_t>(info >> 4);
        sym.type = static_cast<std::uint8_t>(info & 0xf);
        sym.visibility = static_cast<std::uint8_t>(sym.other & 0x3);
        sym.section_index = shndx == shn_xindex ? extended_section_index(index, i, at) : shndx;
        sym.name = budget_.take(strings.get(name), strings.offset());
        symbols.push_back(std::move(sym));
    }
    return symbols;
}

// SHN_XINDEX: the real index is entry `symbol` of the SHT_SYMTAB_SHNDX
// section that links to the symbol table.
std::uint32_t Parser::extended_section_index(std::size_t symtab, std::uint64_t symbol, std::uint64_t symbol_offset) {
    if (!shndx_looked_up_) {
        shndx_looked_up_ = true;
        for (std::size_t i = 0; i < file_.sections.size(); ++i) {
            const Section& s = file_.sections[i];
            if (s.type == sht_symtab_shndx && s.link == symtab && s.has_file_data()) {
                shndx_section_ = i;
                break;
            }
        }
    }
    if (!shndx_section_) {
        throw FormatError(symbol_offset,
                          std::format("symbol {} of {} uses SHN_XINDEX but no SHT_SYMTAB_SHNDX section links to it",
                                      symbol, label(symtab)));
    }
    const Section& table = file_.sections[*shndx_section_];
    if (symbol >= table.size / 4) {
        throw FormatError(section_header_offset(*shndx_section_),
                          std::format("{} has no entry for symbol {}", label(*shndx_section_), symbol));
    }
    return view_.u32(table.offset + symbol * 4, file_.header.endian);
}

void Parser::read_interpreter() {
    for (const Segment& p : file_.segments) {
        if (p.type != pt_interp) continue;
        const auto b = view_.bytes(p.offset, p.filesz, "PT_INTERP");
        const std::string_view text(reinterpret_cast<const char*>(b.data()), b.size());
        const std::size_t end = text.find('\0');
        if (end == std::string_view::npos) {
            throw FormatError(p.offset, "the interpreter path (PT_INTERP) is not NUL-terminated");
        }
        file_.interpreter = budget_.take(text.substr(0, end), p.offset);
        return;
    }
}

std::optional<std::uint64_t> Parser::address_to_offset(std::uint64_t address, std::uint64_t size) const noexcept {
    for (const Segment& p : file_.segments) {
        if (p.type != pt_load || address < p.vaddr) continue;
        const std::uint64_t delta = address - p.vaddr;
        if (delta < p.filesz && size <= p.filesz - delta) return p.offset + delta;
    }
    return std::nullopt;
}

// The dynamic section comes from the SHT_DYNAMIC section, with strings from
// its sh_link; without section headers, from PT_DYNAMIC, with strings found
// through DT_STRTAB and DT_STRSZ in the loadable segments.
void Parser::read_dynamic() {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::optional<StringTable> strings;
    if (const auto i = find_section_of_type(sht_dynamic); i && file_.sections[*i].has_file_data()) {
        offset = file_.sections[*i].offset;
        size = file_.sections[*i].size;
        if (file_.sections[*i].link != shn_undef) strings = linked_strings(*i);
    } else {
        const Segment* dynamic = nullptr;
        for (const Segment& p : file_.segments) {
            if (p.type == pt_dynamic) {
                dynamic = &p;
                break;
            }
        }
        if (dynamic == nullptr) return;
        offset = dynamic->offset;
        size = dynamic->filesz;
    }

    const bool wide = file_.header.is64;
    const std::uint64_t count = size / sizes().dyn;
    bool has_string_values = false;
    std::optional<std::uint64_t> strtab;
    std::optional<std::uint64_t> strsz;
    for (std::uint64_t i = 0; i < count; ++i) {
        Cursor c = cursor(offset + i * sizes().dyn);
        DynamicEntry e;
        e.tag = wide ? static_cast<std::int64_t>(c.u64()) : std::int64_t{static_cast<std::int32_t>(c.u32())};
        e.value = c.word(wide);
        if (e.tag == dt_null) break;
        if (e.tag == dt_needed || e.tag == dt_soname || e.tag == dt_rpath || e.tag == dt_runpath) {
            has_string_values = true;
        }
        if (e.tag == dt_strtab && !strtab) strtab = e.value;
        if (e.tag == dt_strsz && !strsz) strsz = e.value;
        file_.dynamic.push_back(e);
    }
    if (!has_string_values) return;

    if (!strings) {
        if (!strtab || !strsz) {
            throw FormatError(offset, "the dynamic section names libraries but has no DT_STRTAB and DT_STRSZ");
        }
        const auto at = address_to_offset(*strtab, *strsz);
        if (!at) {
            throw FormatError(offset, std::format("DT_STRTAB {:#x} ({:#x} bytes) is not inside a loadable segment",
                                                  *strtab, *strsz));
        }
        strings = StringTable(view_, *at, *strsz, "dynamic string table");
    }
    for (const DynamicEntry& e : file_.dynamic) {
        std::optional<std::string>* slot = nullptr;
        if (e.tag == dt_soname) slot = &file_.soname;
        else if (e.tag == dt_rpath) slot = &file_.rpath;
        else if (e.tag == dt_runpath) slot = &file_.runpath;
        else if (e.tag != dt_needed) continue;

        std::string value = budget_.take(strings->get(e.value), strings->offset());
        if (e.tag == dt_needed) {
            file_.needed.push_back(std::move(value));
        } else if (!*slot) {
            *slot = std::move(value);
        }
    }
}

void Parser::read_build_id() {
    bool have_note_sections = false;
    for (std::size_t i = 0; i < file_.sections.size(); ++i) {
        const Section& s = file_.sections[i];
        if (s.type != sht_note || !s.has_file_data()) continue;
        have_note_sections = true;
        if (s.size > note_bytes_left_) return;
        note_bytes_left_ -= s.size;
        if (scan_notes(s.offset, s.size, s.addralign == 8 ? 8 : 4, label(i))) return;
    }
    if (have_note_sections) return;
    for (std::size_t i = 0; i < file_.segments.size(); ++i) {
        const Segment& p = file_.segments[i];
        if (p.type != pt_note) continue;
        if (p.filesz > note_bytes_left_) return;
        note_bytes_left_ -= p.filesz;
        if (scan_notes(p.offset, p.filesz, p.align == 8 ? 8 : 4, std::format("program header {} (NOTE)", i))) return;
    }
}

// Walks the notes in [offset, offset + size) until it finds the GNU build ID.
bool Parser::scan_notes(std::uint64_t offset, std::uint64_t size, std::uint64_t align, std::string_view where) {
    constexpr std::array<std::byte, 4> gnu{std::byte{'G'}, std::byte{'N'}, std::byte{'U'}, std::byte{0}};
    std::uint64_t pos = 0;
    while (pos <= size && size - pos >= 12) {
        Cursor c = cursor(offset + pos);
        const std::uint32_t name_size = c.u32();
        const std::uint32_t desc_size = c.u32();
        const std::uint32_t type = c.u32();
        const std::uint64_t name_start = pos + 12;
        const std::uint64_t desc_start = detail::align_up(name_start + name_size, align);
        const std::uint64_t desc_end = desc_start + desc_size;
        if (desc_end > size) {
            throw FormatError(offset + pos, std::format("{}: note ({} name bytes, {} descriptor bytes) extends past "
                                                        "the end of its data",
                                                        where, name_size, desc_size));
        }
        if (type == nt_gnu_build_id && name_size == gnu.size()) {
            const auto name = view_.bytes(offset + name_start, name_size, "note name");
            if (std::equal(name.begin(), name.end(), gnu.begin())) {
                const auto desc = view_.bytes(offset + desc_start, desc_size, "note descriptor");
                file_.build_id.reserve(desc.size());
                for (const std::byte b : desc) file_.build_id.push_back(std::to_integer<std::uint8_t>(b));
                return true;
            }
        }
        pos = detail::align_up(desc_end, align);
    }
    return false;
}

}  // namespace

bool is_elf(std::span<const std::byte> data) noexcept {
    return data.size() >= 4 && data[0] == std::byte{0x7f} && data[1] == std::byte{'E'} && data[2] == std::byte{'L'} &&
           data[3] == std::byte{'F'};
}

ElfFile parse_elf(std::span<const std::byte> data, const ParseOptions& options) {
    return Parser(data, options).run();
}

const Section* ElfFile::find_section(std::string_view name) const noexcept {
    for (const Section& s : sections) {
        if (s.name == name) return &s;
    }
    return nullptr;
}

}  // namespace binpeek::elf
