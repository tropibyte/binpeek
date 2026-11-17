// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include "image_builder.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "binpeek/elf.hpp"
#include "binpeek/pe.hpp"

namespace binpeek::test {

namespace {

std::uint64_t align_up(std::uint64_t x, std::uint64_t a) { return a <= 1 ? x : (x + a - 1) / a * a; }

void poke(Bytes& image, std::uint64_t at, std::uint64_t v, std::size_t n, Endian endian) {
    if (at + n > image.size()) throw std::out_of_range("poke past the end of the image");
    for (std::size_t i = 0; i < n; ++i) {
        const std::size_t shift = 8 * (endian == Endian::Little ? i : n - 1 - i);
        image[static_cast<std::size_t>(at) + i] = static_cast<std::byte>((v >> shift) & 0xff);
    }
}

void put(Bytes& out, std::uint64_t v, std::size_t n, Endian endian) {
    out.resize(out.size() + n);
    poke(out, out.size() - n, v, n, endian);
}

}  // namespace

Bytes to_bytes(std::string_view s) {
    Bytes out;
    for (const char c : s) out.push_back(static_cast<std::byte>(c));
    return out;
}

void ByteWriter::u8(std::uint8_t v) { put(data_, v, 1, endian_); }
void ByteWriter::u16(std::uint16_t v) { put(data_, v, 2, endian_); }
void ByteWriter::u32(std::uint32_t v) { put(data_, v, 4, endian_); }
void ByteWriter::u64(std::uint64_t v) { put(data_, v, 8, endian_); }
void ByteWriter::word(std::uint64_t v, bool wide) { put(data_, v, wide ? 8 : 4, endian_); }
void ByteWriter::raw(std::span<const std::byte> bytes) { data_.insert(data_.end(), bytes.begin(), bytes.end()); }
void ByteWriter::text(std::string_view s) { raw(to_bytes(s)); }

void ByteWriter::cstr(std::string_view s) {
    text(s);
    u8(0);
}

void ByteWriter::zeros(std::size_t count) { data_.resize(data_.size() + count); }
void ByteWriter::align(std::size_t alignment) { pad_to(static_cast<std::size_t>(align_up(data_.size(), alignment))); }

void ByteWriter::pad_to(std::size_t offset) {
    if (offset < data_.size()) throw std::logic_error("pad_to: already past the offset");
    data_.resize(offset);
}

void poke_u8(Bytes& image, std::uint64_t at, std::uint8_t v) { poke(image, at, v, 1, Endian::Little); }
void poke_u16(Bytes& image, std::uint64_t at, std::uint16_t v, Endian endian) { poke(image, at, v, 2, endian); }
void poke_u32(Bytes& image, std::uint64_t at, std::uint32_t v, Endian endian) { poke(image, at, v, 4, endian); }
void poke_u64(Bytes& image, std::uint64_t at, std::uint64_t v, Endian endian) { poke(image, at, v, 8, endian); }

void poke_word(Bytes& image, std::uint64_t at, std::uint64_t v, bool wide, Endian endian) {
    poke(image, at, v, wide ? 8 : 4, endian);
}

std::uint32_t peek_u32(const Bytes& image, std::uint64_t at, Endian endian) {
    return ByteView(image).u32(at, endian);
}

std::uint32_t StringTableWriter::add(std::string_view s) {
    const auto offset = static_cast<std::uint32_t>(text_.size());
    text_.append(s);
    text_.push_back('\0');
    return offset;
}

// ---- ELF -------------------------------------------------------------------

ElfFields elf_fields(bool is64) {
    if (is64) return {32, 40, 54, 56, 58, 60, 62, 0, 4, 24, 32, 40, 44, 56, 8, 32, 24, 16};
    return {28, 32, 42, 44, 46, 48, 50, 0, 4, 16, 20, 24, 28, 36, 4, 16, 16, 8};
}

Bytes elf_symbols(bool is64, Endian endian, const std::vector<ElfSymbolSpec>& symbols, StringTableWriter& strings) {
    ByteWriter w(endian);
    w.zeros(is64 ? 24 : 16);
    for (const ElfSymbolSpec& s : symbols) {
        const std::uint32_t name = strings.add(s.name);
        const auto info = static_cast<std::uint8_t>((s.bind << 4) | (s.type & 0xf));
        if (is64) {
            w.u32(name);
            w.u8(info);
            w.u8(s.visibility);
            w.u16(s.shndx);
            w.u64(s.value);
            w.u64(s.size);
        } else {
            w.u32(name);
            w.u32(static_cast<std::uint32_t>(s.value));
            w.u32(static_cast<std::uint32_t>(s.size));
            w.u8(info);
            w.u8(s.visibility);
            w.u16(s.shndx);
        }
    }
    return w.take();
}

Bytes elf_dynamic(bool is64, Endian endian, const std::vector<std::pair<std::int64_t, std::uint64_t>>& entries) {
    ByteWriter w(endian);
    for (const auto& [tag, value] : entries) {
        w.word(static_cast<std::uint64_t>(tag), is64);
        w.word(value, is64);
    }
    w.zeros(is64 ? 16 : 8);
    return w.take();
}

Bytes elf_note(Endian endian, std::string_view owner, std::uint32_t type, std::span<const std::byte> desc) {
    ByteWriter w(endian);
    w.u32(static_cast<std::uint32_t>(owner.size() + 1));
    w.u32(static_cast<std::uint32_t>(desc.size()));
    w.u32(type);
    w.cstr(owner);
    w.align(4);
    w.raw(desc);
    w.align(4);
    return w.take();
}

std::size_t ElfImage::index_of(std::string_view name) const {
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (names[i] == name) return i;
    }
    throw std::out_of_range("no section named " + std::string(name));
}

std::uint64_t ElfImage::section_header(std::size_t index) const { return shoff + index * (is64 ? 64u : 40u); }

std::uint64_t ElfImage::program_header(std::size_t index) const { return phoff + index * (is64 ? 56u : 32u); }

ElfBuilder::ElfBuilder(bool is64, Endian endian, std::uint16_t type, std::uint16_t machine)
    : is64_(is64), endian_(endian), type_(type), machine_(machine) {}

ElfImage ElfBuilder::build() const {
    const std::uint64_t ehsize = is64_ ? 64 : 52;
    const std::uint64_t phentsize = is64_ ? 56 : 32;
    const std::uint64_t shentsize = is64_ ? 64 : 40;

    ElfImage image;
    image.is64 = is64_;
    image.endian = endian_;
    image.names.push_back("");
    for (const ElfSectionSpec& s : sections_) image.names.push_back(s.name);
    image.names.push_back(".shstrtab");
    const std::size_t count = image.names.size();

    StringTableWriter shstrtab;
    std::vector<std::uint32_t> name_offsets(count, 0);
    for (std::size_t i = 1; i < count; ++i) name_offsets[i] = shstrtab.add(image.names[i]);
    const Bytes shstrtab_bytes = shstrtab.bytes();

    // Layout.
    image.phoff = segments_.empty() ? 0 : ehsize;
    std::uint64_t pos = ehsize + segments_.size() * phentsize;
    image.data_offsets.assign(count, 0);
    std::vector<std::uint64_t> sizes(count, 0), addresses(count, 0);
    std::uint64_t load_file_end = 0, load_memory_end = 0;
    for (std::size_t i = 0; i < sections_.size(); ++i) {
        const ElfSectionSpec& s = sections_[i];
        const bool nobits = s.type == elf::sht_nobits;
        pos = align_up(pos, s.align);
        image.data_offsets[i + 1] = pos;
        sizes[i + 1] = nobits ? s.nobits_size : s.data.size();
        if ((s.flags & elf::shf_alloc) != 0) {
            addresses[i + 1] = base_address + pos;
            if (!nobits) load_file_end = pos + s.data.size();
            load_memory_end = pos + sizes[i + 1];
        }
        if (!nobits) pos += s.data.size();
    }
    image.data_offsets[count - 1] = pos;
    sizes[count - 1] = shstrtab_bytes.size();
    pos += shstrtab_bytes.size();
    image.shoff = align_up(pos, 8);

    auto index_of_link = [&](const std::string& name) -> std::uint32_t {
        return name.empty() ? 0 : static_cast<std::uint32_t>(image.index_of(name));
    };

    ByteWriter w(endian_);
    w.u8(0x7f);
    w.text("ELF");
    w.u8(is64_ ? elf::elfclass64 : elf::elfclass32);
    w.u8(endian_ == Endian::Little ? elf::elfdata2lsb : elf::elfdata2msb);
    w.u8(1);
    w.pad_to(16);
    w.u16(type_);
    w.u16(machine_);
    w.u32(1);
    w.word(entry_, is64_);
    w.word(image.phoff, is64_);
    w.word(image.shoff, is64_);
    w.u32(0);
    w.u16(static_cast<std::uint16_t>(ehsize));
    w.u16(static_cast<std::uint16_t>(phentsize));
    w.u16(static_cast<std::uint16_t>(segments_.size()));
    w.u16(static_cast<std::uint16_t>(shentsize));
    w.u16(static_cast<std::uint16_t>(count));
    w.u16(static_cast<std::uint16_t>(count - 1));

    for (const ElfSegmentSpec& p : segments_) {
        std::uint64_t offset = 0, filesz = 0, memsz = 0;
        if (p.section.empty()) {
            filesz = load_file_end;
            memsz = load_memory_end;
        } else if (p.section == "[phdr]") {
            offset = image.phoff;
            filesz = memsz = segments_.size() * phentsize;
        } else {
            const std::size_t i = image.index_of(p.section);
            offset = image.data_offsets[i];
            memsz = sizes[i];
            filesz = sections_[i - 1].type == elf::sht_nobits ? 0 : sizes[i];
        }
        const std::uint64_t vaddr = base_address + offset;
        w.u32(p.type);
        if (is64_) {
            w.u32(p.flags);
            w.u64(offset);
            w.u64(vaddr);
            w.u64(vaddr);
            w.u64(filesz);
            w.u64(memsz);
            w.u64(p.align);
        } else {
            w.u32(static_cast<std::uint32_t>(offset));
            w.u32(static_cast<std::uint32_t>(vaddr));
            w.u32(static_cast<std::uint32_t>(vaddr));
            w.u32(static_cast<std::uint32_t>(filesz));
            w.u32(static_cast<std::uint32_t>(memsz));
            w.u32(p.flags);
            w.u32(static_cast<std::uint32_t>(p.align));
        }
    }

    for (std::size_t i = 0; i < sections_.size(); ++i) {
        if (sections_[i].type == elf::sht_nobits) continue;
        w.pad_to(static_cast<std::size_t>(image.data_offsets[i + 1]));
        w.raw(sections_[i].data);
    }
    w.pad_to(static_cast<std::size_t>(image.data_offsets[count - 1]));
    w.raw(shstrtab_bytes);
    w.pad_to(static_cast<std::size_t>(image.shoff));

    auto header = [&](std::uint32_t name, std::uint32_t type, std::uint64_t flags, std::uint64_t addr,
                      std::uint64_t offset, std::uint64_t size, std::uint32_t link, std::uint32_t info,
                      std::uint64_t align, std::uint64_t entsize) {
        w.u32(name);
        w.u32(type);
        w.word(flags, is64_);
        w.word(addr, is64_);
        w.word(offset, is64_);
        w.word(size, is64_);
        w.u32(link);
        w.u32(info);
        w.word(align, is64_);
        w.word(entsize, is64_);
    };
    w.zeros(static_cast<std::size_t>(shentsize));
    for (std::size_t i = 0; i < sections_.size(); ++i) {
        const ElfSectionSpec& s = sections_[i];
        header(name_offsets[i + 1], s.type, s.flags, addresses[i + 1], image.data_offsets[i + 1], sizes[i + 1],
               index_of_link(s.link), s.info, s.align, s.entsize);
    }
    header(name_offsets[count - 1], elf::sht_strtab, 0, 0, image.data_offsets[count - 1], sizes[count - 1], 0, 0, 1,
           0);
    image.bytes = w.take();
    return image;
}

std::vector<std::uint8_t> sample_build_id() {
    std::vector<std::uint8_t> id;
    for (std::uint8_t b = 0x10; b < 0x24; ++b) id.push_back(b);
    return id;
}

namespace {

ElfImage sample_elf(bool is64, Endian endian, std::uint64_t dynstr_address) {
    using namespace binpeek::elf;
    const std::uint16_t machine = is64 ? (endian == Endian::Little ? em_x86_64 : em_ppc64)
                                       : (endian == Endian::Little ? em_386 : em_mips);
    const std::uint64_t sym_size = is64 ? 24 : 16;
    const std::uint64_t dyn_size = is64 ? 16 : 8;
    // Section indexes, in the order added below.
    constexpr std::uint16_t text = 5, data = 7, bss = 8;

    StringTableWriter dynstr;
    const Bytes dynsym = elf_symbols(is64, endian,
                                     {{"puts", 0, 0, stt_func, stb_global, stv_default, shn_undef},
                                      {"exit", 0, 0, stt_func, stb_global, stv_default, shn_undef},
                                      {"sample_api", 0x401000, 16, stt_func, stb_global, stv_default, text},
                                      {"sample_data", 0x402000, 4, stt_object, stb_weak, stv_default, data},
                                      {"internal_fn", 0x401010, 8, stt_func, stb_global, stv_hidden, text}},
                                     dynstr);
    const std::uint32_t libc = dynstr.add("libc.so.6");
    const std::uint32_t libm = dynstr.add("libm.so.6");
    const std::uint32_t soname = dynstr.add("libsample.so.1");
    const std::uint32_t rpath = dynstr.add("/opt/old/lib");
    const std::uint32_t runpath = dynstr.add("$ORIGIN/../lib");
    const Bytes dynstr_bytes = dynstr.bytes();
    const Bytes dynamic = elf_dynamic(is64, endian,
                                      {{dt_needed, libc},
                                       {dt_needed, libm},
                                       {dt_soname, soname},
                                       {dt_rpath, rpath},
                                       {dt_runpath, runpath},
                                       {dt_strtab, dynstr_address},
                                       {dt_strsz, dynstr_bytes.size()}});

    StringTableWriter strtab;
    const Bytes symtab = elf_symbols(is64, endian,
                                     {{"sample.c", 0, 0, stt_file, stb_local, stv_default, shn_abs},
                                      {"", 0, 0, stt_section, stb_local, stv_default, text},
                                      {"local_counter", 0, 4, stt_object, stb_local, stv_default, bss},
                                      {"main", 0x401000, 16, stt_func, stb_global, stv_default, text},
                                      {"sample_data", 0x402000, 4, stt_object, stb_weak, stv_default, data},
                                      {"puts", 0, 0, stt_func, stb_global, stv_default, shn_undef},
                                      {"protected_fn", 0x401010, 8, stt_func, stb_global, stv_protected, text}},
                                     strtab);

    const auto id = sample_build_id();
    Bytes id_bytes;
    for (const std::uint8_t b : id) id_bytes.push_back(static_cast<std::byte>(b));

    ElfBuilder b(is64, endian, et_exec, machine);
    b.add_section({".interp", sht_progbits, shf_alloc, to_bytes(std::string("/lib/ld-sample.so.1") + '\0')});
    b.add_section({".note.gnu.build-id", sht_note, shf_alloc, elf_note(endian, "GNU", nt_gnu_build_id, id_bytes),
                   0, "", 0, 4});
    b.add_section({".dynsym", sht_dynsym, shf_alloc, dynsym, 0, ".dynstr", 1, 8, sym_size});
    b.add_section({".dynstr", sht_strtab, shf_alloc, dynstr_bytes});
    b.add_section({".text", sht_progbits, shf_alloc | shf_execinstr, Bytes(32, std::byte{0x90}), 0, "", 0, 16});
    b.add_section({".dynamic", sht_dynamic, shf_alloc | shf_write, dynamic, 0, ".dynstr", 0, 8, dyn_size});
    b.add_section({".data", sht_progbits, shf_alloc | shf_write, Bytes(8, std::byte{0x2a}), 0, "", 0, 4});
    b.add_section({".bss", sht_nobits, shf_alloc | shf_write, {}, 32, "", 0, 8});
    b.add_section({".symtab", sht_symtab, 0, symtab, 0, ".strtab", 4, 8, sym_size});
    b.add_section({".strtab", sht_strtab, 0, strtab.bytes()});
    b.add_segment({pt_phdr, pf_r, "[phdr]", 8});
    b.add_segment({pt_interp, pf_r, ".interp", 1});
    b.add_segment({pt_load, pf_r | pf_w | pf_x, "", 0x1000});
    b.add_segment({pt_dynamic, pf_r | pf_w, ".dynamic", 8});
    b.add_segment({pt_note, pf_r, ".note.gnu.build-id", 4});
    b.set_entry(0x401000);
    return b.build();
}

}  // namespace

ElfImage make_sample_elf(bool is64, Endian endian) {
    // Values never change the layout, so a first build tells where .dynstr
    // goes and a second one records its address in DT_STRTAB.
    const ElfImage draft = sample_elf(is64, endian, 0);
    return sample_elf(is64, endian, ElfBuilder::base_address + draft.data_offset(".dynstr"));
}

// ---- PE --------------------------------------------------------------------

namespace {

constexpr std::uint32_t file_alignment = 0x200;
constexpr std::uint32_t section_alignment = 0x1000;

std::uint32_t align32(std::uint64_t x, std::uint32_t a) { return static_cast<std::uint32_t>(align_up(x, a)); }

Bytes export_section(const PeExportSpec& spec, std::uint32_t base) {
    std::vector<std::pair<std::string, std::uint16_t>> names;
    for (std::size_t i = 0; i < spec.slots.size(); ++i) {
        for (const std::string& n : spec.slots[i].names) names.emplace_back(n, static_cast<std::uint16_t>(i));
    }
    std::sort(names.begin(), names.end());

    const auto slots = static_cast<std::uint32_t>(spec.slots.size());
    const auto named = static_cast<std::uint32_t>(names.size());
    const std::uint32_t functions_at = 40, names_at = functions_at + 4 * slots, ordinals_at = names_at + 4 * named;
    std::uint32_t pos = ordinals_at + 2 * named;
    const std::uint32_t dll_name_at = pos;
    pos += static_cast<std::uint32_t>(spec.dll_name.size() + 1);
    std::vector<std::uint32_t> name_at;
    for (const auto& n : names) {
        name_at.push_back(pos);
        pos += static_cast<std::uint32_t>(n.first.size() + 1);
    }
    std::vector<std::uint32_t> forwarder_at;
    for (const PeExportSlot& s : spec.slots) {
        forwarder_at.push_back(pos);
        if (!s.forwarder.empty()) pos += static_cast<std::uint32_t>(s.forwarder.size() + 1);
    }

    ByteWriter w;
    w.u32(0);
    w.u32(0);
    w.u16(1);
    w.u16(0);
    w.u32(base + dll_name_at);
    w.u32(spec.ordinal_base);
    w.u32(slots);
    w.u32(named);
    w.u32(base + functions_at);
    w.u32(base + names_at);
    w.u32(base + ordinals_at);
    for (std::size_t i = 0; i < spec.slots.size(); ++i) {
        w.u32(spec.slots[i].forwarder.empty() ? spec.slots[i].rva : base + forwarder_at[i]);
    }
    for (const std::uint32_t at : name_at) w.u32(base + at);
    for (const auto& n : names) w.u16(n.second);
    w.cstr(spec.dll_name);
    for (const auto& n : names) w.cstr(n.first);
    for (const PeExportSlot& s : spec.slots) {
        if (!s.forwarder.empty()) w.cstr(s.forwarder);
    }
    if (w.size() != pos) throw std::logic_error("export section layout mismatch");
    return w.take();
}

Bytes import_section(const std::vector<PeImportSpec>& dlls, std::uint32_t base, bool plus,
                     std::vector<std::uint32_t>& lookup_tables) {
    const std::uint32_t thunk = plus ? 8 : 4;
    std::uint32_t pos = static_cast<std::uint32_t>(dlls.size() + 1) * 20;
    std::vector<std::uint32_t> ilt, iat;
    for (const PeImportSpec& d : dlls) {
        const auto entries = static_cast<std::uint32_t>(d.functions.size() + 1);
        ilt.push_back(pos);
        pos += entries * thunk;
        iat.push_back(pos);
        pos += entries * thunk;
    }
    std::vector<std::vector<std::uint32_t>> hint_name(dlls.size());
    for (std::size_t i = 0; i < dlls.size(); ++i) {
        for (const PeImportFunctionSpec& f : dlls[i].functions) {
            hint_name[i].push_back(pos);
            if (!f.ordinal) pos = align32(pos + 2 + f.name.size() + 1, 2);
        }
    }
    std::vector<std::uint32_t> dll_name;
    for (const PeImportSpec& d : dlls) {
        dll_name.push_back(pos);
        pos += static_cast<std::uint32_t>(d.dll.size() + 1);
    }

    ByteWriter w;
    for (std::size_t i = 0; i < dlls.size(); ++i) {
        w.u32(base + ilt[i]);
        w.u32(0);
        w.u32(0);
        w.u32(base + dll_name[i]);
        w.u32(base + iat[i]);
    }
    w.zeros(20);
    for (std::size_t i = 0; i < dlls.size(); ++i) {
        for (int table = 0; table < 2; ++table) {
            for (std::size_t j = 0; j < dlls[i].functions.size(); ++j) {
                const PeImportFunctionSpec& f = dlls[i].functions[j];
                if (f.ordinal) {
                    w.word((plus ? std::uint64_t{1} << 63 : std::uint64_t{1} << 31) | *f.ordinal, plus);
                } else {
                    w.word(base + hint_name[i][j], plus);
                }
            }
            w.word(0, plus);
        }
    }
    for (const PeImportSpec& d : dlls) {
        for (const PeImportFunctionSpec& f : d.functions) {
            if (f.ordinal) continue;
            w.u16(f.hint);
            w.cstr(f.name);
            w.align(2);
        }
    }
    for (const PeImportSpec& d : dlls) w.cstr(d.dll);
    if (w.size() != pos) throw std::logic_error("import section layout mismatch");
    lookup_tables = ilt;
    return w.take();
}

}  // namespace

PeImage PeBuilder::build() const {
    constexpr std::uint32_t pe_offset = 0x80;
    const std::uint32_t optional_size = pe32_plus_ ? 240 : 224;

    PeImage image;
    image.pe32_plus = pe32_plus_;
    image.pe_offset = pe_offset;
    image.optional_header = pe_offset + 24;
    image.section_table = image.optional_header + optional_size;

    std::vector<PeSectionSpec> all = sections_;
    auto next_rva = [&] { return section_alignment * static_cast<std::uint32_t>(all.size() + 1); };
    std::uint32_t export_rva = 0, export_size = 0, import_rva = 0, import_size = 0;
    std::vector<std::uint32_t> lookup_tables;
    if (exports_) {
        export_rva = next_rva();
        all.push_back(
            {".edata", pe::scn_cnt_initialized_data | pe::scn_mem_read, export_section(*exports_, export_rva)});
        export_size = static_cast<std::uint32_t>(all.back().data.size());
    }
    if (!imports_.empty()) {
        import_rva = next_rva();
        all.push_back({".idata", pe::scn_cnt_initialized_data | pe::scn_mem_read | pe::scn_mem_write,
                       import_section(imports_, import_rva, pe32_plus_, lookup_tables)});
        import_size = static_cast<std::uint32_t>(all.back().data.size());
    }

    const auto count = static_cast<std::uint32_t>(all.size());
    const std::uint32_t headers_size = align32(image.section_table + 40 * count, file_alignment);
    std::uint32_t pos = headers_size;
    std::uint32_t code_size = 0, data_size = 0, bss_size = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const PeSectionSpec& s = all[i];
        if (s.data.size() >= section_alignment) throw std::logic_error("test sections must be under 4 KiB");
        const std::uint32_t raw = align32(s.data.size(), file_alignment);
        image.rvas.push_back(section_alignment * (i + 1));
        image.raw_offsets.push_back(raw != 0 ? pos : 0);
        image.raw_sizes.push_back(raw);
        pos += raw;
        if ((s.characteristics & pe::scn_cnt_code) != 0) code_size += raw;
        if ((s.characteristics & pe::scn_cnt_initialized_data) != 0) data_size += raw;
        bss_size += s.uninitialized_size;
    }
    if (export_rva != 0) image.export_directory = image.raw_offsets[count - (import_rva != 0 ? 2 : 1)];
    if (import_rva != 0) {
        image.import_directory = image.raw_offsets[count - 1];
        for (const std::uint32_t t : lookup_tables) image.lookup_tables.push_back(image.import_directory + t);
    }

    ByteWriter w;
    w.text("MZ");
    w.u16(0x90);  // bytes on the last page
    w.u16(3);     // pages
    w.pad_to(0x3c);
    w.u32(pe_offset);
    w.pad_to(pe_offset);
    w.text(std::string_view("PE\0\0", 4));
    w.u16(machine_);
    w.u16(static_cast<std::uint16_t>(count));
    w.u32(0x65000000);  // 2023-09-12 06:06:56 UTC
    w.u32(0);
    w.u32(0);
    w.u16(static_cast<std::uint16_t>(optional_size));
    w.u16(characteristics_);

    w.u16(pe32_plus_ ? pe::magic_pe32_plus : pe::magic_pe32);
    w.u8(14);
    w.u8(38);
    w.u32(code_size);
    w.u32(data_size);
    w.u32(bss_size);
    w.u32(count != 0 ? section_alignment : 0);  // entry point: the start of the first section
    w.u32(section_alignment);
    if (!pe32_plus_) w.u32(2 * section_alignment);
    w.word(pe32_plus_ ? 0x180000000ull : 0x10000000ull, pe32_plus_);
    w.u32(section_alignment);
    w.u32(file_alignment);
    w.u16(6);  // OS version
    w.u16(0);
    w.u16(1);  // image version
    w.u16(2);
    w.u16(6);  // subsystem version
    w.u16(0);
    w.u32(0);
    w.u32(section_alignment * (count + 1));
    w.u32(headers_size);
    w.u32(0);
    w.u16(subsystem_);
    w.u16(dll_characteristics_);
    w.word(0x100000, pe32_plus_);
    w.word(0x1000, pe32_plus_);
    w.word(0x100000, pe32_plus_);
    w.word(0x1000, pe32_plus_);
    w.u32(0);
    w.u32(16);
    w.u32(export_rva);
    w.u32(export_size);
    w.u32(import_rva);
    w.u32(import_size);
    w.zeros(14 * 8);

    for (std::uint32_t i = 0; i < count; ++i) {
        const PeSectionSpec& s = all[i];
        Bytes name = to_bytes(s.name.substr(0, 8));
        name.resize(8);
        w.raw(name);
        w.u32(s.data.empty() ? s.uninitialized_size : static_cast<std::uint32_t>(s.data.size()));
        w.u32(image.rvas[i]);
        w.u32(image.raw_sizes[i]);
        w.u32(image.raw_offsets[i]);
        w.zeros(12);
        w.u32(s.characteristics);
    }
    w.pad_to(headers_size);
    for (std::uint32_t i = 0; i < count; ++i) {
        if (image.raw_sizes[i] == 0) continue;
        w.raw(all[i].data);
        w.pad_to(image.raw_offsets[i] + image.raw_sizes[i]);
    }
    image.bytes = w.take();
    return image;
}

PeImage make_sample_pe(bool pe32_plus) {
    using namespace binpeek::pe;
    PeBuilder b(pe32_plus, pe32_plus ? machine_amd64 : machine_i386);
    b.set_characteristics(static_cast<std::uint16_t>(file_executable_image | file_dll |
                                                     (pe32_plus ? file_large_address_aware : file_32bit_machine)));
    b.set_subsystem(subsystem_windows_gui);
    b.set_dll_characteristics(static_cast<std::uint16_t>(dllchar_dynamic_base | dllchar_nx_compat |
                                                         (pe32_plus ? dllchar_high_entropy_va : 0)));
    b.add_section({".text", scn_cnt_code | scn_mem_execute | scn_mem_read, Bytes(64, std::byte{0xc3})});
    b.add_section({".data", scn_cnt_initialized_data | scn_mem_read | scn_mem_write, Bytes(16, std::byte{0x01})});
    b.add_section({".bss", scn_cnt_uninitialized_data | scn_mem_read | scn_mem_write, {}, 0x80});
    b.set_exports({"sample.dll",
                   5,
                   {{0x1000, "", {"alpha"}},
                    {0x1010, "", {"beta", "beta_alias"}},
                    {0, "", {}},
                    {0x1020, "", {}},
                    {0, "KERNEL32.ExitProcess", {"Quit"}}}});
    b.set_imports({{"KERNEL32.dll", {{"ExitProcess", 0x163, {}}, {"GetStdHandle", 0x2e8, {}}}},
                   {"USER32.dll", {{"MessageBoxA", 0x285, {}}, {"", 0, std::uint16_t{17}}}}});
    return b.build();
}

// ---- COFF ------------------------------------------------------------------

CoffImage CoffBuilder::build() const {
    std::string strings;
    auto string_offset = [&](const std::string& s) {
        const auto offset = static_cast<std::uint32_t>(4 + strings.size());
        strings += s;
        strings += '\0';
        return offset;
    };

    CoffImage image;
    const auto count = static_cast<std::uint32_t>(sections_.size());
    image.section_table = 20;
    std::uint32_t pos = image.section_table + 40 * count;
    for (const PeSectionSpec& s : sections_) {
        pos = align32(pos, 4);
        image.raw_offsets.push_back(s.data.empty() ? 0 : pos);
        pos += static_cast<std::uint32_t>(s.data.size());
    }
    image.symbol_table = align32(pos, 4);
    std::uint32_t records = 0;
    for (const CoffSymbolSpec& s : symbols_) records += 1u + s.aux_count;
    image.string_table = image.symbol_table + 18 * records;

    ByteWriter w;
    w.u16(machine_);
    w.u16(static_cast<std::uint16_t>(count));
    w.u32(0);
    w.u32(image.symbol_table);
    w.u32(records);
    w.u16(0);
    w.u16(0);
    for (std::uint32_t i = 0; i < count; ++i) {
        const PeSectionSpec& s = sections_[i];
        Bytes name = to_bytes(s.name.size() <= 8 ? s.name : "/" + std::to_string(string_offset(s.name)));
        name.resize(8);
        w.raw(name);
        w.u32(0);
        w.u32(0);
        w.u32(s.data.empty() ? s.uninitialized_size : static_cast<std::uint32_t>(s.data.size()));
        w.u32(image.raw_offsets[i]);
        w.zeros(12);
        w.u32(s.characteristics);
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        if (sections_[i].data.empty()) continue;
        w.pad_to(image.raw_offsets[i]);
        w.raw(sections_[i].data);
    }
    w.pad_to(image.symbol_table);
    for (const CoffSymbolSpec& s : symbols_) {
        if (s.name.size() <= 8) {
            Bytes name = to_bytes(s.name);
            name.resize(8);
            w.raw(name);
        } else {
            w.u32(0);
            w.u32(string_offset(s.name));
        }
        w.u32(s.value);
        w.u16(static_cast<std::uint16_t>(s.section));
        w.u16(s.type);
        w.u8(s.storage_class);
        w.u8(s.aux_count);
        w.zeros(18u * s.aux_count);
    }
    w.u32(static_cast<std::uint32_t>(4 + strings.size()));
    w.text(strings);
    image.bytes = w.take();
    return image;
}

CoffImage make_sample_coff(std::uint16_t machine) {
    using namespace binpeek::pe;
    CoffBuilder b(machine);
    b.add_section({".text", scn_cnt_code | scn_mem_execute | scn_mem_read | 0x00500000, Bytes(16, std::byte{0xc3})});
    b.add_section({".data", scn_cnt_initialized_data | scn_mem_read | scn_mem_write, Bytes(8, std::byte{0x07})});
    b.add_section({".bss", scn_cnt_uninitialized_data | scn_mem_read | scn_mem_write, {}, 16});
    b.add_section({".debug_long_section", scn_cnt_initialized_data | scn_mem_discardable | scn_mem_read,
                   Bytes(4, std::byte{0x00})});
    b.add_symbol({".file", 0, sym_debug, 0, class_file, 1});
    b.add_symbol({".text", 0, 1, 0, class_static, 1});
    b.add_symbol({"main", 0, 1, sym_dtype_function, class_external, 0});
    b.add_symbol({"a_long_external_name", 4, 2, 0, class_external, 0});
    b.add_symbol({"puts", 0, sym_undefined, sym_dtype_function, class_external, 0});
    b.add_symbol({"abs_value", 0x1234, sym_absolute, 0, class_external, 0});
    b.add_symbol({"counter", 0, 3, 0, class_static, 0});
    return b.build();
}

}  // namespace binpeek::test
