// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// ELF: executables, shared objects and relocatable objects, 32 and 64 bit,
// either byte order. Constant names follow the System V gABI in lower case
// (EM_X86_64 is em_x86_64) so they cannot collide with <elf.h> macros.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "binpeek/bytes.hpp"
#include "binpeek/options.hpp"

namespace binpeek::elf {

// e_ident
inline constexpr std::uint8_t elfclass32 = 1;
inline constexpr std::uint8_t elfclass64 = 2;
inline constexpr std::uint8_t elfdata2lsb = 1;
inline constexpr std::uint8_t elfdata2msb = 2;

// e_type
inline constexpr std::uint16_t et_none = 0;
inline constexpr std::uint16_t et_rel = 1;
inline constexpr std::uint16_t et_exec = 2;
inline constexpr std::uint16_t et_dyn = 3;
inline constexpr std::uint16_t et_core = 4;

// e_machine (a selection)
inline constexpr std::uint16_t em_none = 0;
inline constexpr std::uint16_t em_sparc = 2;
inline constexpr std::uint16_t em_386 = 3;
inline constexpr std::uint16_t em_68k = 4;
inline constexpr std::uint16_t em_mips = 8;
inline constexpr std::uint16_t em_ppc = 20;
inline constexpr std::uint16_t em_ppc64 = 21;
inline constexpr std::uint16_t em_s390 = 22;
inline constexpr std::uint16_t em_arm = 40;
inline constexpr std::uint16_t em_sh = 42;
inline constexpr std::uint16_t em_sparcv9 = 43;
inline constexpr std::uint16_t em_ia_64 = 50;
inline constexpr std::uint16_t em_x86_64 = 62;
inline constexpr std::uint16_t em_aarch64 = 183;
inline constexpr std::uint16_t em_riscv = 243;
inline constexpr std::uint16_t em_bpf = 247;
inline constexpr std::uint16_t em_loongarch = 258;

// Special section indexes and counts
inline constexpr std::uint16_t shn_undef = 0;
inline constexpr std::uint16_t shn_loreserve = 0xff00;
inline constexpr std::uint16_t shn_abs = 0xfff1;
inline constexpr std::uint16_t shn_common = 0xfff2;
inline constexpr std::uint16_t shn_xindex = 0xffff;
inline constexpr std::uint16_t pn_xnum = 0xffff;

// sh_type
inline constexpr std::uint32_t sht_null = 0;
inline constexpr std::uint32_t sht_progbits = 1;
inline constexpr std::uint32_t sht_symtab = 2;
inline constexpr std::uint32_t sht_strtab = 3;
inline constexpr std::uint32_t sht_rela = 4;
inline constexpr std::uint32_t sht_hash = 5;
inline constexpr std::uint32_t sht_dynamic = 6;
inline constexpr std::uint32_t sht_note = 7;
inline constexpr std::uint32_t sht_nobits = 8;
inline constexpr std::uint32_t sht_rel = 9;
inline constexpr std::uint32_t sht_shlib = 10;
inline constexpr std::uint32_t sht_dynsym = 11;
inline constexpr std::uint32_t sht_init_array = 14;
inline constexpr std::uint32_t sht_fini_array = 15;
inline constexpr std::uint32_t sht_preinit_array = 16;
inline constexpr std::uint32_t sht_group = 17;
inline constexpr std::uint32_t sht_symtab_shndx = 18;
inline constexpr std::uint32_t sht_relr = 19;
inline constexpr std::uint32_t sht_gnu_attributes = 0x6ffffff5;
inline constexpr std::uint32_t sht_gnu_hash = 0x6ffffff6;
inline constexpr std::uint32_t sht_gnu_verdef = 0x6ffffffd;
inline constexpr std::uint32_t sht_gnu_verneed = 0x6ffffffe;
inline constexpr std::uint32_t sht_gnu_versym = 0x6fffffff;
inline constexpr std::uint32_t sht_x86_64_unwind = 0x70000001;
inline constexpr std::uint32_t sht_arm_exidx = 0x70000001;
inline constexpr std::uint32_t sht_arm_attributes = 0x70000003;
inline constexpr std::uint32_t sht_riscv_attributes = 0x70000003;

// sh_flags
inline constexpr std::uint64_t shf_write = 0x1;
inline constexpr std::uint64_t shf_alloc = 0x2;
inline constexpr std::uint64_t shf_execinstr = 0x4;
inline constexpr std::uint64_t shf_merge = 0x10;
inline constexpr std::uint64_t shf_strings = 0x20;
inline constexpr std::uint64_t shf_info_link = 0x40;
inline constexpr std::uint64_t shf_link_order = 0x80;
inline constexpr std::uint64_t shf_os_nonconforming = 0x100;
inline constexpr std::uint64_t shf_group = 0x200;
inline constexpr std::uint64_t shf_tls = 0x400;
inline constexpr std::uint64_t shf_compressed = 0x800;
inline constexpr std::uint64_t shf_exclude = 0x80000000;

// p_type
inline constexpr std::uint32_t pt_null = 0;
inline constexpr std::uint32_t pt_load = 1;
inline constexpr std::uint32_t pt_dynamic = 2;
inline constexpr std::uint32_t pt_interp = 3;
inline constexpr std::uint32_t pt_note = 4;
inline constexpr std::uint32_t pt_shlib = 5;
inline constexpr std::uint32_t pt_phdr = 6;
inline constexpr std::uint32_t pt_tls = 7;
inline constexpr std::uint32_t pt_gnu_eh_frame = 0x6474e550;
inline constexpr std::uint32_t pt_gnu_stack = 0x6474e551;
inline constexpr std::uint32_t pt_gnu_relro = 0x6474e552;
inline constexpr std::uint32_t pt_gnu_property = 0x6474e553;
inline constexpr std::uint32_t pt_gnu_sframe = 0x6474e554;

// p_flags
inline constexpr std::uint32_t pf_x = 0x1;
inline constexpr std::uint32_t pf_w = 0x2;
inline constexpr std::uint32_t pf_r = 0x4;

// Symbol binding, type and visibility
inline constexpr std::uint8_t stb_local = 0;
inline constexpr std::uint8_t stb_global = 1;
inline constexpr std::uint8_t stb_weak = 2;
inline constexpr std::uint8_t stb_gnu_unique = 10;
inline constexpr std::uint8_t stt_notype = 0;
inline constexpr std::uint8_t stt_object = 1;
inline constexpr std::uint8_t stt_func = 2;
inline constexpr std::uint8_t stt_section = 3;
inline constexpr std::uint8_t stt_file = 4;
inline constexpr std::uint8_t stt_common = 5;
inline constexpr std::uint8_t stt_tls = 6;
inline constexpr std::uint8_t stt_gnu_ifunc = 10;
inline constexpr std::uint8_t stv_default = 0;
inline constexpr std::uint8_t stv_internal = 1;
inline constexpr std::uint8_t stv_hidden = 2;
inline constexpr std::uint8_t stv_protected = 3;

// d_tag (a selection)
inline constexpr std::int64_t dt_null = 0;
inline constexpr std::int64_t dt_needed = 1;
inline constexpr std::int64_t dt_pltrelsz = 2;
inline constexpr std::int64_t dt_pltgot = 3;
inline constexpr std::int64_t dt_hash = 4;
inline constexpr std::int64_t dt_strtab = 5;
inline constexpr std::int64_t dt_symtab = 6;
inline constexpr std::int64_t dt_rela = 7;
inline constexpr std::int64_t dt_relasz = 8;
inline constexpr std::int64_t dt_relaent = 9;
inline constexpr std::int64_t dt_strsz = 10;
inline constexpr std::int64_t dt_syment = 11;
inline constexpr std::int64_t dt_init = 12;
inline constexpr std::int64_t dt_fini = 13;
inline constexpr std::int64_t dt_soname = 14;
inline constexpr std::int64_t dt_rpath = 15;
inline constexpr std::int64_t dt_symbolic = 16;
inline constexpr std::int64_t dt_rel = 17;
inline constexpr std::int64_t dt_relsz = 18;
inline constexpr std::int64_t dt_relent = 19;
inline constexpr std::int64_t dt_pltrel = 20;
inline constexpr std::int64_t dt_debug = 21;
inline constexpr std::int64_t dt_textrel = 22;
inline constexpr std::int64_t dt_jmprel = 23;
inline constexpr std::int64_t dt_bind_now = 24;
inline constexpr std::int64_t dt_init_array = 25;
inline constexpr std::int64_t dt_fini_array = 26;
inline constexpr std::int64_t dt_init_arraysz = 27;
inline constexpr std::int64_t dt_fini_arraysz = 28;
inline constexpr std::int64_t dt_runpath = 29;
inline constexpr std::int64_t dt_flags = 30;
inline constexpr std::int64_t dt_preinit_array = 32;
inline constexpr std::int64_t dt_preinit_arraysz = 33;
inline constexpr std::int64_t dt_relrsz = 35;
inline constexpr std::int64_t dt_relr = 36;
inline constexpr std::int64_t dt_relrent = 37;
inline constexpr std::int64_t dt_gnu_hash = 0x6ffffef5;
inline constexpr std::int64_t dt_versym = 0x6ffffff0;
inline constexpr std::int64_t dt_relacount = 0x6ffffff9;
inline constexpr std::int64_t dt_relcount = 0x6ffffffa;
inline constexpr std::int64_t dt_flags_1 = 0x6ffffffb;
inline constexpr std::int64_t dt_verdef = 0x6ffffffc;
inline constexpr std::int64_t dt_verdefnum = 0x6ffffffd;
inline constexpr std::int64_t dt_verneed = 0x6ffffffe;
inline constexpr std::int64_t dt_verneednum = 0x6fffffff;

// Note types (owner "GNU")
inline constexpr std::uint32_t nt_gnu_build_id = 3;

struct FileHeader {
    bool is64 = false;
    Endian endian = Endian::Little;
    std::uint8_t ident_version = 0;  ///< e_ident[EI_VERSION]
    std::uint8_t os_abi = 0;
    std::uint8_t abi_version = 0;
    std::uint16_t type = 0;
    std::uint16_t machine = 0;
    std::uint32_t version = 0;
    std::uint64_t entry = 0;
    std::uint64_t phoff = 0;
    std::uint64_t shoff = 0;
    std::uint32_t flags = 0;
    std::uint16_t ehsize = 0;
    std::uint16_t phentsize = 0;
    std::uint16_t shentsize = 0;
    /// The counts and the section name table index, with extended numbering
    /// resolved: when e_phnum is PN_XNUM, e_shnum is 0 or e_shstrndx is
    /// SHN_XINDEX, the real value is in section header 0.
    std::uint32_t phnum = 0;
    std::uint64_t shnum = 0;
    std::uint32_t shstrndx = 0;
};

struct Segment {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t paddr = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz = 0;
    std::uint64_t align = 0;
};

struct Section {
    std::string name;  ///< from the section name string table
    std::uint32_t name_offset = 0;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t addr = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t addralign = 0;
    std::uint64_t entsize = 0;

    /// False for SHT_NULL and SHT_NOBITS, whose offset and size do not
    /// describe bytes in the file.
    bool has_file_data() const noexcept { return type != sht_null && type != sht_nobits; }
};

struct Symbol {
    std::string name;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t type = 0;        ///< stt_*
    std::uint8_t bind = 0;        ///< stb_*
    std::uint8_t visibility = 0;  ///< stv_*
    std::uint8_t other = 0;       ///< the whole st_other byte
    /// st_shndx, or the index from SHT_SYMTAB_SHNDX when st_shndx is
    /// SHN_XINDEX. Reserved values (shn_abs, shn_common) are kept.
    std::uint32_t section_index = 0;

    bool is_undefined() const noexcept { return section_index == shn_undef; }
};

struct DynamicEntry {
    std::int64_t tag = 0;
    std::uint64_t value = 0;
};

struct ElfFile {
    FileHeader header;
    std::vector<Segment> segments;
    std::vector<Section> sections;
    /// .symtab and .dynsym, each including the null symbol at index 0.
    /// Empty when the file has no such table or it was not requested.
    std::vector<Symbol> symbols;
    std::vector<Symbol> dynamic_symbols;

    /// The dynamic section up to, not including, DT_NULL.
    std::vector<DynamicEntry> dynamic;
    std::vector<std::string> needed;  ///< DT_NEEDED, in order
    std::optional<std::string> soname;
    std::optional<std::string> rpath;
    std::optional<std::string> runpath;
    std::optional<std::string> interpreter;  ///< PT_INTERP
    std::vector<std::uint8_t> build_id;      ///< NT_GNU_BUILD_ID descriptor; empty when absent

    /// The first section with this name, or nullptr.
    const Section* find_section(std::string_view name) const noexcept;
};

/// True when data starts with the ELF magic number.
bool is_elf(std::span<const std::byte> data) noexcept;

/// Parses an ELF file. Throws FormatError for malformed input, including
/// any header, section or segment whose file range lies outside the data.
ElfFile parse_elf(std::span<const std::byte> data, const ParseOptions& options = {});

// Names for display. Unknown values come back as hexadecimal text.
std::string file_type_name(std::uint16_t type);
std::string machine_name(std::uint16_t machine);
std::string os_abi_name(std::uint8_t os_abi);
std::string section_type_name(std::uint32_t type, std::uint16_t machine);
std::string segment_type_name(std::uint32_t type);
std::string symbol_type_name(std::uint8_t type);
std::string symbol_bind_name(std::uint8_t bind);
std::string visibility_name(std::uint8_t visibility);
std::string dynamic_tag_name(std::int64_t tag);
/// readelf-style flag letters: W A X M S I L O G T C E, x for unknown bits.
std::string section_flags_string(std::uint64_t flags);
/// "R-X" style: R, W and X, with dashes for absent permissions.
std::string segment_flags_string(std::uint32_t flags);
/// "UND", "ABS", "COM", "XIDX" or the decimal index.
std::string section_index_name(std::uint32_t index);

}  // namespace binpeek::elf
