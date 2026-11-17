// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility>

#include "binpeek/elf.hpp"

namespace binpeek::elf {

namespace {

template <typename T, std::size_t N>
const char* lookup(const std::pair<T, const char*> (&table)[N], T value) noexcept {
    for (const auto& [v, name] : table) {
        if (v == value) return name;
    }
    return nullptr;
}

const std::pair<std::uint16_t, const char*> kFileTypes[] = {
    {et_none, "NONE"}, {et_rel, "REL"}, {et_exec, "EXEC"}, {et_dyn, "DYN"}, {et_core, "CORE"},
};

const std::pair<std::uint16_t, const char*> kMachines[] = {
    {em_none, "none"},       {em_sparc, "SPARC"},      {em_386, "i386"},           {em_68k, "Motorola 68000"},
    {em_mips, "MIPS"},       {em_ppc, "PowerPC"},      {em_ppc64, "PowerPC64"},    {em_s390, "IBM S/390"},
    {em_arm, "ARM"},         {em_sh, "SuperH"},        {em_sparcv9, "SPARC V9"},   {em_ia_64, "IA-64"},
    {em_x86_64, "x86-64"},   {em_aarch64, "AArch64"},  {em_riscv, "RISC-V"},       {em_bpf, "BPF"},
    {em_loongarch, "LoongArch"},
};

const std::pair<std::uint8_t, const char*> kOsAbis[] = {
    {0, "SYSV"},    {1, "HP-UX"},   {2, "NetBSD"}, {3, "GNU"},      {6, "Solaris"},
    {7, "AIX"},     {8, "IRIX"},    {9, "FreeBSD"}, {12, "OpenBSD"}, {64, "ARM EABI"},
    {97, "ARM"},    {255, "standalone"},
};

const std::pair<std::uint32_t, const char*> kSectionTypes[] = {
    {sht_null, "NULL"},
    {sht_progbits, "PROGBITS"},
    {sht_symtab, "SYMTAB"},
    {sht_strtab, "STRTAB"},
    {sht_rela, "RELA"},
    {sht_hash, "HASH"},
    {sht_dynamic, "DYNAMIC"},
    {sht_note, "NOTE"},
    {sht_nobits, "NOBITS"},
    {sht_rel, "REL"},
    {sht_shlib, "SHLIB"},
    {sht_dynsym, "DYNSYM"},
    {sht_init_array, "INIT_ARRAY"},
    {sht_fini_array, "FINI_ARRAY"},
    {sht_preinit_array, "PREINIT_ARRAY"},
    {sht_group, "GROUP"},
    {sht_symtab_shndx, "SYMTAB_SHNDX"},
    {sht_relr, "RELR"},
    {sht_gnu_attributes, "GNU_ATTRIBUTES"},
    {sht_gnu_hash, "GNU_HASH"},
    {sht_gnu_verdef, "GNU_VERDEF"},
    {sht_gnu_verneed, "GNU_VERNEED"},
    {sht_gnu_versym, "GNU_VERSYM"},
};

const std::pair<std::uint32_t, const char*> kSegmentTypes[] = {
    {pt_null, "NULL"},
    {pt_load, "LOAD"},
    {pt_dynamic, "DYNAMIC"},
    {pt_interp, "INTERP"},
    {pt_note, "NOTE"},
    {pt_shlib, "SHLIB"},
    {pt_phdr, "PHDR"},
    {pt_tls, "TLS"},
    {pt_gnu_eh_frame, "GNU_EH_FRAME"},
    {pt_gnu_stack, "GNU_STACK"},
    {pt_gnu_relro, "GNU_RELRO"},
    {pt_gnu_property, "GNU_PROPERTY"},
    {pt_gnu_sframe, "GNU_SFRAME"},
};

const std::pair<std::uint8_t, const char*> kSymbolTypes[] = {
    {stt_notype, "NOTYPE"}, {stt_object, "OBJECT"}, {stt_func, "FUNC"}, {stt_section, "SECTION"},
    {stt_file, "FILE"},     {stt_common, "COMMON"}, {stt_tls, "TLS"},   {stt_gnu_ifunc, "GNU_IFUNC"},
};

const std::pair<std::uint8_t, const char*> kBindings[] = {
    {stb_local, "LOCAL"}, {stb_global, "GLOBAL"}, {stb_weak, "WEAK"}, {stb_gnu_unique, "GNU_UNIQUE"},
};

const std::pair<std::uint8_t, const char*> kVisibilities[] = {
    {stv_default, "DEFAULT"}, {stv_internal, "INTERNAL"}, {stv_hidden, "HIDDEN"}, {stv_protected, "PROTECTED"},
};

const std::pair<std::int64_t, const char*> kDynamicTags[] = {
    {dt_null, "NULL"},
    {dt_needed, "NEEDED"},
    {dt_pltrelsz, "PLTRELSZ"},
    {dt_pltgot, "PLTGOT"},
    {dt_hash, "HASH"},
    {dt_strtab, "STRTAB"},
    {dt_symtab, "SYMTAB"},
    {dt_rela, "RELA"},
    {dt_relasz, "RELASZ"},
    {dt_relaent, "RELAENT"},
    {dt_strsz, "STRSZ"},
    {dt_syment, "SYMENT"},
    {dt_init, "INIT"},
    {dt_fini, "FINI"},
    {dt_soname, "SONAME"},
    {dt_rpath, "RPATH"},
    {dt_symbolic, "SYMBOLIC"},
    {dt_rel, "REL"},
    {dt_relsz, "RELSZ"},
    {dt_relent, "RELENT"},
    {dt_pltrel, "PLTREL"},
    {dt_debug, "DEBUG"},
    {dt_textrel, "TEXTREL"},
    {dt_jmprel, "JMPREL"},
    {dt_bind_now, "BIND_NOW"},
    {dt_init_array, "INIT_ARRAY"},
    {dt_fini_array, "FINI_ARRAY"},
    {dt_init_arraysz, "INIT_ARRAYSZ"},
    {dt_fini_arraysz, "FINI_ARRAYSZ"},
    {dt_runpath, "RUNPATH"},
    {dt_flags, "FLAGS"},
    {dt_preinit_array, "PREINIT_ARRAY"},
    {dt_preinit_arraysz, "PREINIT_ARRAYSZ"},
    {dt_relrsz, "RELRSZ"},
    {dt_relr, "RELR"},
    {dt_relrent, "RELRENT"},
    {dt_gnu_hash, "GNU_HASH"},
    {dt_versym, "VERSYM"},
    {dt_relacount, "RELACOUNT"},
    {dt_relcount, "RELCOUNT"},
    {dt_flags_1, "FLAGS_1"},
    {dt_verdef, "VERDEF"},
    {dt_verdefnum, "VERDEFNUM"},
    {dt_verneed, "VERNEED"},
    {dt_verneednum, "VERNEEDNUM"},
};

// Values in the OS- and processor-specific ranges, relative to the range base.
std::string ranged(std::uint32_t value) {
    if (value >= 0x60000000 && value <= 0x6fffffff) return std::format("LOOS+{:#x}", value - 0x60000000);
    if (value >= 0x70000000 && value <= 0x7fffffff) return std::format("LOPROC+{:#x}", value - 0x70000000);
    if (value >= 0x80000000) return std::format("LOUSER+{:#x}", value - 0x80000000);
    return std::format("{:#x}", value);
}

}  // namespace

std::string file_type_name(std::uint16_t type) {
    if (const char* name = lookup(kFileTypes, type)) return name;
    return std::format("{:#x}", type);
}

std::string machine_name(std::uint16_t machine) {
    if (const char* name = lookup(kMachines, machine)) return name;
    return std::format("machine {}", machine);
}

std::string os_abi_name(std::uint8_t os_abi) {
    if (const char* name = lookup(kOsAbis, os_abi)) return name;
    return std::format("OS/ABI {}", os_abi);
}

std::string section_type_name(std::uint32_t type, std::uint16_t machine) {
    if (const char* name = lookup(kSectionTypes, type)) return name;
    if (machine == em_x86_64 && type == sht_x86_64_unwind) return "X86_64_UNWIND";
    if (machine == em_arm && type == sht_arm_exidx) return "ARM_EXIDX";
    if (machine == em_arm && type == sht_arm_attributes) return "ARM_ATTRIBUTES";
    if (machine == em_riscv && type == sht_riscv_attributes) return "RISCV_ATTRIBUTES";
    return ranged(type);
}

std::string segment_type_name(std::uint32_t type) {
    if (const char* name = lookup(kSegmentTypes, type)) return name;
    return ranged(type);
}

std::string symbol_type_name(std::uint8_t type) {
    if (const char* name = lookup(kSymbolTypes, type)) return name;
    return std::format("{}", type);
}

std::string symbol_bind_name(std::uint8_t bind) {
    if (const char* name = lookup(kBindings, bind)) return name;
    return std::format("{}", bind);
}

std::string visibility_name(std::uint8_t visibility) {
    if (const char* name = lookup(kVisibilities, visibility)) return name;
    return std::format("{}", visibility);
}

std::string dynamic_tag_name(std::int64_t tag) {
    if (const char* name = lookup(kDynamicTags, tag)) return name;
    return std::format("{:#x}", static_cast<std::uint64_t>(tag));
}

std::string section_flags_string(std::uint64_t flags) {
    static constexpr std::pair<std::uint64_t, char> kLetters[] = {
        {shf_write, 'W'},      {shf_alloc, 'A'},         {shf_execinstr, 'X'},        {shf_merge, 'M'},
        {shf_strings, 'S'},    {shf_info_link, 'I'},     {shf_link_order, 'L'},       {shf_os_nonconforming, 'O'},
        {shf_group, 'G'},      {shf_tls, 'T'},           {shf_compressed, 'C'},       {shf_exclude, 'E'},
    };
    std::string out;
    std::uint64_t known = 0;
    for (const auto& [bit, letter] : kLetters) {
        known |= bit;
        if ((flags & bit) != 0) out += letter;
    }
    if ((flags & ~known) != 0) out += 'x';
    return out;
}

std::string segment_flags_string(std::uint32_t flags) {
    std::string out;
    out += (flags & pf_r) != 0 ? 'R' : '-';
    out += (flags & pf_w) != 0 ? 'W' : '-';
    out += (flags & pf_x) != 0 ? 'X' : '-';
    return out;
}

std::string section_index_name(std::uint32_t index) {
    switch (index) {
        case shn_undef: return "UND";
        case shn_abs: return "ABS";
        case shn_common: return "COM";
        case shn_xindex: return "XIDX";
        default: break;
    }
    if (index >= shn_loreserve && index <= 0xffff) return std::format("{:#x}", index);
    return std::format("{}", index);
}

}  // namespace binpeek::elf
