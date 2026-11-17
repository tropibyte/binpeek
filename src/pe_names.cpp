// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.

#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>

#include "binpeek/pe.hpp"

namespace binpeek::pe {

namespace {

template <typename T, std::size_t N>
const char* lookup(const std::pair<T, const char*> (&table)[N], T value) noexcept {
    for (const auto& [v, name] : table) {
        if (v == value) return name;
    }
    return nullptr;
}

// Names of the set bits, space-separated, then any unnamed bits in hex.
template <typename T, std::size_t N>
std::string flag_names(const std::pair<T, const char*> (&table)[N], T flags) {
    std::string out;
    T known = 0;
    for (const auto& [bit, name] : table) {
        known = static_cast<T>(known | bit);
        if ((flags & bit) == 0) continue;
        if (!out.empty()) out += ' ';
        out += name;
    }
    const auto unknown = static_cast<T>(flags & static_cast<T>(~known));
    if (unknown != 0) {
        if (!out.empty()) out += ' ';
        out += std::format("{:#x}", unknown);
    }
    return out;
}

const std::pair<std::uint16_t, const char*> kMachines[] = {
    {machine_unknown, "unknown"},   {machine_i386, "i386"},          {machine_r4000, "MIPS R4000"},
    {machine_arm, "ARM"},           {machine_thumb, "Thumb"},        {machine_armnt, "ARMNT"},
    {machine_powerpc, "PowerPC"},   {machine_ia64, "IA64"},          {machine_ebc, "EBC"},
    {machine_riscv32, "RISC-V 32"}, {machine_riscv64, "RISC-V 64"},  {machine_loongarch64, "LoongArch64"},
    {machine_amd64, "AMD64"},       {machine_arm64ec, "ARM64EC"},    {machine_arm64x, "ARM64X"},
    {machine_arm64, "ARM64"},
};

const std::pair<std::uint16_t, const char*> kSubsystems[] = {
    {subsystem_unknown, "unknown"},
    {subsystem_native, "native"},
    {subsystem_windows_gui, "Windows GUI"},
    {subsystem_windows_cui, "Windows CUI"},
    {subsystem_os2_cui, "OS/2 CUI"},
    {subsystem_posix_cui, "POSIX CUI"},
    {subsystem_native_windows, "native Win9x driver"},
    {subsystem_windows_ce_gui, "Windows CE GUI"},
    {subsystem_efi_application, "EFI application"},
    {subsystem_efi_boot_service_driver, "EFI boot service driver"},
    {subsystem_efi_runtime_driver, "EFI runtime driver"},
    {subsystem_efi_rom, "EFI ROM"},
    {subsystem_xbox, "Xbox"},
    {subsystem_windows_boot_application, "Windows boot application"},
};

const char* const kDirectories[] = {
    "Export",      "Import",       "Resource",     "Exception", "Security",     "Base relocation",
    "Debug",       "Architecture", "Global pointer", "TLS",     "Load config",  "Bound import",
    "IAT",         "Delay import", "CLR runtime",  "Reserved",
};

const std::pair<std::uint8_t, const char*> kStorageClasses[] = {
    {class_end_of_function, "END_OF_FUNCTION"},
    {class_null, "NULL"},
    {class_automatic, "AUTOMATIC"},
    {class_external, "EXTERNAL"},
    {class_static, "STATIC"},
    {class_register, "REGISTER"},
    {class_external_def, "EXTERNAL_DEF"},
    {class_label, "LABEL"},
    {class_undefined_label, "UNDEFINED_LABEL"},
    {8, "MEMBER_OF_STRUCT"},
    {class_argument, "ARGUMENT"},
    {10, "STRUCT_TAG"},
    {11, "MEMBER_OF_UNION"},
    {12, "UNION_TAG"},
    {13, "TYPE_DEFINITION"},
    {14, "UNDEFINED_STATIC"},
    {15, "ENUM_TAG"},
    {16, "MEMBER_OF_ENUM"},
    {17, "REGISTER_PARAM"},
    {18, "BIT_FIELD"},
    {class_block, "BLOCK"},
    {class_function, "FUNCTION"},
    {class_end_of_struct, "END_OF_STRUCT"},
    {class_file, "FILE"},
    {class_section, "SECTION"},
    {class_weak_external, "WEAK_EXTERNAL"},
    {class_clr_token, "CLR_TOKEN"},
};

const std::pair<std::uint16_t, const char*> kFileFlags[] = {
    {file_relocs_stripped, "RELOCS_STRIPPED"},
    {file_executable_image, "EXECUTABLE_IMAGE"},
    {file_line_nums_stripped, "LINE_NUMS_STRIPPED"},
    {file_local_syms_stripped, "LOCAL_SYMS_STRIPPED"},
    {0x0010, "AGGRESSIVE_WS_TRIM"},
    {file_large_address_aware, "LARGE_ADDRESS_AWARE"},
    {0x0080, "BYTES_REVERSED_LO"},
    {file_32bit_machine, "32BIT_MACHINE"},
    {file_debug_stripped, "DEBUG_STRIPPED"},
    {file_removable_run_from_swap, "REMOVABLE_RUN_FROM_SWAP"},
    {file_net_run_from_swap, "NET_RUN_FROM_SWAP"},
    {file_system, "SYSTEM"},
    {file_dll, "DLL"},
    {file_up_system_only, "UP_SYSTEM_ONLY"},
    {0x8000, "BYTES_REVERSED_HI"},
};

const std::pair<std::uint16_t, const char*> kDllFlags[] = {
    {dllchar_high_entropy_va, "HIGH_ENTROPY_VA"},
    {dllchar_dynamic_base, "DYNAMIC_BASE"},
    {dllchar_force_integrity, "FORCE_INTEGRITY"},
    {dllchar_nx_compat, "NX_COMPAT"},
    {dllchar_no_isolation, "NO_ISOLATION"},
    {dllchar_no_seh, "NO_SEH"},
    {dllchar_no_bind, "NO_BIND"},
    {dllchar_appcontainer, "APPCONTAINER"},
    {dllchar_wdm_driver, "WDM_DRIVER"},
    {dllchar_guard_cf, "GUARD_CF"},
    {dllchar_terminal_server_aware, "TERMINAL_SERVER_AWARE"},
};

// Section flags other than alignment and the R/W/X permissions.
const std::pair<std::uint32_t, const char*> kSectionFlags[] = {
    {0x00000008, "TYPE_NO_PAD"},
    {scn_cnt_code, "CODE"},
    {scn_cnt_initialized_data, "INITIALIZED_DATA"},
    {scn_cnt_uninitialized_data, "UNINITIALIZED_DATA"},
    {scn_lnk_info, "LNK_INFO"},
    {scn_lnk_remove, "LNK_REMOVE"},
    {scn_lnk_comdat, "LNK_COMDAT"},
    {scn_gprel, "GPREL"},
    {scn_lnk_nreloc_ovfl, "LNK_NRELOC_OVFL"},
    {scn_mem_discardable, "DISCARDABLE"},
    {scn_mem_not_cached, "NOT_CACHED"},
    {scn_mem_not_paged, "NOT_PAGED"},
    {scn_mem_shared, "SHARED"},
};

}  // namespace

std::string machine_name(std::uint16_t machine) {
    if (const char* name = lookup(kMachines, machine)) return name;
    return std::format("machine {:#x}", machine);
}

std::string subsystem_name(std::uint16_t subsystem) {
    if (const char* name = lookup(kSubsystems, subsystem)) return name;
    return std::format("subsystem {}", subsystem);
}

std::string directory_name(std::size_t index) {
    if (index < std::size(kDirectories)) return kDirectories[index];
    return std::format("#{}", index);
}

std::string storage_class_name(std::uint8_t storage_class) {
    if (const char* name = lookup(kStorageClasses, storage_class)) return name;
    return std::format("{}", storage_class);
}

std::string symbol_section_name(std::int16_t section_number) {
    switch (section_number) {
        case sym_undefined: return "UNDEF";
        case sym_absolute: return "ABS";
        case sym_debug: return "DEBUG";
        default: return std::format("{}", section_number);
    }
}

std::string file_characteristics_string(std::uint16_t flags) { return flag_names(kFileFlags, flags); }

std::string dll_characteristics_string(std::uint16_t flags) { return flag_names(kDllFlags, flags); }

std::string section_characteristics_string(std::uint32_t flags) {
    constexpr std::uint32_t permissions = scn_mem_read | scn_mem_write | scn_mem_execute;
    std::string out = flag_names(kSectionFlags, static_cast<std::uint32_t>(flags & ~(permissions | scn_align_mask)));
    // The alignment field holds n for 2^(n-1) bytes; 15 is not defined.
    const std::uint32_t align = (flags & scn_align_mask) >> 20;
    if (align != 0) {
        if (!out.empty()) out += ' ';
        out += align <= 14 ? std::format("ALIGN_{}BYTES", 1u << (align - 1)) : std::format("ALIGN_{:#x}", align);
    }
    return out;
}

std::string section_permissions(std::uint32_t flags) {
    std::string out;
    out += (flags & scn_mem_read) != 0 ? 'R' : '-';
    out += (flags & scn_mem_write) != 0 ? 'W' : '-';
    out += (flags & scn_mem_execute) != 0 ? 'X' : '-';
    return out;
}

}  // namespace binpeek::pe
