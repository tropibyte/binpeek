// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Tropibyte, Inc.
//
// PE/COFF: Windows executables and DLLs (PE32 and PE32+) and COFF object
// files. Constant names are the PE/COFF specification's, in lower case and
// without the IMAGE_ prefix (IMAGE_FILE_MACHINE_AMD64 is machine_amd64), so
// they cannot collide with <windows.h> macros.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "binpeek/options.hpp"

namespace binpeek::pe {

// Machine types (a selection)
inline constexpr std::uint16_t machine_unknown = 0;
inline constexpr std::uint16_t machine_i386 = 0x14c;
inline constexpr std::uint16_t machine_r4000 = 0x166;
inline constexpr std::uint16_t machine_arm = 0x1c0;
inline constexpr std::uint16_t machine_thumb = 0x1c2;
inline constexpr std::uint16_t machine_armnt = 0x1c4;
inline constexpr std::uint16_t machine_powerpc = 0x1f0;
inline constexpr std::uint16_t machine_ia64 = 0x200;
inline constexpr std::uint16_t machine_ebc = 0xebc;
inline constexpr std::uint16_t machine_riscv32 = 0x5032;
inline constexpr std::uint16_t machine_riscv64 = 0x5064;
inline constexpr std::uint16_t machine_loongarch64 = 0x6264;
inline constexpr std::uint16_t machine_amd64 = 0x8664;
inline constexpr std::uint16_t machine_arm64ec = 0xa641;
inline constexpr std::uint16_t machine_arm64x = 0xa64e;
inline constexpr std::uint16_t machine_arm64 = 0xaa64;

// COFF header characteristics
inline constexpr std::uint16_t file_relocs_stripped = 0x0001;
inline constexpr std::uint16_t file_executable_image = 0x0002;
inline constexpr std::uint16_t file_line_nums_stripped = 0x0004;
inline constexpr std::uint16_t file_local_syms_stripped = 0x0008;
inline constexpr std::uint16_t file_large_address_aware = 0x0020;
inline constexpr std::uint16_t file_32bit_machine = 0x0100;
inline constexpr std::uint16_t file_debug_stripped = 0x0200;
inline constexpr std::uint16_t file_removable_run_from_swap = 0x0400;
inline constexpr std::uint16_t file_net_run_from_swap = 0x0800;
inline constexpr std::uint16_t file_system = 0x1000;
inline constexpr std::uint16_t file_dll = 0x2000;
inline constexpr std::uint16_t file_up_system_only = 0x4000;

// Optional header magic
inline constexpr std::uint16_t magic_pe32 = 0x10b;
inline constexpr std::uint16_t magic_pe32_plus = 0x20b;

// Subsystems
inline constexpr std::uint16_t subsystem_unknown = 0;
inline constexpr std::uint16_t subsystem_native = 1;
inline constexpr std::uint16_t subsystem_windows_gui = 2;
inline constexpr std::uint16_t subsystem_windows_cui = 3;
inline constexpr std::uint16_t subsystem_os2_cui = 5;
inline constexpr std::uint16_t subsystem_posix_cui = 7;
inline constexpr std::uint16_t subsystem_native_windows = 8;
inline constexpr std::uint16_t subsystem_windows_ce_gui = 9;
inline constexpr std::uint16_t subsystem_efi_application = 10;
inline constexpr std::uint16_t subsystem_efi_boot_service_driver = 11;
inline constexpr std::uint16_t subsystem_efi_runtime_driver = 12;
inline constexpr std::uint16_t subsystem_efi_rom = 13;
inline constexpr std::uint16_t subsystem_xbox = 14;
inline constexpr std::uint16_t subsystem_windows_boot_application = 16;

// DLL characteristics
inline constexpr std::uint16_t dllchar_high_entropy_va = 0x0020;
inline constexpr std::uint16_t dllchar_dynamic_base = 0x0040;
inline constexpr std::uint16_t dllchar_force_integrity = 0x0080;
inline constexpr std::uint16_t dllchar_nx_compat = 0x0100;
inline constexpr std::uint16_t dllchar_no_isolation = 0x0200;
inline constexpr std::uint16_t dllchar_no_seh = 0x0400;
inline constexpr std::uint16_t dllchar_no_bind = 0x0800;
inline constexpr std::uint16_t dllchar_appcontainer = 0x1000;
inline constexpr std::uint16_t dllchar_wdm_driver = 0x2000;
inline constexpr std::uint16_t dllchar_guard_cf = 0x4000;
inline constexpr std::uint16_t dllchar_terminal_server_aware = 0x8000;

// Data directory indexes
inline constexpr std::size_t dir_export = 0;
inline constexpr std::size_t dir_import = 1;
inline constexpr std::size_t dir_resource = 2;
inline constexpr std::size_t dir_exception = 3;
inline constexpr std::size_t dir_security = 4;
inline constexpr std::size_t dir_basereloc = 5;
inline constexpr std::size_t dir_debug = 6;
inline constexpr std::size_t dir_architecture = 7;
inline constexpr std::size_t dir_globalptr = 8;
inline constexpr std::size_t dir_tls = 9;
inline constexpr std::size_t dir_load_config = 10;
inline constexpr std::size_t dir_bound_import = 11;
inline constexpr std::size_t dir_iat = 12;
inline constexpr std::size_t dir_delay_import = 13;
inline constexpr std::size_t dir_clr_runtime = 14;

// Section characteristics
inline constexpr std::uint32_t scn_cnt_code = 0x00000020;
inline constexpr std::uint32_t scn_cnt_initialized_data = 0x00000040;
inline constexpr std::uint32_t scn_cnt_uninitialized_data = 0x00000080;
inline constexpr std::uint32_t scn_lnk_info = 0x00000200;
inline constexpr std::uint32_t scn_lnk_remove = 0x00000800;
inline constexpr std::uint32_t scn_lnk_comdat = 0x00001000;
inline constexpr std::uint32_t scn_gprel = 0x00008000;
inline constexpr std::uint32_t scn_align_mask = 0x00f00000;
inline constexpr std::uint32_t scn_lnk_nreloc_ovfl = 0x01000000;
inline constexpr std::uint32_t scn_mem_discardable = 0x02000000;
inline constexpr std::uint32_t scn_mem_not_cached = 0x04000000;
inline constexpr std::uint32_t scn_mem_not_paged = 0x08000000;
inline constexpr std::uint32_t scn_mem_shared = 0x10000000;
inline constexpr std::uint32_t scn_mem_execute = 0x20000000;
inline constexpr std::uint32_t scn_mem_read = 0x40000000;
inline constexpr std::uint32_t scn_mem_write = 0x80000000;

// Special symbol section numbers
inline constexpr std::int16_t sym_undefined = 0;
inline constexpr std::int16_t sym_absolute = -1;
inline constexpr std::int16_t sym_debug = -2;

// Symbol storage classes (a selection)
inline constexpr std::uint8_t class_end_of_function = 0xff;
inline constexpr std::uint8_t class_null = 0;
inline constexpr std::uint8_t class_automatic = 1;
inline constexpr std::uint8_t class_external = 2;
inline constexpr std::uint8_t class_static = 3;
inline constexpr std::uint8_t class_register = 4;
inline constexpr std::uint8_t class_external_def = 5;
inline constexpr std::uint8_t class_label = 6;
inline constexpr std::uint8_t class_undefined_label = 7;
inline constexpr std::uint8_t class_argument = 9;
inline constexpr std::uint8_t class_block = 100;
inline constexpr std::uint8_t class_function = 101;
inline constexpr std::uint8_t class_end_of_struct = 102;
inline constexpr std::uint8_t class_file = 103;
inline constexpr std::uint8_t class_section = 104;
inline constexpr std::uint8_t class_weak_external = 105;
inline constexpr std::uint8_t class_clr_token = 107;

// Symbol type: the derived type in bits 4-5
inline constexpr std::uint16_t sym_dtype_function = 0x20;

/// Size of the fields binpeek reads from a COFF symbol record.
inline constexpr std::size_t symbol_record_size = 18;

struct DosHeader {
    std::uint16_t magic = 0;  ///< "MZ"
    std::uint16_t last_page_bytes = 0;
    std::uint16_t page_count = 0;
    std::uint16_t relocation_count = 0;
    std::uint16_t header_paragraphs = 0;
    std::uint16_t min_extra_paragraphs = 0;
    std::uint16_t max_extra_paragraphs = 0;
    std::uint16_t initial_ss = 0;
    std::uint16_t initial_sp = 0;
    std::uint16_t checksum = 0;
    std::uint16_t initial_ip = 0;
    std::uint16_t initial_cs = 0;
    std::uint16_t relocation_table_offset = 0;
    std::uint16_t overlay_number = 0;
    std::uint16_t oem_id = 0;
    std::uint16_t oem_info = 0;
    std::uint32_t pe_offset = 0;  ///< e_lfanew
};

/// The COFF file header.
struct FileHeader {
    std::uint16_t machine = 0;
    std::uint16_t section_count = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t symbol_table_offset = 0;
    std::uint32_t symbol_count = 0;  ///< records, auxiliary records included
    std::uint16_t optional_header_size = 0;
    std::uint16_t characteristics = 0;
};

struct DataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

struct OptionalHeader {
    std::uint16_t magic = 0;  ///< magic_pe32 or magic_pe32_plus
    std::uint8_t linker_major = 0;
    std::uint8_t linker_minor = 0;
    std::uint32_t size_of_code = 0;
    std::uint32_t size_of_initialized_data = 0;
    std::uint32_t size_of_uninitialized_data = 0;
    std::uint32_t entry_point = 0;
    std::uint32_t base_of_code = 0;
    std::uint32_t base_of_data = 0;  ///< PE32 only
    std::uint64_t image_base = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint16_t os_major = 0;
    std::uint16_t os_minor = 0;
    std::uint16_t image_major = 0;
    std::uint16_t image_minor = 0;
    std::uint16_t subsystem_major = 0;
    std::uint16_t subsystem_minor = 0;
    std::uint32_t win32_version = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t checksum = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dll_characteristics = 0;
    std::uint64_t stack_reserve = 0;
    std::uint64_t stack_commit = 0;
    std::uint64_t heap_reserve = 0;
    std::uint64_t heap_commit = 0;
    std::uint32_t loader_flags = 0;
    std::uint32_t rva_count = 0;  ///< NumberOfRvaAndSizes
    std::vector<DataDirectory> directories;

    bool is_pe32_plus() const noexcept { return magic == magic_pe32_plus; }
    /// The directory at index, or an empty one when the header has fewer.
    DataDirectory directory(std::size_t index) const noexcept;
};

struct Section {
    /// The section name; "/123" long names are resolved through the COFF
    /// string table when the file has one.
    std::string name;
    std::string short_name;  ///< the 8-byte name field as stored
    std::uint32_t virtual_size = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t raw_size = 0;    ///< SizeOfRawData
    std::uint32_t raw_offset = 0;  ///< PointerToRawData
    std::uint32_t relocations_offset = 0;
    std::uint32_t line_numbers_offset = 0;
    std::uint16_t relocation_count = 0;
    std::uint16_t line_number_count = 0;
    std::uint32_t characteristics = 0;

    /// True when the section has bytes in the file: PointerToRawData and
    /// SizeOfRawData are both nonzero. (Object files give .bss a size and no
    /// pointer.)
    bool has_file_data() const noexcept { return raw_offset != 0 && raw_size != 0; }
};

struct ImportedFunction {
    std::string name;                      ///< empty for imports by ordinal
    std::uint16_t hint = 0;                ///< for imports by name
    std::optional<std::uint16_t> ordinal;  ///< for imports by ordinal
    std::uint32_t iat_rva = 0;             ///< the address table slot the loader fills
};

struct ImportedDll {
    std::string name;
    std::uint32_t lookup_table_rva = 0;  ///< OriginalFirstThunk
    std::uint32_t timestamp = 0;
    std::uint32_t forwarder_chain = 0;
    std::uint32_t name_rva = 0;
    std::uint32_t address_table_rva = 0;  ///< FirstThunk
    std::vector<ImportedFunction> functions;
};

struct ExportedFunction {
    std::uint32_t ordinal = 0;  ///< with the ordinal base added
    std::uint32_t rva = 0;      ///< for forwarders, the RVA of the forwarder string
    std::string name;           ///< empty when exported by ordinal only
    std::string forwarder;      ///< "DLL.Function" or "DLL.#12"; empty when not forwarded
};

struct ExportDirectory {
    std::string dll_name;
    std::uint32_t characteristics = 0;
    std::uint32_t timestamp = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint32_t ordinal_base = 0;
    std::uint32_t function_count = 0;
    std::uint32_t name_count = 0;
    std::uint32_t functions_rva = 0;
    std::uint32_t names_rva = 0;
    std::uint32_t name_ordinals_rva = 0;
    /// One entry per name, plus one per unnamed function, in ordinal order
    /// (names in table order within an ordinal). Unused slots (RVA 0 and no
    /// name) are left out.
    std::vector<ExportedFunction> functions;
};

/// A COFF symbol record. Auxiliary records are not decoded; aux_count says
/// how many follow, and index is the record's position in the table.
struct Symbol {
    std::uint32_t index = 0;
    std::string name;
    std::uint32_t value = 0;
    std::int16_t section_number = 0;
    std::uint16_t type = 0;
    std::uint8_t storage_class = 0;
    std::uint8_t aux_count = 0;
};

struct PeFile {
    std::optional<DosHeader> dos;  ///< set for images, not for object files
    FileHeader header;
    std::optional<OptionalHeader> optional_header;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::vector<ImportedDll> imports;
    std::optional<ExportDirectory> exports;

    bool is_image() const noexcept { return dos.has_value(); }
    bool is_dll() const noexcept { return (header.characteristics & file_dll) != 0; }
    bool is_pe32_plus() const noexcept { return optional_header && optional_header->is_pe32_plus(); }

    /// The first section with this name, or nullptr.
    const Section* find_section(std::string_view name) const noexcept;
};

/// True when data has an MZ header whose e_lfanew points at "PE\0\0".
bool is_pe(std::span<const std::byte> data) noexcept;

/// True when data starts with a COFF file header for x86, x64 or ARM64.
bool is_coff_object(std::span<const std::byte> data) noexcept;

/// Parses a PE image (MZ header, "PE\0\0", COFF header, optional header).
/// Throws FormatError for malformed input.
PeFile parse_pe(std::span<const std::byte> data, const ParseOptions& options = {});

/// Parses a COFF object file. Throws FormatError for malformed input.
PeFile parse_coff_object(std::span<const std::byte> data, const ParseOptions& options = {});

/// Maps an RVA to a file offset: through the first section, in table order,
/// whose virtual range [VirtualAddress, VirtualAddress + VirtualSize) contains
/// it (SizeOfRawData when VirtualSize is 0) and whose raw data covers it;
/// otherwise, for an RVA below SizeOfHeaders, the RVA itself. nullopt when
/// neither applies, for example in the zero-filled tail of a section.
std::optional<std::uint64_t> rva_to_offset(const PeFile& file, std::uint32_t rva) noexcept;

// Names for display. Unknown values come back as hexadecimal text.
std::string machine_name(std::uint16_t machine);
std::string subsystem_name(std::uint16_t subsystem);
std::string directory_name(std::size_t index);
std::string storage_class_name(std::uint8_t storage_class);
/// "UNDEF", "ABS", "DEBUG" or the 1-based section number.
std::string symbol_section_name(std::int16_t section_number);
/// Space-separated flag names: "EXECUTABLE_IMAGE LARGE_ADDRESS_AWARE".
std::string file_characteristics_string(std::uint16_t flags);
std::string dll_characteristics_string(std::uint16_t flags);
/// Content and alignment flags ("CODE ALIGN_16BYTES"), without the R/W/X permissions.
std::string section_characteristics_string(std::uint32_t flags);
/// "R-X" style permissions.
std::string section_permissions(std::uint32_t flags);

}  // namespace binpeek::pe
