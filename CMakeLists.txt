cmake_minimum_required(VERSION 3.20)

project(binpeek
    VERSION 0.1.0
    DESCRIPTION "Inspect ELF and PE/COFF executables, libraries and object files"
    LANGUAGES CXX)

# PROJECT_IS_TOP_LEVEL needs CMake 3.21.
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(binpeek_top_level ON)
else()
    set(binpeek_top_level OFF)
endif()

option(BINPEEK_BUILD_TESTS "Build the unit tests" ${binpeek_top_level})
option(BINPEEK_BUILD_CLI "Build the binpeek command-line tool" ${binpeek_top_level})
option(BINPEEK_BUILD_EXAMPLES "Build the example programs" ${binpeek_top_level})
option(BINPEEK_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(BINPEEK_SANITIZE "Build with AddressSanitizer and UBSan (GCC/Clang)" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The mingw preset names its emulator ("wine64"); resolve it to a full path
# so that ctest finds it without the preset's PATH. Debian and Ubuntu keep
# wine64 in /usr/lib/wine.
if(CMAKE_CROSSCOMPILING AND CMAKE_CROSSCOMPILING_EMULATOR AND NOT IS_ABSOLUTE "${CMAKE_CROSSCOMPILING_EMULATOR}")
    find_program(BINPEEK_EMULATOR_PATH NAMES ${CMAKE_CROSSCOMPILING_EMULATOR} PATHS /usr/lib/wine NO_CMAKE_FIND_ROOT_PATH)
    if(BINPEEK_EMULATOR_PATH)
        set(CMAKE_CROSSCOMPILING_EMULATOR ${BINPEEK_EMULATOR_PATH})
    endif()
endif()

add_library(binpeek
    src/bytes.cpp
    src/coff.cpp
    src/elf.cpp
    src/elf_names.cpp
    src/error.cpp
    src/file.cpp
    src/json.cpp
    src/pe.cpp
    src/pe_names.cpp
    src/report.cpp
    src/report_elf.cpp
    src/report_pe.cpp
    src/text.cpp
)
add_library(binpeek::binpeek ALIAS binpeek)

target_include_directories(binpeek PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(binpeek PUBLIC cxx_std_20)
set_target_properties(binpeek PROPERTIES CXX_EXTENSIONS OFF)

add_library(binpeek_build_flags INTERFACE)
if(MSVC)
    target_compile_options(binpeek_build_flags INTERFACE
        /W4 /permissive- /utf-8 /EHsc /Zc:__cplusplus /Zc:preprocessor)
    if(BINPEEK_WARNINGS_AS_ERRORS)
        target_compile_options(binpeek_build_flags INTERFACE /WX)
    endif()
else()
    target_compile_options(binpeek_build_flags INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wnon-virtual-dtor -Wold-style-cast)
    if(BINPEEK_WARNINGS_AS_ERRORS)
        target_compile_options(binpeek_build_flags INTERFACE -Werror)
    endif()
    if(BINPEEK_SANITIZE)
        target_compile_options(binpeek_build_flags INTERFACE
            -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
        target_link_options(binpeek_build_flags INTERFACE -fsanitize=address,undefined)
    endif()
endif()
target_link_libraries(binpeek PRIVATE $<BUILD_INTERFACE:binpeek_build_flags>)

if(BINPEEK_BUILD_CLI)
    add_executable(binpeek_cli tools/binpeek_cli.cpp)
    set_target_properties(binpeek_cli PROPERTIES OUTPUT_NAME binpeek CXX_EXTENSIONS OFF)
    target_link_libraries(binpeek_cli PRIVATE binpeek binpeek_build_flags)
    if(WIN32)
        # CommandLineToArgvW, for file names outside the ANSI code page.
        target_link_libraries(binpeek_cli PRIVATE shell32)
    endif()
endif()

if(BINPEEK_BUILD_EXAMPLES)
    add_executable(binpeek_list_deps examples/list_deps.cpp)
    set_target_properties(binpeek_list_deps PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(binpeek_list_deps PRIVATE binpeek binpeek_build_flags)
endif()

if(BINPEEK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

include(GNUInstallDirs)
install(TARGETS binpeek EXPORT binpeekTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
if(BINPEEK_BUILD_CLI)
    install(TARGETS binpeek_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(DIRECTORY include/binpeek DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT binpeekTargets NAMESPACE binpeek:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/binpeek)
