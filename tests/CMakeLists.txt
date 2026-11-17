add_executable(binpeek_tests
    test_main.cpp
    image_builder.cpp
    test_bytes.cpp
    test_coff.cpp
    test_corrupt.cpp
    test_detect.cpp
    test_elf.cpp
    test_fixtures.cpp
    test_json.cpp
    test_pe.cpp
    test_report.cpp
)
set_target_properties(binpeek_tests PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(binpeek_tests SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/doctest)
# doctest names test cases with __COUNTER__, which Clang 22 and later report
# under -Wpedantic as a C2y extension; with BINPEEK_WARNINGS_AS_ERRORS that
# fails the build. The warning concerns doctest's macros, not our code, so
# turn off just that one, for the tests only. It must come after -Wpedantic
# on the command line, hence a separate interface target linked after
# binpeek_build_flags. (Check the positive flag: GCC accepts any unknown
# -Wno-... silently.)
add_library(binpeek_test_flags INTERFACE)
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-Wc2y-extensions BINPEEK_HAVE_WC2Y_EXTENSIONS)
if(BINPEEK_HAVE_WC2Y_EXTENSIONS)
    target_compile_options(binpeek_test_flags INTERFACE -Wno-c2y-extensions)
endif()

target_link_libraries(binpeek_tests PRIVATE binpeek binpeek_build_flags binpeek_test_flags)
# Fixtures are found through the source tree, so the tests do not depend on
# the working directory.
target_compile_definitions(binpeek_tests PRIVATE BINPEEK_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
add_test(NAME binpeek_tests COMMAND binpeek_tests)

set(DATA ${CMAKE_CURRENT_SOURCE_DIR}/data)

# Smoke tests for the command-line tool against the fixtures.
if(TARGET binpeek_cli)
    add_test(NAME cli_elf_headers COMMAND binpeek_cli ${DATA}/hello.elf)
    set_tests_properties(cli_elf_headers PROPERTIES PASS_REGULAR_EXPRESSION
        "Interpreter: +/lib64/ld-linux-x86-64.so.2")

    add_test(NAME cli_elf_imports COMMAND binpeek_cli --imports ${DATA}/hello.elf)
    set_tests_properties(cli_elf_imports PROPERTIES PASS_REGULAR_EXPRESSION "libm\\.so\\.6.*FUNC +GLOBAL +sqrt")

    add_test(NAME cli_object_symbols COMMAND binpeek_cli -s ${DATA}/sample.o)
    set_tests_properties(cli_object_symbols PROPERTIES PASS_REGULAR_EXPRESSION "FUNC +GLOBAL +HIDDEN +1 +helper")

    add_test(NAME cli_pe_imports COMMAND binpeek_cli -i ${DATA}/hello.exe)
    set_tests_properties(cli_pe_imports PROPERTIES PASS_REGULAR_EXPRESSION "Imports from greet\\.dll.*ordinal 7")

    add_test(NAME cli_dll_exports COMMAND binpeek_cli --exports ${DATA}/greet.dll)
    set_tests_properties(cli_dll_exports PROPERTIES PASS_REGULAR_EXPRESSION "ExitNow +KERNEL32\\.ExitProcess")

    add_test(NAME cli_coff_long_name COMMAND binpeek_cli -S ${DATA}/greet.obj)
    set_tests_properties(cli_coff_long_name PROPERTIES PASS_REGULAR_EXPRESSION "\\.rdata\\$greeting")

    add_test(NAME cli_json COMMAND binpeek_cli --json -S ${DATA}/sample.o ${DATA}/greet.dll)
    set_tests_properties(cli_json PROPERTIES PASS_REGULAR_EXPRESSION
        "\"name\": \"\\.symtab\".*\"format\": \"PE\"")

    add_test(NAME cli_all COMMAND binpeek_cli --all ${DATA}/hello.elf ${DATA}/hello.exe)
    set_tests_properties(cli_all PROPERTIES PASS_REGULAR_EXPRESSION "Program headers \\(10\\).*Data directories")

    # Exit codes: 1 for unreadable or malformed files (with the offset in the
    # message), 2 for usage errors.
    function(binpeek_exit_test name code regex)
        add_test(NAME ${name} COMMAND ${CMAKE_COMMAND}
            -DPROGRAM=$<TARGET_FILE:binpeek_cli>
            "-DEMULATOR=${CMAKE_CROSSCOMPILING_EMULATOR}"
            -DEXPECTED_EXIT=${code}
            "-DEXPECTED_OUTPUT=${regex}"
            "-DARGS=${ARGN}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run_cli.cmake)
    endfunction()
    binpeek_exit_test(cli_truncated 1 "truncated\\.elf: offset 0x10b8: section header table" ${DATA}/truncated.elf)
    binpeek_exit_test(cli_not_binary 1 "offset 0x0: unrecognized file format" ${DATA}/src/greet.def)
    binpeek_exit_test(cli_missing_file 1 "missing\\.bin: " ${DATA}/missing.bin)
    binpeek_exit_test(cli_partial_failure 1 "x86-64" ${DATA}/hello.elf ${DATA}/truncated.elf)
    binpeek_exit_test(cli_json_error 1 "\"error\": \"section header table" --json ${DATA}/truncated.elf)
    binpeek_exit_test(cli_no_files 2 "no input files" --headers)
    binpeek_exit_test(cli_bad_option 2 "unknown option '--bogus'" --bogus ${DATA}/hello.elf)
    binpeek_exit_test(cli_bad_short_option 2 "unknown option '-q'" -Sq ${DATA}/hello.elf)
    binpeek_exit_test(cli_help 0 "Usage:" --help)
endif()

if(TARGET binpeek_list_deps)
    add_test(NAME example_list_deps COMMAND binpeek_list_deps ${DATA}/hello.exe ${DATA}/hello.elf)
    set_tests_properties(example_list_deps PROPERTIES PASS_REGULAR_EXPRESSION
        "greet\\.dll \\(3 functions\\).*libc\\.so\\.6")
endif()
