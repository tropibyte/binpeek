# Runs PROGRAM with ARGS (a list) and checks its exit code against
# EXPECTED_EXIT and, when given, its standard output and error together
# against the regular expression EXPECTED_OUTPUT. EMULATOR, when set, runs
# the program (Wine for the mingw preset).
#
#   cmake -DPROGRAM=... -DEXPECTED_EXIT=2 "-DARGS=--bogus" -P run_cli.cmake

set(command ${PROGRAM} ${ARGS})
if(EMULATOR)
    set(command ${EMULATOR} ${command})
endif()
execute_process(COMMAND ${command} RESULT_VARIABLE result OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT result STREQUAL "${EXPECTED_EXIT}")
    message(FATAL_ERROR "exit status ${result}, expected ${EXPECTED_EXIT}\nstdout:\n${out}\nstderr:\n${err}")
endif()
if(DEFINED EXPECTED_OUTPUT AND NOT "${out}${err}" MATCHES "${EXPECTED_OUTPUT}")
    message(FATAL_ERROR "output does not match '${EXPECTED_OUTPUT}'\nstdout:\n${out}\nstderr:\n${err}")
endif()
