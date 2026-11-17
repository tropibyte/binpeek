# Cross-compiles for 64-bit Windows with MinGW-w64 (Debian/Ubuntu package
# names). The -posix compilers use the POSIX thread model, which libstdc++
# needs for std::thread and friends; the runtime is linked statically so the
# executables run under Wine without copying DLLs next to them.
#
#   cmake --preset mingw && cmake --build --preset mingw && ctest --preset mingw

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(BINPEEK_MINGW_TRIPLET x86_64-w64-mingw32)
set(CMAKE_C_COMPILER ${BINPEEK_MINGW_TRIPLET}-gcc-posix)
set(CMAKE_CXX_COMPILER ${BINPEEK_MINGW_TRIPLET}-g++-posix)
set(CMAKE_RC_COMPILER ${BINPEEK_MINGW_TRIPLET}-windres)

set(CMAKE_FIND_ROOT_PATH /usr/${BINPEEK_MINGW_TRIPLET})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -static-libgcc -static-libstdc++")
