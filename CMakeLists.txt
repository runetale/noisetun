cmake_minimum_required(VERSION 3.16)

# The version is set once, as WG_VERSION in include/wireguard.h.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/wireguard.h" _wg_version_line
     REGEX "^#define WG_VERSION \"[0-9]+\\.[0-9]+\\.[0-9]+\"")
string(REGEX REPLACE "^#define WG_VERSION \"([0-9.]+)\".*" "\\1" _wg_version "${_wg_version_line}")

# Files read at configure time: a change to either must re-run CMake, as a
# change to the list in this file used to.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/sources.txt"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/wireguard.h")

project(noisetun
    VERSION ${_wg_version}
    LANGUAGES C
    DESCRIPTION "WireGuard userspace implementation in C"
)

# ──────────────────────────────────────────
# Global settings
# ──────────────────────────────────────────
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(WG_BUILD_TESTS  "Build test suite"  ON)
option(WG_BUILD_BENCH  "Build benchmarks"  OFF)
option(WG_BUILD_FUZZ   "Build fuzz targets (requires Clang)" OFF)
option(WG_ASAN         "Enable AddressSanitizer + UBSan in Debug" ON)
option(WG_TSAN         "Enable ThreadSanitizer in Debug"         OFF)
option(WG_USE_OPENSSL  "Use OpenSSL for ChaCha20-Poly1305 AEAD (NEON on ARM64)" ON)
option(WG_USE_IO_URING "Use io_uring for TUN/UDP I/O batching (Linux 5.6+)" OFF)

if(WG_ASAN AND WG_TSAN)
    message(FATAL_ERROR "WG_ASAN and WG_TSAN cannot be enabled simultaneously")
endif()

# POSIX APIs: pthread_rwlock_t, clock_gettime, etc.
# On macOS, _POSIX_C_SOURCE hides Darwin-specific APIs (PF_SYSTEM, utun, etc.)
# so we use _DARWIN_C_SOURCE which enables all POSIX + BSD + Darwin extensions.
if(APPLE)
    add_compile_definitions(_DARWIN_C_SOURCE)
elseif(ANDROID)
    # bionic declares cpu_set_t, pthread_setname_np and the like only with
    # _GNU_SOURCE, where glibc has some of them under _POSIX_C_SOURCE too.
    add_compile_definitions(_GNU_SOURCE)
elseif(NOT WIN32)
    add_compile_definitions(_POSIX_C_SOURCE=200112L)
endif()

# ──────────────────────────────────────────
# Compiler warnings
# ──────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /wd4100 /wd4200 /wd4996 /experimental:c11atomics)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wstrict-prototypes
        -Wshadow
        -Wformat=2
    )
endif()

# Clang-only warning suppression
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wno-empty-translation-unit)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(-fvisibility=hidden)
endif()

# Sanitizers for Debug builds (GCC/Clang only)
if(NOT MSVC)
    if(WG_ASAN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()

    if(WG_TSAN AND CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
        add_link_options(-fsanitize=thread)
    endif()
endif()

# ──────────────────────────────────────────
# Dependencies: libsodium
# ──────────────────────────────────────────
set(SODIUM_INCLUDE_DIR "" CACHE PATH "Path to libsodium include directory")
set(SODIUM_LIBRARY "" CACHE FILEPATH "Path to libsodium library file")

if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
    add_library(sodium STATIC IMPORTED)
    set_target_properties(sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
        INTERFACE_COMPILE_DEFINITIONS "SODIUM_STATIC"
    )
    set(SODIUM_FOUND TRUE)
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
    endif()

    if(NOT SODIUM_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            libsodium
            GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
            GIT_TAG        stable
        )
        FetchContent_MakeAvailable(libsodium)
    endif()
endif()

# ──────────────────────────────────────────
# Dependencies: OpenSSL (optional, for ChaCha20-Poly1305 NEON on ARM64)
# ──────────────────────────────────────────
if(WG_USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
endif()

# ──────────────────────────────────────────
# Dependencies: liburing (optional, for io_uring I/O batching)
# ──────────────────────────────────────────
if(WG_USE_IO_URING)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "WG_USE_IO_URING requires Linux")
    endif()
    if(PkgConfig_FOUND)
        pkg_check_modules(URING IMPORTED_TARGET liburing)
    endif()
    if(NOT URING_FOUND)
        find_library(URING_LIB uring)
        find_path(URING_INC liburing.h)
        if(NOT URING_LIB OR NOT URING_INC)
            message(FATAL_ERROR "liburing not found; install liburing-dev or set WG_USE_IO_URING=OFF")
        endif()
    endif()
endif()

# ──────────────────────────────────────────
# Core library: libwireguard
# ──────────────────────────────────────────
# The source list lives in sources.txt, where other build systems can read
# it too. Each line is "<path> <platforms>".
if(WIN32)
    set(_wg_platforms all windows)
elseif(CMAKE_SYSTEM_NAME MATCHES "^(Linux|Android)$")
    set(_wg_platforms all posix linux)
elseif(CMAKE_SYSTEM_NAME MATCHES "^(Darwin|iOS|tvOS|visionOS)$")
    set(_wg_platforms all posix apple)
else()
    set(_wg_platforms all posix)
endif()
set(WG_SOURCES "")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/sources.txt" _wg_source_lines REGEX "^src/")
foreach(_line IN LISTS _wg_source_lines)
    string(REGEX MATCH "^([^ \t]+)[ \t]+([a-z]+)" _m "${_line}")
    if(NOT _m)
        message(FATAL_ERROR "sources.txt: bad line: ${_line}")
    endif()
    if(CMAKE_MATCH_2 IN_LIST _wg_platforms)
        list(APPEND WG_SOURCES "${CMAKE_MATCH_1}")
    endif()
endforeach()

add_library(wireguard STATIC ${WG_SOURCES})
# Unset: automatic (on for iOS). Set it to test the bounded pools elsewhere.
if(DEFINED WG_MEMORY_CONSTRAINED)
    if(WG_MEMORY_CONSTRAINED)
        target_compile_definitions(wireguard PUBLIC WG_MEMORY_CONSTRAINED=1)
    else()
        target_compile_definitions(wireguard PUBLIC WG_MEMORY_CONSTRAINED=0)
    endif()
endif()

target_include_directories(wireguard
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(SODIUM_FOUND AND TARGET PkgConfig::SODIUM)
    target_link_libraries(wireguard PUBLIC PkgConfig::SODIUM)
else()
    target_link_libraries(wireguard PUBLIC sodium)
endif()

if(WG_USE_OPENSSL)
    target_link_libraries(wireguard PUBLIC OpenSSL::Crypto)
    target_compile_definitions(wireguard PUBLIC WG_USE_OPENSSL=1)
    target_include_directories(wireguard PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

if(WG_USE_IO_URING)
    if(URING_FOUND AND TARGET PkgConfig::URING)
        target_link_libraries(wireguard PUBLIC PkgConfig::URING)
    else()
        target_link_libraries(wireguard PUBLIC ${URING_LIB})
        target_include_directories(wireguard PRIVATE ${URING_INC})
    endif()
    target_compile_definitions(wireguard PUBLIC WG_USE_IO_URING=1)
endif()

# pthreads (POSIX) / Windows system libs
if(WIN32)
    target_link_libraries(wireguard PUBLIC ws2_32 ntdll ole32 advapi32 synchronization)
    target_compile_definitions(wireguard PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0602)
    if(MINGW)
        # clock_gettime and nanosleep come from winpthreads (the MSVC build
        # uses the shims in wg_platform.h); link it statically so the
        # executables need no extra DLL.
        target_link_libraries(wireguard PUBLIC -l:libwinpthread.a)
    endif()
else()
    find_package(Threads REQUIRED)
    target_link_libraries(wireguard PUBLIC Threads::Threads)
endif()

# ──────────────────────────────────────────
# Tests
# ──────────────────────────────────────────
if(WG_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ──────────────────────────────────────────
# Benchmarks
# ──────────────────────────────────────────
if(WG_BUILD_BENCH)
    add_subdirectory(bench)
endif()

# ──────────────────────────────────────────
# Fuzz targets (requires Clang + libFuzzer)
# ──────────────────────────────────────────
if(WG_BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()

# ──────────────────────────────────────────
# Tools (standalone binaries)
# ──────────────────────────────────────────
option(WG_BUILD_TOOLS "Build standalone tools (wg-c daemon)" ON)
if(WG_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# ──────────────────────────────────────────
# Install
# ──────────────────────────────────────────
install(TARGETS wireguard
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)
install(DIRECTORY include/
    DESTINATION include/wireguard
    FILES_MATCHING PATTERN "*.h"
)
