# Fuzz targets — build with: cmake -DWG_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang
# Requires clang with libFuzzer support.

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(WARNING "Fuzzing requires Clang (libFuzzer). Skipping fuzz targets.")
    return()
endif()

set(FUZZ_FLAGS "-fsanitize=fuzzer,address -g -O1")
set(FUZZ_LINK_FLAGS "-fsanitize=fuzzer,address")

# ── fuzz_handshake ──
add_executable(fuzz_handshake fuzz_handshake.c)
target_include_directories(fuzz_handshake PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(fuzz_handshake PRIVATE wireguard)
set_target_properties(fuzz_handshake PROPERTIES
    COMPILE_FLAGS "${FUZZ_FLAGS}"
    LINK_FLAGS "${FUZZ_LINK_FLAGS}"
)

# ── fuzz_uapi ──
add_executable(fuzz_uapi fuzz_uapi.c)
target_include_directories(fuzz_uapi PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(fuzz_uapi PRIVATE wireguard)
set_target_properties(fuzz_uapi PROPERTIES
    COMPILE_FLAGS "${FUZZ_FLAGS}"
    LINK_FLAGS "${FUZZ_LINK_FLAGS}"
)

# ── fuzz_transport ──
add_executable(fuzz_transport fuzz_transport.c)
target_include_directories(fuzz_transport PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(fuzz_transport PRIVATE wireguard)
set_target_properties(fuzz_transport PROPERTIES
    COMPILE_FLAGS "${FUZZ_FLAGS}"
    LINK_FLAGS "${FUZZ_LINK_FLAGS}"
)
