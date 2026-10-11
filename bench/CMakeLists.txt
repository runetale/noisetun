# Benchmarks use assert() for setup validation, so NDEBUG must not be defined.
remove_definitions(-DNDEBUG)
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")

add_executable(bench_throughput bench_throughput.c)
target_include_directories(bench_throughput PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(bench_throughput PRIVATE wireguard)

add_executable(bench_latency bench_latency.c)
target_include_directories(bench_latency PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(bench_latency PRIVATE wireguard)

add_executable(bench_crypto bench_crypto.c)
target_include_directories(bench_crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(bench_crypto PRIVATE wireguard)

add_executable(bench_handshake bench_handshake.c)
target_include_directories(bench_handshake PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(bench_handshake PRIVATE wireguard)
