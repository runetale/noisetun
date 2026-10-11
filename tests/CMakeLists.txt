# Tests use assert() with side effects (ASSERT_OK etc.), so NDEBUG must not be defined.
remove_definitions(-DNDEBUG)
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
# MSVC spells it /DNDEBUG.
string(REPLACE "/DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
string(REPLACE "/DNDEBUG" "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")

# Windows: only the tests that do not need POSIX headers (pthread.h,
# arpa/inet.h, unistd.h) build there yet.
if(WIN32)
    foreach(t types rfc_vectors noise handshake cookie replay transport indextable peer timers uapi_set)
        add_executable(test_${t} test_${t}.c)
        target_include_directories(test_${t} PRIVATE ${CMAKE_SOURCE_DIR}/src)
        target_link_libraries(test_${t} PRIVATE wireguard)
        add_test(NAME test_${t} COMMAND test_${t})
    endforeach()

    # The handshake against wireguard-go vectors. The test compiles
    # wg_noise.c itself with fixed ephemeral keys and timestamp; the
    # library's copy is not linked in, as this one defines all its symbols.
    add_executable(test_noise_vectors test_noise_vectors.c ${CMAKE_SOURCE_DIR}/src/noise/wg_noise.c)
    target_compile_definitions(test_noise_vectors PRIVATE WG_NOISE_FIXED_INPUTS)
    target_include_directories(test_noise_vectors PRIVATE ${CMAKE_SOURCE_DIR}/src
                                                          ${CMAKE_SOURCE_DIR}/src/noise)
    target_link_libraries(test_noise_vectors PRIVATE wireguard)
    add_test(NAME test_noise_vectors COMMAND test_noise_vectors)
    return()
endif()

add_executable(test_types test_types.c)
target_link_libraries(test_types PRIVATE wireguard)
add_test(NAME test_types COMMAND test_types)

add_executable(test_prev_queue test_prev_queue.c)
target_include_directories(test_prev_queue PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_prev_queue PRIVATE wireguard)
add_test(NAME test_prev_queue COMMAND test_prev_queue)

add_executable(test_uapi_set test_uapi_set.c)
target_include_directories(test_uapi_set PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_uapi_set PRIVATE wireguard)
add_test(NAME test_uapi_set COMMAND test_uapi_set)

add_executable(test_tunnel test_tunnel.c)
target_link_libraries(test_tunnel PRIVATE wireguard)
add_test(NAME test_tunnel COMMAND test_tunnel)

add_executable(test_pool_exhaustion test_pool_exhaustion.c)
target_include_directories(test_pool_exhaustion PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_pool_exhaustion PRIVATE wireguard)
add_test(NAME test_pool_exhaustion COMMAND test_pool_exhaustion)

add_executable(test_crypto test_crypto.c)
target_include_directories(test_crypto PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_crypto PRIVATE wireguard)
add_test(NAME test_crypto COMMAND test_crypto)

add_executable(test_rfc_vectors test_rfc_vectors.c)
target_include_directories(test_rfc_vectors PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_rfc_vectors PRIVATE wireguard)
add_test(NAME test_rfc_vectors COMMAND test_rfc_vectors)

add_executable(test_noise test_noise.c)
target_include_directories(test_noise PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_noise PRIVATE wireguard)
add_test(NAME test_noise COMMAND test_noise)

# The handshake against wireguard-go vectors. The test compiles
# wg_noise.c itself with fixed ephemeral keys and timestamp; the
# library's copy is not linked in, as this one defines all its symbols.
add_executable(test_noise_vectors test_noise_vectors.c ${CMAKE_SOURCE_DIR}/src/noise/wg_noise.c)
target_compile_definitions(test_noise_vectors PRIVATE WG_NOISE_FIXED_INPUTS)
target_include_directories(test_noise_vectors PRIVATE ${CMAKE_SOURCE_DIR}/src
                                                      ${CMAKE_SOURCE_DIR}/src/noise)
target_link_libraries(test_noise_vectors PRIVATE wireguard)
add_test(NAME test_noise_vectors COMMAND test_noise_vectors)

add_executable(test_handshake test_handshake.c)
target_include_directories(test_handshake PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_handshake PRIVATE wireguard)
add_test(NAME test_handshake COMMAND test_handshake)

add_executable(test_cookie test_cookie.c)
target_include_directories(test_cookie PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_cookie PRIVATE wireguard)
add_test(NAME test_cookie COMMAND test_cookie)

add_executable(test_replay test_replay.c)
target_include_directories(test_replay PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_replay PRIVATE wireguard)
add_test(NAME test_replay COMMAND test_replay)

add_executable(test_handshake_concurrent test_handshake_concurrent.c)
target_include_directories(test_handshake_concurrent PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_handshake_concurrent PRIVATE wireguard)
add_test(NAME test_handshake_concurrent COMMAND test_handshake_concurrent)

add_executable(test_transport test_transport.c)
target_include_directories(test_transport PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_transport PRIVATE wireguard)
add_test(NAME test_transport COMMAND test_transport)

add_executable(test_indextable test_indextable.c)
target_include_directories(test_indextable PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_indextable PRIVATE wireguard)
add_test(NAME test_indextable COMMAND test_indextable)

add_executable(test_session test_session.c)
target_include_directories(test_session PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_session PRIVATE wireguard)
add_test(NAME test_session COMMAND test_session)

add_executable(test_queue test_queue.c)
target_include_directories(test_queue PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_queue PRIVATE wireguard)
add_test(NAME test_queue COMMAND test_queue)

add_executable(test_pools test_pools.c)
target_include_directories(test_pools PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_pools PRIVATE wireguard)
add_test(NAME test_pools COMMAND test_pools)

add_executable(test_allowedips test_allowedips.c)
target_include_directories(test_allowedips PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_allowedips PRIVATE wireguard)
add_test(NAME test_allowedips COMMAND test_allowedips)

add_executable(test_peer test_peer.c)
target_include_directories(test_peer PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_peer PRIVATE wireguard)
add_test(NAME test_peer COMMAND test_peer)

add_executable(test_timers test_timers.c)
target_include_directories(test_timers PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_timers PRIVATE wireguard)
add_test(NAME test_timers COMMAND test_timers)

add_executable(test_ratelimiter test_ratelimiter.c)
target_include_directories(test_ratelimiter PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_ratelimiter PRIVATE wireguard)
add_test(NAME test_ratelimiter COMMAND test_ratelimiter)

add_executable(test_device test_device.c)
target_include_directories(test_device PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_device PRIVATE wireguard)
add_test(NAME test_device COMMAND test_device)

add_executable(test_workers test_workers.c)
target_include_directories(test_workers PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_workers PRIVATE wireguard)
add_test(NAME test_workers COMMAND test_workers)

add_executable(test_device_ping_pong test_device_ping_pong.c)
target_include_directories(test_device_ping_pong PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_device_ping_pong PRIVATE wireguard)
add_test(NAME test_device_ping_pong COMMAND test_device_ping_pong)

add_executable(test_device_handshake_stdbind test_device_handshake_stdbind.c)
target_include_directories(test_device_handshake_stdbind PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_device_handshake_stdbind PRIVATE wireguard)
add_test(NAME test_device_handshake_stdbind COMMAND test_device_handshake_stdbind)

add_executable(test_ratelimiter_concurrent test_ratelimiter_concurrent.c)
target_include_directories(test_ratelimiter_concurrent PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_ratelimiter_concurrent PRIVATE wireguard)
add_test(NAME test_ratelimiter_concurrent COMMAND test_ratelimiter_concurrent)

add_executable(test_indextable_concurrent test_indextable_concurrent.c)
target_include_directories(test_indextable_concurrent PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_indextable_concurrent PRIVATE wireguard)
add_test(NAME test_indextable_concurrent COMMAND test_indextable_concurrent)

add_executable(test_allowedips_concurrent test_allowedips_concurrent.c)
target_include_directories(test_allowedips_concurrent PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_allowedips_concurrent PRIVATE wireguard)
add_test(NAME test_allowedips_concurrent COMMAND test_allowedips_concurrent)

add_executable(test_peer_concurrent test_peer_concurrent.c)
target_include_directories(test_peer_concurrent PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_peer_concurrent PRIVATE wireguard)
add_test(NAME test_peer_concurrent COMMAND test_peer_concurrent)

add_executable(test_device_concurrent test_device_concurrent.c)
target_include_directories(test_device_concurrent PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_device_concurrent PRIVATE wireguard)
add_test(NAME test_device_concurrent COMMAND test_device_concurrent)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_tun_linux test_tun_linux.c)
    target_include_directories(test_tun_linux PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_tun_linux PRIVATE wireguard)
    add_test(NAME test_tun_linux COMMAND test_tun_linux)

    add_executable(test_handshake_real test_handshake_real.c)
    target_include_directories(test_handshake_real PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_handshake_real PRIVATE wireguard)
    add_test(NAME test_handshake_real COMMAND test_handshake_real)

    add_executable(test_interop_wg_go test_interop_wg_go.c)
    target_include_directories(test_interop_wg_go PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_interop_wg_go PRIVATE wireguard)
    add_test(NAME test_interop_wg_go COMMAND test_interop_wg_go)

    add_executable(test_uapi_wg_compat test_uapi_wg_compat.c)
    target_include_directories(test_uapi_wg_compat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_uapi_wg_compat PRIVATE wireguard)
    add_test(NAME test_uapi_wg_compat COMMAND test_uapi_wg_compat)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_executable(test_tun_darwin test_tun_darwin.c)
    target_include_directories(test_tun_darwin PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_tun_darwin PRIVATE wireguard)
    add_test(NAME test_tun_darwin COMMAND test_tun_darwin)

    add_executable(test_handshake_real test_handshake_real.c)
    target_include_directories(test_handshake_real PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test_handshake_real PRIVATE wireguard)
    add_test(NAME test_handshake_real COMMAND test_handshake_real)
endif()
