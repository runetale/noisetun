add_executable(wg-c wg-c/main.c)
target_include_directories(wg-c PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(wg-c PRIVATE wireguard)
if(WIN32)
    target_link_libraries(wg-c PRIVATE ws2_32 advapi32 ole32)
    target_compile_definitions(wg-c PRIVATE SODIUM_STATIC)
endif()
install(TARGETS wg-c RUNTIME DESTINATION bin)

# wg-quick-c: quick configuration tool (Linux only)
if(NOT WIN32)
    add_executable(wg-quick-c wg-quick-c/main.c)
    target_include_directories(wg-quick-c PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    install(TARGETS wg-quick-c RUNTIME DESTINATION bin)
endif()

# Copy wintun.dll next to wg-c.exe on Windows
if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
            set(WINTUN_ARCH "arm64")
        else()
            set(WINTUN_ARCH "amd64")
        endif()
    else()
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM")
            set(WINTUN_ARCH "arm")
        else()
            set(WINTUN_ARCH "x86")
        endif()
    endif()

    set(WINTUN_DLL "${CMAKE_SOURCE_DIR}/third_party/wintun/${WINTUN_ARCH}/wintun.dll")
    if(EXISTS ${WINTUN_DLL})
        add_custom_command(TARGET wg-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${WINTUN_DLL}
                $<TARGET_FILE_DIR:wg-c>/wintun.dll
            COMMENT "Copying wintun.dll (${WINTUN_ARCH}) to output directory"
        )
    else()
        message(WARNING "wintun.dll not found at ${WINTUN_DLL} - download from https://www.wintun.net/")
    endif()
endif()
