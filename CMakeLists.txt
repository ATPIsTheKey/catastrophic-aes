cmake_minimum_required(VERSION 3.15)
project(catastrophic_aes C)

set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM libsodium)
find_package(Threads REQUIRED)

if(STATIC_LIBSODIUM)
    if(BUILD_STATIC_EXECUTABLES)
        set_target_properties(minisign PROPERTIES LINK_SEARCH_START_STATIC 1)
        set_target_properties(minisign PROPERTIES LINK_SEARCH_END_STATIC 1)
    endif()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
endif()

find_path(SODIUM_INCLUDE_DIR sodium.h HINTS ${LIBSODIUM_INCLUDE_DIRS} /usr/local/include /opt/local/include /opt/include)
find_library(SODIUM_LIBRARY NAMES sodium HINTS ${LIBSODIUM_LIBRARY_DIRS} /usr/local/lib /opt/local/lib /opt/lib)

if(STATIC_LIBSODIUM)
    set(LIBSODIUM_CFLAGS_OTHER ${LIBSODIUM_STATIC_CFLAGS_OTHER})
    set(LIBSODIUM_LDFLAGS_OTHER ${LIBSODIUM_STATIC_LDFLAGS_OTHER})
endif()

add_executable(${PROJECT_NAME} main.c utils/stdprojutils.c utils/stdprojutils.h catastrophic-aes/aes_core.c catastrophic-aes/aes_core.h catastrophic-aes/aes_utils.c catastrophic-aes/aes_utils.h catastrophic-aes/aes_fcrypt.c catastrophic-aes/aes_fcrypt.h)

target_include_directories(${PROJECT_NAME} PUBLIC ${SODIUM_INCLUDE_DIR})
target_compile_options(${PROJECT_NAME} PUBLIC ${LIBSODIUM_CFLAGS} ${LIBSODIUM_CFLAGS_OTHER} PRIVATE -DDEBUG)
target_link_libraries(${PROJECT_NAME} ${SODIUM_LIBRARY} ${LIBSODIUM_LDFLAGS_OTHER} ssl crypto ${CMAKE_THREAD_LIBS_INIT})
