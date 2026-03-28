cmake_minimum_required(VERSION 3.28)
project(password_file_crypto 
VERSION 1.0.0
DESCRIPTION "A simple password file en-/de-cryption tool using libsodium"
HOMEPAGE_URL "https://github.com/Zheng-Bote/password_file_crypto"
LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
include(ExternalProject)

# libsodium holen
FetchContent_Declare(
    libsodium_src
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG stable
)

FetchContent_GetProperties(libsodium_src)
if(NOT libsodium_src_POPULATED)
    FetchContent_Populate(libsodium_src)
endif()

# libsodium bauen und lokal installieren
ExternalProject_Add(libsodium_build
    SOURCE_DIR        ${libsodium_src_SOURCE_DIR}
    CONFIGURE_COMMAND ./configure --prefix=${CMAKE_BINARY_DIR}/libsodium-install
    BUILD_COMMAND     make
    INSTALL_COMMAND   make install
    BUILD_IN_SOURCE   1
)

# Include- und Library-Pfade setzen
set(LIBSODIUM_INCLUDE_DIR ${CMAKE_BINARY_DIR}/libsodium-install/include)
set(LIBSODIUM_LIBRARY     ${CMAKE_BINARY_DIR}/libsodium-install/lib/libsodium.a)

add_executable(password_file_crypto
    src/main.cpp
)

add_dependencies(password_file_crypto libsodium_build)

target_include_directories(password_file_crypto PRIVATE ${LIBSODIUM_INCLUDE_DIR})
target_link_libraries(password_file_crypto PRIVATE ${LIBSODIUM_LIBRARY})

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/libs.txt" 
     CONTENT "$<TARGET_PROPERTY:${PROJECT_NAME},LINK_LIBRARIES>")