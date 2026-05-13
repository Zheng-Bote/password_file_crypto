cmake_minimum_required(VERSION 3.28)

# cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; cmake --build build --config Release

project(password_file_crypto 
VERSION 1.2.0
DESCRIPTION "A simple password file en-/de-cryption tool using libsodium"
HOMEPAGE_URL "https://github.com/Zheng-Bote/password_file_crypto"
LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Configure (für rz_config.hpp) ---
set(EXECUTABLE_NAME "${PROJECT_NAME}")
set(PROG_LONGNAME "${PROJECT_DESCRIPTION}")
set(PROG_CREATED "2026")
set(PROG_COPYRIGHT "ZHENG Robert")
set(PROG_LICENSE "MIT")
set(PROG_AUTHOR "ZHENG Robert")
set(PROG_ORGANIZATION_NAME "ZHENG Robert")
set(PROG_ORGANIZATION_DOMAIN "net.hase-zheng")
# create rz_config.hpp
add_subdirectory(configure)

# --- Dependencies via Conan & FetchContent ---
find_package(libsodium REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(httplib REQUIRED)
find_package(OpenSSL REQUIRED)

include(FetchContent)

FetchContent_Declare(
  gh_update_checker
  GIT_REPOSITORY https://github.com/Zheng-Bote/gh-update-checker.git
  GIT_TAG        v1.0.9
)
FetchContent_MakeAvailable(gh_update_checker)
if(NOT TARGET gh_update_checker::gh_update_checker)
    add_library(gh_update_checker::gh_update_checker ALIAS gh_update_checker)
endif()

add_executable(password_file_crypto
    src/main.cpp
)

# Ensure standard Windows libraries are linked for OpenSSL/httplib
if(MSVC)
    target_link_libraries(password_file_crypto PRIVATE ws2_32 crypt32)
endif()

target_include_directories(password_file_crypto PRIVATE include)

# Use static definition for libsodium
target_compile_definitions(password_file_crypto PRIVATE SODIUM_STATIC CPPHTTPLIB_OPENSSL_SUPPORT)

target_link_libraries(password_file_crypto PRIVATE 
    libsodium::libsodium 
    gh_update_checker::gh_update_checker
    nlohmann_json::nlohmann_json
    httplib::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Ensure GCC/MinGW links standard libraries statically
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # if not using MSVC, add -static
    if(NOT MSVC)
        target_link_options(password_file_crypto PRIVATE -static)
    endif()
endif()

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/${PROJECT_NAME}_libs.txt" 
     CONTENT "$<TARGET_PROPERTY:${PROJECT_NAME},LINK_LIBRARIES>")