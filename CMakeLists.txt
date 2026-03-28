cmake_minimum_required(VERSION 3.28)

# cmake -S . -B build; cmake --build build --config Release

project(password_file_crypto 
VERSION 1.0.0
DESCRIPTION "A simple password file en-/de-cryption tool using libsodium"
HOMEPAGE_URL "https://github.com/Zheng-Bote/password_file_crypto"
LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Configure static runtime library for MSVC
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(FetchContent)

# Fetch a CMake-enabled wrapper for libsodium to avoid ./configure issues on Windows
set(BUILD_SHARED_LIBS OFF)
# Disable libsodium tests
set(SODIUM_DISABLE_TESTS ON)
FetchContent_Declare(
    libsodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
)
FetchContent_MakeAvailable(libsodium)

add_executable(password_file_crypto
    src/main.cpp
)

# Use static definition for libsodium
target_compile_definitions(password_file_crypto PRIVATE SODIUM_STATIC)

target_link_libraries(password_file_crypto PRIVATE sodium)

# Ensure GCC/MinGW links standard libraries statically
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # if not using MSVC, add -static
    if(NOT MSVC)
        target_link_options(password_file_crypto PRIVATE -static)
    endif()
endif()

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/libs.txt" 
     CONTENT "$<TARGET_PROPERTY:${PROJECT_NAME},LINK_LIBRARIES>")