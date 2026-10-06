cmake_minimum_required(VERSION 3.20)
project(ReverseRosetta VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# macOS minimum target
set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0")

# Sources
set(SOURCES
    src/main.cpp
    src/loader/macho_loader.cpp
    src/decoder/arm64_decoder.cpp
    src/interpreter/interpreter.cpp
    src/syscall/syscall_translator.cpp
)

add_executable(rrosetta ${SOURCES})

target_include_directories(rrosetta PRIVATE include)

# macOS frameworks
target_link_libraries(rrosetta
    "-framework Foundation"
    "-framework Security"
)

# Entitlements for JIT memory (MAP_JIT)
set_target_properties(rrosetta PROPERTIES
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "${CMAKE_SOURCE_DIR}/entitlements/rrosetta.entitlements"
)

# Build type defaults
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

target_compile_options(rrosetta PRIVATE
    -Wall -Wextra
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-g -O0>
)
