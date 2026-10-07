cmake_minimum_required(VERSION 3.20)
project(Reverta VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0")

set(SOURCES
    src/main.cpp
    # Phase 1 — core
    src/loader/macho_loader.cpp
    src/decoder/arm64_decoder.cpp
    src/interpreter/interpreter.cpp
    # Phase 2 — x86-64 JIT
    src/jit/jit_compiler.cpp
    src/syscall/syscall_translator.cpp
    # Phase 5 — runtime bridges
    src/objc/objc_runtime.cpp
    src/swift/swift_runtime.cpp
    src/foundation/foundation_stubs.cpp
    src/appkit/appkit_stubs.cpp
    src/dylib/dylib_interceptor.cpp
)

add_executable(reverta ${SOURCES})

target_include_directories(reverta PRIVATE include)

target_link_libraries(reverta
    "-framework Foundation"
    "-framework AppKit"
    "-framework CoreFoundation"
    "-framework Security"
)

set_target_properties(reverta PROPERTIES
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS
        "${CMAKE_SOURCE_DIR}/entitlements/rrosetta.entitlements"
)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

target_compile_options(reverta PRIVATE
    -Wall -Wextra
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Debug>:-g -O0>
)

include(CTest)
if(BUILD_TESTING)
    add_executable(reverta_jit_smoke
        tests/jit_smoke.cpp
        src/jit/jit_compiler.cpp
        src/decoder/arm64_decoder.cpp
    )
    target_include_directories(reverta_jit_smoke PRIVATE include)
    add_test(NAME reverta_jit_smoke COMMAND reverta_jit_smoke)
endif()
