#pragma once
#include <cstdint>
#include "interpreter/interpreter.h"

// ARM64 macOS syscall numbers differ from x86-64 macOS syscall numbers
// but the kernel semantics are the same — we just re-issue the call
// using the x86-64 ABI (syscall instruction with appropriate registers).
//
// ARM64 ABI:  syscall number in X16, args in X0-X7, result in X0/X1
// x86-64 ABI: syscall number in RAX, args in RDI,RSI,RDX,R10,R8,R9
//
// Syscall numbers are DIFFERENT between the two architectures on macOS,
// so we map them explicitly rather than passing through blindly.

class SyscallTranslator {
public:
    // Handle a SVC #0 from guest ARM64 code.
    // Reads X16 (syscall number), X0-X7 (args) from cpu state.
    // Writes result back to X0 (and X1 for 128-bit returns).
    // Returns false when the program should exit.
    bool handle(CpuState& state);

private:
    // Individual syscall implementations
    bool sys_exit(CpuState& state);
    bool sys_write(CpuState& state);
    bool sys_read(CpuState& state);
    bool sys_open(CpuState& state);
    bool sys_close(CpuState& state);
    bool sys_mmap(CpuState& state);
    bool sys_munmap(CpuState& state);
    bool sys_getpid(CpuState& state);

    // Issue a raw macOS x86-64 syscall
    // (only valid when running on x86-64 host)
    int64_t raw_syscall(int64_t num,
                        int64_t a0=0, int64_t a1=0, int64_t a2=0,
                        int64_t a3=0, int64_t a4=0, int64_t a5=0);
};

// ARM64 macOS syscall numbers (partial list, enough for basic programs)
// Source: xnu/bsd/kern/syscalls.master
namespace Arm64Syscall {
    constexpr uint64_t exit    =  1;
    constexpr uint64_t fork    =  2;
    constexpr uint64_t read    =  3;
    constexpr uint64_t write   =  4;
    constexpr uint64_t open    =  5;
    constexpr uint64_t close   =  6;
    constexpr uint64_t getpid  = 20;
    constexpr uint64_t mmap    = 197;
    constexpr uint64_t munmap  = 73;
}
