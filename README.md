# Reverse Rosetta

Run ARM64 Mach-O binaries on x86-64 macOS (macOS 12+).  
The opposite of Apple's Rosetta 2.

## Status — Phase 1 (interpreter)

- [x] ARM64 Mach-O loader (static binaries, fat binaries)
- [x] AArch64 instruction decoder (core integer subset)
- [x] Interpreter (branches, load/store, data processing, flags)
- [x] Syscall translation layer (exit, read, write, open, close, mmap, getpid)
- [ ] Dynamic linker / dylib support
- [ ] Full NEON / SIMD
- [ ] JIT compiler (Phase 2)
- [ ] Objective-C / Swift runtime bridges (Phase 3)

## Build

Requires macOS 12+, Xcode Command Line Tools, CMake 3.20+.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

To run a static ARM64 binary:

```bash
./build/rrosetta /path/to/arm64-binary
```

> **Note:** The binary must be signed with the `com.apple.security.cs.allow-jit`
> entitlement for JIT memory to work in Phase 2. For Phase 1 (interpreter),
> no special signing is required.

## Architecture

```
arm64 Mach-O
     │
     ▼
┌─────────────┐
│ MachO Loader│  parse + mmap segments into host address space
└─────┬───────┘
      │
      ▼
┌─────────────┐
│Arm64 Decoder│  decode 4-byte AArch64 instructions → Arm64Insn
└─────┬───────┘
      │
      ▼
┌─────────────┐
│ Interpreter │  execute Arm64Insn, maintain CpuState
└─────┬───────┘
      │ SVC
      ▼
┌──────────────────┐
│ SyscallTranslator│  ARM64 macOS syscall → x86-64 macOS libc call
└──────────────────┘
```

## Roadmap to "all apps"

1. **Phase 1 (now):** Interpreter, static binaries, core syscalls
2. **Phase 2:** JIT — translate ARM64 basic blocks to x86-64, block cache
3. **Phase 3:** Dynamic linker — load + translate ARM64 dylibs on demand
4. **Phase 4:** SIMD — full NEON → SSE/AVX mapping
5. **Phase 5:** ObjC/Swift — runtime ABI bridges
