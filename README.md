# Reverta

Run ARM64 Mach-O binaries on x86-64 macOS (macOS 12+).  
The opposite of Apple's Rosetta 2.

## Status

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | ARM64 Mach-O loader (static + fat binaries) | ✅ |
| 1 | AArch64 instruction decoder (core integer subset) | ✅ |
| 1 | Interpreter (branches, load/store, data processing, flags) | ✅ |
| 1 | Syscall translation (exit, read, write, open, mmap, ...) | ✅ |
| 5 | ObjC runtime bridge (objc_msgSend, alloc/init, retain/release) | ✅ |
| 5 | Swift runtime bridge (alloc, retain/release, stdlib stubs) | ✅ |
| 5 | Foundation / CoreFoundation stubs (CFString, CFData, CFArray, ...) | ✅ |
| 5 | AppKit stubs (NSApplication, NSWindow, NSView, NSAlert) | ✅ |
| 5 | Dylib interceptor (routes ARM64 dylib calls to host stubs) | ✅ |
| 2 | JIT compiler | 🔲 |
| 3 | Dynamic linker (full ARM64 dylib loading) | 🔲 |
| 4 | Full NEON / SIMD | 🔲 |

## Build

Requires macOS 12+, Xcode Command Line Tools, CMake 3.20+.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(sysctl -n hw.logicalcpu)
```

## Usage

```bash
./build/reverta /path/to/arm64-binary [args...]
```

## Architecture

```
ARM64 Mach-O binary
        │
        ▼
┌───────────────┐
│  MachO Loader │  parse segments, map into host address space
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Arm64 Decoder │  decode 4-byte AArch64 instructions → Arm64Insn
└───────┬───────┘
        │
        ▼
┌───────────────┐
│  Interpreter  │  execute Arm64Insn, maintain CpuState (x0-x30, sp, pc, NZCV)
└───────┬───────┘
        │
     SVC #0           SVC #0xAB
        │                  │
        ▼                  ▼
┌──────────────┐   ┌──────────────────┐
│   Syscall    │   │ Dylib Interceptor│
│  Translator  │   │                  │
│  (exit/read/ │   │  ObjC Runtime    │
│   write/mmap)│   │  Swift Runtime   │
│              │   │  Foundation/CF   │
│              │   │  AppKit stubs    │
│              │   │  POSIX stubs     │
└──────────────┘   └──────────────────┘
```

## Roadmap

- **v0.3** — JIT: translate ARM64 basic blocks → native x86-64, block cache
- **v0.4** — Full dynamic linker: load + translate ARM64 dylibs on demand  
- **v0.5** — Full NEON → SSE/AVX mapping
- **v1.0** — Real apps running end-to-end
