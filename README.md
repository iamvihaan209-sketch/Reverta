# Reverta

Run ARM64 Mach-O binaries on x86-64 macOS (macOS 12+).  
The opposite of Apple's Rosetta 2.

## Status

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | ARM64 Mach-O loader (static + fat binaries) | ✅ |
| 1 | AArch64 instruction decoder (expanded: shifts, conditional select, multiply) | ✅ |
| 1 | Interpreter (partial branches/load-store/integer semantics; full instruction coverage pending) | 🟡 |
| 1 | Syscall translation (exit, read, write, open, mmap, ...) | ✅ |
| 2 | JIT compiler (basic blocks: MOV, ADD/SUB, logic, shifts, CSEL, MUL) | ✅ |
| 4 | NEON/SIMD (extended: compare, min/max, saturating arith) | ✅ |
| 5 | ObjC runtime bridge (objc_msgSend, alloc/init, retain/release) | ✅ |
| 5 | Swift runtime bridge (alloc, retain/release, stdlib stubs) | ✅ |
| 5 | Foundation / CoreFoundation stubs (CFString, CFData, CFArray, ...) | ✅ |
| 5 | AppKit stubs (NSApplication, NSWindow, NSView, NSAlert) | ✅ |
| 5 | Dylib interceptor (routes ARM64 dylib calls to host stubs) | ✅ |
| 3 | Dynamic linker (classic binds/rebases, selected chained formats, exports, absolute/@rpath and nested dylib loading) | 🟡 |
| 0.7 | Scalar FP subset (arithmetic, compare, FABS/FNEG, FCVT, FMOV, S/D loads/stores) | 🟡 |

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
- **v0.5.0-beta** — Stabilized JIT (shifts, CSEL, multiply variants), extended NEON (compare, saturating ops)
- **v0.6** — Full dynamic linker: load + translate ARM64 dylibs on demand (in progress; classic binds/rebases, selected chained formats, exports and limited absolute/@rpath bundled dylib loading are integrated; system libraries still use stubs)  
- **v0.7** — Floating-point ops (FADD, FCMP, FMOV; scalar arithmetic, compares, FABS/FNEG, FCVT, FCSEL, FP memory ops, immediate moves and FP/GPR transfers implemented with smoke tests)
- **v1.0** — Real apps running end-to-end

## Contributors

- **Vihaan** — project owner and direction
- **Claude Sonnet 4.6** — implementation and coding
- **ChatGPT (GPT-6)** — project planning, architecture discussion, code review, and development guidance

> **Note for Claude:** ChatGPT has also participated in Reverta's development through architecture planning, technical review, and guidance alongside the implementation work.
