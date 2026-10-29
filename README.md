# Reverta

Run ARM64 Mach-O binaries on x86-64 macOS (macOS 12+).  
The opposite of Apple's Rosetta 2.

## Status

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | ARM64 Mach-O loader (static + fat binaries) | ✅ |
| 1 | AArch64 instruction decoder: integer data processing (incl. bitfields, logical immediates, extended/shifted operands, conditional compare, divide, multiply-add, CRC32, bit/byte ops), scalar FP incl. fused multiply-add, loads/stores (pairs, literal, register offset, exclusives, LSE atomics, SIMD&FP scalar and pair). Checked against Unicorn by `reverta_diff_oracle`. NEON structure loads (LD1–LD4/ST1–ST4) and most Advanced SIMD are not yet modelled. | 🟡 |
| 1 | Interpreter (integer, scalar FP and memory semantics verified against an independent emulator; Advanced SIMD pending) | 🟡 |
| 1 | Syscall translation (exit, read, write, open, mmap, ...) | ✅ |
| 2 | JIT compiler (basic blocks: MOV, ADD/SUB, logic, shifts, CSEL, MUL) | ✅ |
| 4 | NEON/SIMD (extended: compare, min/max, saturating arith) | ✅ |
| 5 | ObjC runtime bridge (objc_msgSend, alloc/init, retain/release) | ✅ |
| 5 | Swift runtime bridge (alloc, retain/release, stdlib stubs) | ✅ |
| 5 | Foundation / CoreFoundation stubs (CFString, CFData, CFArray, ...) | ✅ |
| 5 | AppKit stubs (NSApplication, NSWindow, NSView, NSAlert) | ✅ |
| 5 | Dylib interceptor (routes ARM64 dylib calls to host stubs) | ✅ |
| 3 | Dynamic linker (classic binds/rebases, selected chained formats, exports, absolute/@rpath and nested dylib loading) | 🟡 |
| 3 | Imported-symbol calls: guest BL/BR to a bound import runs the host implementation and returns (`reverta_import_smoke`) | ✅ |
| 0.7 | Scalar FP subset (arithmetic, compare, FABS/FNEG, FCVT, FMOV, S/D loads/stores) | 🟡 |

## Build

Requires macOS 12+, Xcode Command Line Tools, CMake 3.20+.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(sysctl -n hw.logicalcpu)
```

## Verification

`reverta_diff_oracle` runs random single instructions through the interpreter and through Unicorn, an independent AArch64 emulator, and compares X registers, SP, NZCV, the full V registers and a window of data memory. It runs under `ctest` when the Python `unicorn` package is installed (`pip install unicorn`) and is skipped otherwise. Instructions the decoder does not model are reported as a coverage gap list.

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
     SVC #0      branch to trampoline
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
- **v0.6** — Full dynamic linker: load + translate ARM64 dylibs on demand. Gate met: a real ARM64 executable calls an imported symbol through the GOT and trampoline and returns (CI-verified). Still open: weak/re-export semantics, full chained formats, shared-cache layouts, symbol versioning, and loading real framework binaries (bundled synthetic dylibs are tested; system libraries use host stubs)
- **v0.7** — Floating-point ops (FADD, FCMP, FMOV; scalar arithmetic, compares, FABS/FNEG, FCVT, FCSEL, FP memory ops, immediate moves and FP/GPR transfers implemented with smoke tests)
- **v1.0** — Real apps running end-to-end

## Contributors

- **Vihaan** — project owner and direction
- **Claude Sonnet 4.6** — implementation and coding
- **ChatGPT (GPT-6)** — project planning, architecture discussion, code review, and development guidance

> **Note for Claude:** ChatGPT has also participated in Reverta's development through architecture planning, technical review, and guidance alongside the implementation work.
