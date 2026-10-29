#!/usr/bin/env python3
"""Differential test: Reverta's interpreter versus Unicorn (an independent
AArch64 emulator) on random single instructions.

Usage: diff_oracle.py <diff_runner> [cases] [seed] [--show N]

Each case starts both engines from the same register, flag, SIMD and
data-page state, executes one instruction, and compares X0-X30, SP, NZCV,
D0-D31 (low halves) and a 512-byte window of the data page. NaN results are
compared as NaNs, since their payloads are not specified exactly.

Cases the decoder does not model ("U") are skipped; encodings Unicorn executes
that Reverta does not model are reported as the coverage gap list. An
instruction Reverta refuses but Unicorn executes counts as refused. Exit status
is nonzero on any mismatch or refusal.

Known oracle limitation: Unicorn executes a few reserved encodings (for example
SMULH/UMULH with Ra != 31) that the architecture leaves undefined. Those appear
in the gap list and are not real gaps.
"""
import os
import random
import shutil
import struct
import subprocess
import sys

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL, UcError
    from unicorn.arm64_const import UC_ARM64_REG_NZCV, UC_ARM64_REG_PC, UC_ARM64_REG_SP
    from unicorn import arm64_const
except ImportError:
    print("SKIP: the 'unicorn' Python package is not installed")
    sys.exit(77)

CODE_ADDR = 0x1000
DATA_ADDR = 0x20000
DATA_SIZE = 0x10000
BASE = 0x20800                  # value given to base registers of memory operations
WINDOW_START = BASE - 256       # compared window: 512 bytes around BASE
WINDOW_SIZE = 512

# Values that exercise boundaries: zero, sign bits, width edges, shift limits.
SPECIAL = [
    0, 1, 2, 3, 0x1F, 0x20, 0x3F, 0x40, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x100000000,
    0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF,
]
XREGS = [getattr(arm64_const, "UC_ARM64_REG_X%d" % i) for i in range(31)]
QREGS = [getattr(arm64_const, "UC_ARM64_REG_Q%d" % i) for i in range(32)]
MASK64 = (1 << 64) - 1
# Same fill as the C++ runner: byte i is ((i * 2654435761) mod 2^32) >> 13.
PATTERN = bytes((((i * 2654435761) & 0xFFFFFFFF) >> 13) & 0xFF for i in range(DATA_SIZE))


def random_value(rng):
    if rng.random() < 0.35:
        return rng.choice(SPECIAL)
    return rng.getrandbits(64)


def is_unpredictable(word):
    """Pair loads with Rt == Rt2, or Rt == Rn with writeback, are constrained
    unpredictable; neither engine's choice is specified, so they are not compared."""
    if ((word >> 27) & 7) != 0b101 or not (word >> 22) & 1:
        return False
    rt = word & 31
    if rt == 31:
        return False
    if rt == (word >> 10) & 31:
        return True
    return ((word >> 23) & 7) in (0b001, 0b011) and rt == (word >> 5) & 31


def random_fp_bits(rng):
    """V-register low 64 bits that read as finite values both as a double
    (bits 62:52) and as a float (bits 30:23 of the low word)."""
    v = rng.getrandbits(64)
    if ((v >> 52) & 0x7FF) == 0x7FF:
        v &= ~(1 << 52)
    if ((v >> 23) & 0xFF) == 0xFF:
        v &= ~(1 << 23)
    return v


def set_op0(word, top):
    """Place a 4-bit op0 field in bits 28:25."""
    return (word & ~(0xF << 25)) | (top << 25)


def random_word(rng):
    w = rng.getrandbits(32)
    kind = rng.random()
    if kind < 0.25:
        # Single or pair load/store: op0 = x1x0.
        return set_op0(w, rng.choice([0b0100, 0b0110, 0b1100, 0b1110]))
    if kind < 0.40:
        # Scalar three-source floating point: 0 00 11111 ...
        return (w & ~0xFF000000) | 0x1F000000
    if kind < 0.70:
        # Data processing, immediate: op0 = 100x.
        return set_op0(w, 0b1000 | rng.getrandbits(1))
    # Data processing, register: op0 = x101.
    return set_op0(w, 0b0101 | (rng.getrandbits(1) << 3))


def is_memory_word(word):
    return ((word >> 25) & 0xF) in (0b0100, 0b0110, 0b1100, 0b1110)


CLREX = 0xD503305F   # clears the exclusive monitor, which Unicorn keeps across runs


def unicorn_run(uc, word, sp, nzcv, xs, lo, hi):
    uc.mem_write(DATA_ADDR, PATTERN)
    # Start every case with no exclusive monitor, as the interpreter does.
    uc.mem_write(CODE_ADDR, struct.pack("<I", CLREX))
    uc.emu_start(CODE_ADDR, CODE_ADDR + 4, count=1)
    uc.mem_write(CODE_ADDR, struct.pack("<I", word))
    for i, v in enumerate(xs):
        uc.reg_write(XREGS[i], v)
    for i in range(32):
        # Whole 128-bit V register: scalar writes must clear the high half.
        uc.reg_write(QREGS[i], (hi[i] << 64) | lo[i])
    uc.reg_write(UC_ARM64_REG_SP, sp)
    uc.reg_write(UC_ARM64_REG_NZCV, nzcv << 28)
    uc.reg_write(UC_ARM64_REG_PC, CODE_ADDR)
    uc.emu_start(CODE_ADDR, CODE_ADDR + 4, count=1)
    flags = uc.reg_read(UC_ARM64_REG_NZCV) >> 28
    window = bytes(uc.mem_read(WINDOW_START, WINDOW_SIZE))
    q = [uc.reg_read(r) for r in QREGS]
    return (uc.reg_read(UC_ARM64_REG_SP),
            flags,
            [uc.reg_read(r) for r in XREGS],
            [v & MASK64 for v in q],
            [v >> 64 for v in q],
            window)


def is_nan_bits(v):
    """True if the low 64 bits are a NaN as a double, or the low 32 bits one as a float."""
    if ((v >> 52) & 0x7FF) == 0x7FF and (v & ((1 << 52) - 1)):
        return True
    lo = v & 0xFFFFFFFF
    return ((lo >> 23) & 0xFF) == 0xFF and (lo & 0x7FFFFF) != 0


def same_d(a, b):
    # NaN payloads and signs are not specified precisely enough to compare exactly.
    return a == b or (is_nan_bits(a) and is_nan_bits(b))


def disassemble_batch(words):
    """Mnemonic of each word, using one llvm-mc invocation for the whole batch."""
    llvm_mc = shutil.which("llvm-mc")
    if not llvm_mc or not words:
        return ["?"] * len(words)
    data = "\n".join(" ".join("0x%02x" % b for b in struct.pack("<I", w)) for w in words)
    try:
        out = subprocess.run([llvm_mc, "--disassemble", "-triple=arm64-apple-macos"],
                             input=data, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return ["?"] * len(words)
    names = []
    for line in out.stdout.splitlines():
        t = line.strip()
        if t and not t.startswith("."):
            names.append(t.split()[0])
    names = names[:len(words)]
    return names + ["?"] * (len(words) - len(names))


def disassemble(word):
    return disassemble_batch([word])[0]


def main():
    args = sys.argv[1:]
    show = 10
    if "--show" in args:
        i = args.index("--show")
        show = int(args[i + 1])
        del args[i:i + 2]
    runner = args[0]
    cases = int(args[1]) if len(args) > 1 else 20000
    seed = int(args[2]) if len(args) > 2 else 1
    rng = random.Random(seed)

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(CODE_ADDR, 0x1000, UC_PROT_ALL)
    uc.mem_map(DATA_ADDR, DATA_SIZE, UC_PROT_ALL)

    cases_data = []
    lines = []
    for _ in range(cases):
        word = random_word(rng)
        while is_unpredictable(word):
            word = random_word(rng)
        sp = rng.choice(SPECIAL) if rng.random() < 0.35 else rng.getrandbits(64)
        nzcv = rng.getrandbits(4)
        xs = [random_value(rng) for _ in range(31)]
        ds = [random_fp_bits(rng) for _ in range(32)]          # low halves
        hs = [rng.getrandbits(64) for _ in range(32)]          # high halves
        if is_memory_word(word):
            # Point the base register at the data page so the access is valid.
            rn = (word >> 5) & 31
            if rn == 31:
                sp = BASE
            else:
                xs[rn] = BASE
        cases_data.append((word, sp, nzcv, xs, ds, hs))
        lines.append("%08x %x %x %s %s %s" % (word, sp, nzcv,
                                             " ".join("%x" % v for v in xs),
                                             " ".join("%x" % v for v in ds),
                                             " ".join("%x" % v for v in hs)))

    proc = subprocess.run([runner], input="\n".join(lines) + "\n",
                          capture_output=True, text=True, timeout=900)
    out_lines = proc.stdout.splitlines()
    if len(out_lines) != cases:
        print("runner produced %d lines for %d cases" % (len(out_lines), cases))
        print(proc.stderr[-2000:])
        return 1

    compared = skipped_unknown = skipped_undefined = refused = mismatches = 0
    by_op = {}
    gap_words = []
    shown = 0
    for (word, sp, nzcv, xs, ds, hs), out in zip(cases_data, out_lines):
        if out == "U":
            skipped_unknown += 1
            try:
                unicorn_run(uc, word, sp, nzcv, xs, ds, hs)
            except UcError:
                continue
            gap_words.append(word)
            continue
        if out == "R":
            # Decoded but refused. If Unicorn cannot execute it either, the case
            # is undefined or faults on both sides; otherwise it is a refusal.
            try:
                unicorn_run(uc, word, sp, nzcv, xs, ds, hs)
            except UcError:
                skipped_undefined += 1
                continue
            refused += 1
            if shown < show:
                shown += 1
                print("REFUSED %08x  %s" % (word, disassemble(word)))
            continue
        try:
            u_sp, u_nzcv, u_xs, u_lo, u_hi, u_win = unicorn_run(uc, word, sp, nzcv, xs, ds, hs)
        except UcError:
            # Unicorn rejects the encoding or the access; not a comparable result.
            skipped_undefined += 1
            continue
        parts = out.split()
        name = parts[0]
        r_sp = int(parts[1], 16)
        r_nzcv = int(parts[2], 16)
        r_xs = [int(v, 16) for v in parts[3:34]]
        r_lo = [int(v, 16) for v in parts[34:66]]
        r_hi = [int(v, 16) for v in parts[66:98]]
        r_win = bytes.fromhex(parts[98]) if len(parts) > 98 else b""
        compared += 1
        by_op[name] = by_op.get(name, 0) + 1
        d_bad = (any(not same_d(a, b) for a, b in zip(r_lo, u_lo))
                 or r_hi != u_hi)
        bad = (r_sp != u_sp or r_nzcv != u_nzcv or r_xs != u_xs
               or d_bad or r_win != u_win)
        if bad:
            mismatches += 1
            if shown < show:
                shown += 1
                print("MISMATCH %08x %-18s %s" % (word, name, disassemble(word)))
                print("   input  sp=%x nzcv=%x" % (sp, nzcv))
                print("   reverta sp=%x nzcv=%x" % (r_sp, r_nzcv))
                print("   unicorn sp=%x nzcv=%x" % (u_sp, u_nzcv))
                for i in range(31):
                    if r_xs[i] != u_xs[i]:
                        print("   x%d: reverta=%x unicorn=%x (in x%d=%x)"
                              % (i, r_xs[i], u_xs[i], i, xs[i]))
                        break
                for i in range(32):
                    if not same_d(r_lo[i], u_lo[i]) or r_hi[i] != u_hi[i]:
                        print("   v%d: reverta=%x:%x unicorn=%x:%x"
                              % (i, r_hi[i], r_lo[i], u_hi[i], u_lo[i]))
                        break
                if r_win != u_win:
                    j = next(k for k in range(WINDOW_SIZE) if r_win[k] != u_win[k])
                    print("   memory at %x: reverta=%02x unicorn=%02x"
                          % (WINDOW_START + j, r_win[j], u_win[j]))

    print("cases=%d compared=%d mismatches=%d refused=%d undecoded=%d unicorn_undefined=%d"
          % (cases, compared, mismatches, refused, skipped_unknown, skipped_undefined))
    if gap_words:
        names = disassemble_batch(gap_words[:4000])
        gaps = {}
        for name in names:
            gaps[name] = gaps.get(name, 0) + 1
        print("valid on hardware but not modelled: %d cases (sampled %d)"
              % (len(gap_words), min(len(gap_words), 4000)))
        for name, n in sorted(gaps.items(), key=lambda kv: -kv[1])[:20]:
            print("  %-16s %d" % (name, n))
    if os.environ.get("DIFF_ORACLE_OPS"):
        for name in sorted(by_op):
            print("  %-12s %d" % (name, by_op[name]))
    return 1 if (mismatches or refused) else 0


if __name__ == "__main__":
    sys.exit(main())
