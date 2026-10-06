#include <cstdio>
#include <cstdlib>
#include "loader/macho_loader.h"
#include "interpreter/interpreter.h"
#include "syscall/syscall_translator.h"

static void usage(const char* prog) {
    std::fprintf(stderr, "Usage: %s <arm64-macho-binary> [args...]\n", prog);
    std::fprintf(stderr, "\n");
    std::fprintf(stderr, "  Reverse Rosetta — run ARM64 Mach-O binaries on x86-64 macOS\n");
    std::fprintf(stderr, "  Phase 1: interpreter (static binaries only)\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char* binary_path = argv[1];

    // ── Load the binary ───────────────────────────────────────────────────────
    MachOLoader loader;
    auto maybe_binary = loader.load(binary_path);
    if (!maybe_binary) {
        std::fprintf(stderr, "[rrosetta] Load failed: %s\n", loader.error().c_str());
        return 1;
    }
    LoadedBinary& binary = *maybe_binary;

    std::fprintf(stderr, "[rrosetta] Loaded '%s'\n", binary_path);
    std::fprintf(stderr, "[rrosetta] Entry point: 0x%llx\n",
                 (unsigned long long)binary.entry_point);
    std::fprintf(stderr, "[rrosetta] Segments:\n");
    for (auto& seg : binary.segments) {
        std::fprintf(stderr, "  %-16s vmaddr=0x%llx size=0x%llx\n",
            seg.name.c_str(),
            (unsigned long long)seg.vmaddr,
            (unsigned long long)seg.vmsize);
    }
    if (!binary.dylibs.empty()) {
        std::fprintf(stderr, "[rrosetta] NOTE: Binary requires %zu dylib(s) — dynamic linking not yet supported\n",
                     binary.dylibs.size());
        for (auto& d : binary.dylibs)
            std::fprintf(stderr, "  %s\n", d.c_str());
    }

    // ── Set up interpreter + syscall handler ──────────────────────────────────
    Interpreter interp(binary);
    SyscallTranslator syscalls;

    interp.set_syscall_handler([&](CpuState& state) -> bool {
        return syscalls.handle(state);
    });

    // ── Run ───────────────────────────────────────────────────────────────────
    std::fprintf(stderr, "[rrosetta] Starting execution at 0x%llx\n",
                 (unsigned long long)binary.entry_point);

    RunResult result = interp.run();

    switch (result) {
    case RunResult::OK:
        std::fprintf(stderr, "[rrosetta] Clean exit\n");
        return 0;
    case RunResult::UNSUPPORTED:
        std::fprintf(stderr, "[rrosetta] Hit unsupported instruction\n");
        return 2;
    case RunResult::FAULT:
        std::fprintf(stderr, "[rrosetta] Memory fault\n");
        return 3;
    case RunResult::SYSCALL:
    case RunResult::ERROR:
        std::fprintf(stderr, "[rrosetta] Error\n");
        return 4;
    }
    return 0;
}
