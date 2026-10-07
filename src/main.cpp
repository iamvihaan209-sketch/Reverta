#include <cstdio>
#include <cstdlib>
#include "loader/macho_loader.h"
#include "interpreter/interpreter.h"
#include "syscall/syscall_translator.h"
#include "dylib/dylib_interceptor.h"

static void usage(const char* prog) {
    std::fprintf(stderr, "Usage: %s <arm64-macho-binary> [args...]\n\n", prog);
    std::fprintf(stderr, "  Reverta — run ARM64 Mach-O binaries on x86-64 macOS\n");
    std::fprintf(stderr, "  Supports: static + dynamic binaries, ObjC, Swift, Foundation, AppKit\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    const char* binary_path = argv[1];

    // ── Install all runtime stubs ─────────────────────────────────────────────
    DylibInterceptor::instance().install_all();

    // ── Load the binary ───────────────────────────────────────────────────────
    MachOLoader loader;
    auto maybe_binary = loader.load(binary_path);
    if (!maybe_binary) {
        std::fprintf(stderr, "[reverta] Load failed: %s\n", loader.error().c_str());
        return 1;
    }
    LoadedBinary& binary = *maybe_binary;

    std::fprintf(stderr, "[reverta] Loaded '%s'\n", binary_path);
    std::fprintf(stderr, "[reverta] Entry: 0x%llx\n",
                 (unsigned long long)binary.entry_point);
    std::fprintf(stderr, "[reverta] Segments:\n");
    for (auto& seg : binary.segments)
        std::fprintf(stderr, "  %-16s 0x%llx  size=0x%llx\n",
            seg.name.c_str(),
            (unsigned long long)seg.vmaddr,
            (unsigned long long)seg.vmsize);

    if (!binary.dylibs.empty()) {
        std::fprintf(stderr, "[reverta] Dylibs (intercepted via stubs):\n");
        for (auto& d : binary.dylibs)
            std::fprintf(stderr, "  %s\n", d.c_str());
    }

    // ── Set up interpreter ────────────────────────────────────────────────────
    Interpreter interp(binary);
    SyscallTranslator syscalls;
    DylibInterceptor& dylib = DylibInterceptor::instance();

    interp.set_syscall_handler([&](CpuState& state) -> bool {
        // SVC #0    → normal syscall (exit, read, write, mmap, ...)
        // SVC #0xAB → dylib trampoline dispatch
        uint32_t* pc = reinterpret_cast<uint32_t*>(
            interp.guest_to_host(state.pc - 4));
        uint32_t svc_imm = pc ? ((*pc >> 5) & 0xFFFF) : 0;

        if (svc_imm == 0xAB) {
            // Dylib trampoline: x15 = trampoline PC (set by allocate_trampoline)
            GuestPtr trampoline_pc = state.x[15];
            uint64_t result = dylib.dispatch_trampoline(trampoline_pc, state.x, 8);
            state.x[0] = result;
            return true;
        }
        return syscalls.handle(state);
    });

    // ── Patch dylib stubs into the binary's __got / __stubs ──────────────────
    // For every imported symbol the loader found, replace its stub with
    // a trampoline address so the interpreter routes to our HostFn
    for (auto& d : binary.dylibs) {
        (void)d; // TODO: walk LC_DYLD_INFO to patch individual symbols
    }

    // ── Run ───────────────────────────────────────────────────────────────────
    std::fprintf(stderr, "[reverta] Starting at 0x%llx\n",
                 (unsigned long long)binary.entry_point);

    RunResult result = interp.run();
    switch (result) {
    case RunResult::OK:          return 0;
    case RunResult::UNSUPPORTED:
        std::fprintf(stderr, "[reverta] Unsupported instruction\n"); return 2;
    case RunResult::FAULT:
        std::fprintf(stderr, "[reverta] Memory fault\n"); return 3;
    default:
        std::fprintf(stderr, "[reverta] Error\n"); return 4;
    }
}
