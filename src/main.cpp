#include <cstdio>
#include <cstdlib>
#include "loader/macho_loader.h"
#include "interpreter/interpreter.h"
#include "syscall/syscall_translator.h"
#include "dylib/dylib_interceptor.h"
#include "dylink/dyld_linker.h"

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

    // ── Link imports before restoring segment protections ──────────────────────
    DyldLinker& linker = DyldLinker::instance();
    if (!linker.link(binary.image_data.data(), binary.image_data.size(),
                     binary.base_address, binary.dylibs,
                     binary.path, binary.rpaths, binary.weak_dylibs)) {
        std::fprintf(stderr, "[reverta] Dynamic dependency loading failed; see dyld diagnostics above\n");
        return 1;
    }
    const auto guest_to_host_for_fixup = [&](uint64_t address) -> uint8_t* {
        for (const auto& seg : binary.segments) {
            const uint64_t base = seg.mapped_vmaddr ? seg.mapped_vmaddr : seg.vmaddr;
            if (!seg.mapped || address < base) continue;
            const uint64_t offset = address - base;
            if (offset <= seg.vmsize && seg.vmsize - offset >= sizeof(uint64_t))
                return seg.mapped + offset;
        }
        return nullptr;
    };
    if (!linker.apply_fixups(binary.image_data.data(), binary.image_data.size(),
                             binary.base_address, guest_to_host_for_fixup)) {
        std::fprintf(stderr, "[reverta] Import fixups failed or use an unsupported format\n");
        return 1;
    }
    if (!loader.finalize_protections(binary)) {
        std::fprintf(stderr, "[reverta] Protection setup failed: %s\n", loader.error().c_str());
        return 1;
    }

    // ── Set up interpreter ────────────────────────────────────────────────────
    Interpreter interp(binary);
    SyscallTranslator syscalls(
        [&](uint64_t address, size_t size, GuestAccess access) { return interp.guest_to_host(address, size, access); },
        [&](uint64_t address, size_t size, int prot, int flags, int fd, int64_t offset) {
            return interp.mmap_guest(address, size, prot, flags, fd, offset);
        },
        [&](uint64_t address, size_t size) { return interp.munmap_guest(address, size); });
    DylibInterceptor& dylib = DylibInterceptor::instance();

    interp.set_syscall_handler([&](CpuState& state) -> bool {
        return syscalls.handle(state);
    });

    // Imported symbols resolve to trampoline addresses (not mapped memory).
    // A guest BL/BR to one runs the host implementation and returns to LR,
    // exactly as a call to a real dylib function would.
    interp.set_pc_hook([&](CpuState& state) -> bool {
        if (!dylib.is_trampoline(state.pc)) return false;
        const GuestPtr return_pc = state.x[30];
        if (return_pc == 0 || dylib.is_trampoline(return_pc)) return false;
        state.x[0] = dylib.dispatch_trampoline(state.pc, state.x, 8);
        state.pc = return_pc;
        return true;
    });

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
