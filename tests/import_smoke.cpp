// End-to-end imported-symbol test.
//
// Builds a tiny ARM64 MH_EXECUTE that:
//   1. BL's to a stub, which loads an imported function address from a GOT slot
//      and BR's to it;
//   2. receives the value 42 from a host implementation and returns to the caller;
//   3. SVC #0 with x0 = 42 so the test syscall handler can observe it.
// The GOT slot is filled by a real classic LC_DYLD_INFO bind stream through
// DyldLinker, exactly as main.cpp does at startup.

#include "loader/macho_loader.h"
#include "interpreter/interpreter.h"
#include "dylink/dyld_linker.h"
#include "dylib/dylib_interceptor.h"
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

// Minimal interceptor for this isolated test target (mirrors dyld_linker_smoke).
DylibInterceptor& DylibInterceptor::instance() {
    static DylibInterceptor instance;
    return instance;
}
void DylibInterceptor::register_symbol(const std::string& name, HostFn fn) {
    symbols_[name] = std::move(fn);
}
bool DylibInterceptor::has_symbol(const std::string& name) const {
    return symbols_.count(name) != 0;
}
GuestPtr DylibInterceptor::allocate_trampoline(const std::string& name) {
    auto found = name_to_trampoline_.find(name);
    if (found != name_to_trampoline_.end()) return found->second;
    const GuestPtr address = next_trampoline_++;
    name_to_trampoline_[name] = address;
    trampoline_to_name_[address] = name;
    return address;
}
uint64_t DylibInterceptor::dispatch_trampoline(GuestPtr pc, uint64_t* args, int nargs) {
    auto name = trampoline_to_name_.find(pc);
    assert(name != trampoline_to_name_.end());
    auto fn = symbols_.find(name->second);
    assert(fn != symbols_.end());
    return fn->second(args, nargs);
}

namespace {

constexpr uint64_t kVmBase   = 0x100000000ULL; // __TEXT vmaddr
constexpr uint64_t kCode     = 0x200;          // entry (file offset == segment offset)
constexpr uint64_t kStub     = 0x210;          // BL target: load GOT, BR through it
constexpr uint64_t kGotSlot  = 0x300;          // imported pointer, patched by bind
constexpr uint64_t kBindOps  = 0x400;          // classic bind opcode stream
constexpr size_t   kImageLen = 0x1000;
constexpr const char* kImportName = "_reverta_import_answer";
constexpr const char* kDylibPath  = "/usr/lib/libSystem.B.dylib";

void put32(std::vector<uint8_t>& image, size_t off, uint32_t word) {
    std::memcpy(image.data() + off, &word, sizeof(word));
}

std::vector<uint8_t> bind_stream() {
    std::vector<uint8_t> ops;
    ops.push_back(0x11); // BIND_OPCODE_SET_DYLIB_ORDINAL_IMM(1)
    ops.push_back(0x51); // BIND_OPCODE_SET_TYPE_IMM(POINTER)
    ops.push_back(0x40); // BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM(0)
    for (const char* c = kImportName; *c; ++c) ops.push_back(static_cast<uint8_t>(*c));
    ops.push_back(0x00); // NUL terminator for the symbol name
    ops.push_back(0x70); // BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(segment 0)
    ops.push_back(static_cast<uint8_t>(0x80 | (kGotSlot & 0x7F)));  // ULEB128 offset
    ops.push_back(static_cast<uint8_t>(kGotSlot >> 7));
    ops.push_back(0x90); // BIND_OPCODE_DO_BIND
    ops.push_back(0x00); // BIND_OPCODE_DONE
    return ops;
}

std::vector<uint8_t> build_image() {
    const std::vector<uint8_t> binds = bind_stream();
    const size_t dylib_cmd_size = sizeof(dylib_command) + 32; // path padded to 8
    const size_t commands_size = sizeof(segment_command_64) + dylib_cmd_size
        + sizeof(dyld_info_command) + sizeof(entry_point_command);
    assert(sizeof(mach_header_64) + commands_size <= kCode);
    assert(kBindOps + binds.size() <= kImageLen);

    std::vector<uint8_t> image(kImageLen, 0);

    auto* mh = reinterpret_cast<mach_header_64*>(image.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->filetype = MH_EXECUTE;
    mh->flags = MH_PIE;
    mh->ncmds = 4;
    mh->sizeofcmds = static_cast<uint32_t>(commands_size);

    size_t off = sizeof(mach_header_64);

    auto* seg = reinterpret_cast<segment_command_64*>(image.data() + off);
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(segment_command_64);
    std::memcpy(seg->segname, "__TEXT", 6);
    seg->vmaddr = kVmBase;
    seg->vmsize = kImageLen;
    seg->fileoff = 0;
    seg->filesize = kImageLen;
    seg->maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
    seg->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    off += sizeof(segment_command_64);

    auto* dylib = reinterpret_cast<dylib_command*>(image.data() + off);
    dylib->cmd = LC_LOAD_DYLIB;
    dylib->cmdsize = static_cast<uint32_t>(dylib_cmd_size);
    dylib->dylib.name.offset = sizeof(dylib_command);
    std::memcpy(image.data() + off + sizeof(dylib_command), kDylibPath,
                std::strlen(kDylibPath) + 1);
    off += dylib_cmd_size;

    auto* info = reinterpret_cast<dyld_info_command*>(image.data() + off);
    info->cmd = LC_DYLD_INFO_ONLY;
    info->cmdsize = sizeof(dyld_info_command);
    info->bind_off = static_cast<uint32_t>(kBindOps);
    info->bind_size = static_cast<uint32_t>(binds.size());
    off += sizeof(dyld_info_command);

    auto* main_cmd = reinterpret_cast<entry_point_command*>(image.data() + off);
    main_cmd->cmd = LC_MAIN;
    main_cmd->cmdsize = sizeof(entry_point_command);
    main_cmd->entryoff = kCode;

    // Entry: BL stub ; SVC #0
    put32(image, kCode + 0, 0x94000004);     // BL  +0x10 (stub)
    put32(image, kCode + 4, 0xD4000001);     // SVC #0 (exit; x0 = result)

    // Stub: materialize the GOT address, load the bound pointer, branch to it.
    //   MOVZ x17, #2, LSL #32   -> x17 = 0x2_0000_0000 (slid __TEXT base)
    //   ADD  x17, x17, #0x300   -> x17 = GOT slot
    //   LDR  x16, [x17]         -> x16 = trampoline address written by bind
    //   BR   x16
    put32(image, kStub + 0,  0xD2C00051);
    put32(image, kStub + 4,  0x910C0231);
    put32(image, kStub + 8,  0xF9400230);
    put32(image, kStub + 12, 0xD61F0200);

    std::memcpy(image.data() + kBindOps, binds.data(), binds.size());
    return image;
}

} // namespace

int main() {
    // Host implementation for the imported symbol. The import is "_reverta_import_answer";
    // the linker strips the leading underscore when looking up host symbols.
    DylibInterceptor::instance().register_symbol(
        "reverta_import_answer", [](uint64_t*, int) -> uint64_t { return 42; });

    const std::vector<uint8_t> image = build_image();

    char path[] = "/tmp/reverta-import-XXXXXX";
    const int fd = ::mkstemp(path);
    assert(fd >= 0);
    size_t written = 0;
    while (written < image.size()) {
        const ssize_t n = ::write(fd, image.data() + written, image.size() - written);
        assert(n > 0);
        written += static_cast<size_t>(n);
    }
    ::close(fd);

    MachOLoader loader;
    auto loaded = loader.load(path);
    ::unlink(path);
    assert(loaded.has_value());
    assert(loaded->entry_point == 0x200000000ULL + kCode);

    // Same startup order as main.cpp: link, fix up imports, then protect.
    DyldLinker& linker = DyldLinker::instance();
    const bool linked = linker.link(loaded->image_data.data(), loaded->image_data.size(),
                                    loaded->base_address, loaded->dylibs,
                                    loaded->path, loaded->rpaths, loaded->weak_dylibs);
    assert(linked);
    const auto guest_to_host_for_fixup = [&](uint64_t address) -> uint8_t* {
        for (const auto& seg : loaded->segments) {
            const uint64_t base = seg.mapped_vmaddr ? seg.mapped_vmaddr : seg.vmaddr;
            if (!seg.mapped || address < base) continue;
            const uint64_t offset = address - base;
            if (offset <= seg.vmsize && seg.vmsize - offset >= sizeof(uint64_t))
                return seg.mapped + offset;
        }
        return nullptr;
    };
    assert(linker.apply_fixups(loaded->image_data.data(), loaded->image_data.size(),
                               loaded->base_address, guest_to_host_for_fixup));
    assert(loader.finalize_protections(*loaded));

    Interpreter interpreter(*loaded);
    interpreter.set_pc_hook([&](CpuState& state) -> bool {
        auto& di = DylibInterceptor::instance();
        if (!di.is_trampoline(state.pc)) return false;
        const uint64_t return_pc = state.x[30];
        assert(return_pc != 0 && !di.is_trampoline(return_pc));
        state.x[0] = di.dispatch_trampoline(state.pc, state.x, 8);
        state.pc = return_pc;
        return true;
    });

    uint64_t observed_x0 = 0;
    interpreter.set_syscall_handler([&](CpuState& state) {
        observed_x0 = state.x[0];
        return false;
    });
    const RunResult result = interpreter.run();
    assert(result == RunResult::OK);
    assert(observed_x0 == 42);

    // The GOT slot must hold the trampoline the interceptor allocated for the import.
    const uint8_t* got = interpreter.guest_to_host(0x200000000ULL + kGotSlot, 8, GuestAccess::Read);
    assert(got != nullptr);
    uint64_t slot_value = 0;
    std::memcpy(&slot_value, got, sizeof(slot_value));
    assert(slot_value == DylibInterceptor::instance().allocate_trampoline("reverta_import_answer"));

    for (const auto& segment : loaded->segments)
        if (segment.mapped && segment.vmsize)
            ::munmap(segment.mapped, static_cast<size_t>(segment.vmsize));
    if (loaded->stack_base && loaded->stack_size)
        ::munmap(reinterpret_cast<void*>(loaded->stack_base),
                 static_cast<size_t>(loaded->stack_size));
    return 0;
}
