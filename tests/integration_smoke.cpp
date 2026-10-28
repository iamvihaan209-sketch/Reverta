#include "loader/macho_loader.h"
#include "interpreter/interpreter.h"
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
    const size_t command_bytes = sizeof(segment_command_64) + sizeof(entry_point_command);
    const size_t entry_offset = sizeof(mach_header_64) + command_bytes;
    std::vector<uint8_t> image(entry_offset + 8, 0);

    auto* mh = reinterpret_cast<mach_header_64*>(image.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->filetype = MH_EXECUTE;
    mh->flags = MH_PIE;
    mh->ncmds = 2;
    mh->sizeofcmds = static_cast<uint32_t>(command_bytes);

    auto* text = reinterpret_cast<segment_command_64*>(
        image.data() + sizeof(mach_header_64));
    text->cmd = LC_SEGMENT_64;
    text->cmdsize = sizeof(segment_command_64);
    std::memcpy(text->segname, "__TEXT", 6);
    text->vmaddr = 0x100000000ULL;
    text->vmsize = 0x1000;
    text->fileoff = 0;
    text->filesize = image.size();
    text->maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
    text->initprot = VM_PROT_READ | VM_PROT_EXECUTE;

    auto* main = reinterpret_cast<entry_point_command*>(
        image.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    main->cmd = LC_MAIN;
    main->cmdsize = sizeof(entry_point_command);
    main->entryoff = entry_offset;

    // mov x0, #42 ; svc #0 — the test syscall handler observes X0 and exits.
    const uint32_t mov_x0_42 = 0xD2800540;
    const uint32_t svc_zero = 0xD4000001;
    std::memcpy(image.data() + entry_offset, &mov_x0_42, sizeof(mov_x0_42));
    std::memcpy(image.data() + entry_offset + 4, &svc_zero, sizeof(svc_zero));

    char path[] = "/tmp/reverta-integration-XXXXXX";
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
    assert(loaded->entry_point == 0x200000000ULL + entry_offset);
    assert(loader.finalize_protections(*loaded));

    Interpreter interpreter(*loaded);
    uint64_t observed_x0 = 0;
    interpreter.set_syscall_handler([&](CpuState& state) {
        observed_x0 = state.x[0];
        return false;
    });
    const RunResult result = interpreter.run();
    assert(result == RunResult::OK);
    assert(observed_x0 == 42);

    const int64_t guest_map = interpreter.mmap_guest(
        0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(guest_map > 0);
    uint8_t* mapped = interpreter.guest_to_host(static_cast<uint64_t>(guest_map), 16);
    assert(mapped != nullptr);
    mapped[0] = 0x5a;
    assert(interpreter.guest_to_host(static_cast<uint64_t>(guest_map) + 4095, 2) == nullptr);
    assert(interpreter.munmap_guest(static_cast<uint64_t>(guest_map), 4096) == 0);
    assert(interpreter.guest_to_host(static_cast<uint64_t>(guest_map), 1) == nullptr);

    for (const auto& segment : loaded->segments)
        if (segment.mapped && segment.vmsize)
            ::munmap(segment.mapped, static_cast<size_t>(segment.vmsize));
    if (loaded->stack_base && loaded->stack_size)
        ::munmap(reinterpret_cast<void*>(loaded->stack_base),
                 static_cast<size_t>(loaded->stack_size));
    return 0;
}
