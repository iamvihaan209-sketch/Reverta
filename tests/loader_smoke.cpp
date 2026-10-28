#include "loader/macho_loader.h"
#include <mach-o/loader.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

static bool loader_rejects(const std::vector<uint8_t>& bytes) {
    char path[] = "/tmp/reverta-loader-test-XXXXXX";
    const int fd = ::mkstemp(path);
    if (fd < 0) return false;
    size_t written = 0;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
        if (n <= 0) { ::close(fd); ::unlink(path); return false; }
        written += static_cast<size_t>(n);
    }
    ::close(fd);
    MachOLoader loader;
    const bool rejected = !loader.load(path).has_value();
    ::unlink(path);
    return rejected;
}

int main() {
    assert(loader_rejects({0x4d, 0x5a, 0x00, 0x00}));

    std::vector<uint8_t> malformed(sizeof(mach_header_64) + sizeof(load_command), 0);
    auto* mh = reinterpret_cast<mach_header_64*>(malformed.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->ncmds = 1;
    mh->sizeofcmds = sizeof(load_command);
    auto* lc = reinterpret_cast<load_command*>(malformed.data() + sizeof(mach_header_64));
    lc->cmd = LC_SEGMENT_64;
    lc->cmdsize = 4; // smaller than even load_command
    assert(loader_rejects(malformed));

    // A dylib has no executable entry point, but should load its segments and runpaths.
    const std::string rpath = "@loader_path/Frameworks";
    const size_t rpath_cmd_size = (sizeof(rpath_command) + rpath.size() + 1 + 7) & ~size_t{7};
    const size_t command_size = sizeof(segment_command_64) + rpath_cmd_size;
    std::vector<uint8_t> dylib(sizeof(mach_header_64) + command_size, 0);
    auto* dh = reinterpret_cast<mach_header_64*>(dylib.data());
    dh->magic = MH_MAGIC_64;
    dh->cputype = CPU_TYPE_ARM64;
    dh->filetype = MH_DYLIB;
    dh->ncmds = 2;
    dh->sizeofcmds = static_cast<uint32_t>(command_size);
    auto* seg = reinterpret_cast<segment_command_64*>(dylib.data() + sizeof(mach_header_64));
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(segment_command_64);
    std::memcpy(seg->segname, "__TEXT", 6);
    seg->vmaddr = 0x100000000ULL;
    seg->vmsize = 0x1000;
    auto* rp = reinterpret_cast<rpath_command*>(
        dylib.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    rp->cmd = LC_RPATH;
    rp->cmdsize = static_cast<uint32_t>(rpath_cmd_size);
    rp->path.offset = sizeof(rpath_command);
    std::memcpy(reinterpret_cast<uint8_t*>(rp) + rp->path.offset,
                rpath.c_str(), rpath.size() + 1);
    char path[] = "/tmp/reverta-dylib-test-XXXXXX";
    const int fd = ::mkstemp(path);
    assert(fd >= 0);
    size_t written = 0;
    while (written < dylib.size()) {
        const ssize_t n = ::write(fd, dylib.data() + written, dylib.size() - written);
        assert(n > 0);
        written += static_cast<size_t>(n);
    }
    ::close(fd);
    MachOLoader dylib_loader;
    auto loaded_dylib = dylib_loader.load(path, 0x1000000000ULL);
    ::unlink(path);
    assert(loaded_dylib.has_value());
    assert(loaded_dylib->filetype == MH_DYLIB);
    assert(loaded_dylib->rpaths.size() == 1);
    assert(loaded_dylib->rpaths[0] == rpath);
    assert(loaded_dylib->entry_point == 0);
    for (const auto& mapped : loaded_dylib->segments)
        if (mapped.mapped && mapped.vmsize)
            ::munmap(mapped.mapped, static_cast<size_t>(mapped.vmsize));
    return 0;
}
