#include "loader/macho_loader.h"
#include <mach-o/loader.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <fcntl.h>
#include <unistd.h>

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
    return 0;
}
