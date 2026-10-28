#include "syscall/syscall_translator.h"
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <limits>

// Issue a raw macOS syscall using the x86-64 ABI
// On macOS, user-space syscalls use syscall instruction with RAX = 0x2000000 | num
int64_t SyscallTranslator::raw_syscall(
        int64_t num, int64_t a0, int64_t a1, int64_t a2,
        int64_t a3, int64_t a4, int64_t a5)
{
    // We're already running native x86-64 code on the host,
    // so we just call through libc / the OS normally.
    // This is the host syscall number (x86-64 macOS).
    (void)num; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    // Actual dispatch done in individual handlers using libc wrappers.
    return -1;
}

bool SyscallTranslator::handle(CpuState& state) {
    uint64_t sysnum = state.x[16]; // ARM64 macOS: syscall number in X16
    // Args in X0-X7, return value in X0

    std::fprintf(stderr, "[rrosetta] SVC #0 syscall=%llu x0=%llx x1=%llx x2=%llx\n",
        (unsigned long long)sysnum,
        (unsigned long long)state.x[0],
        (unsigned long long)state.x[1],
        (unsigned long long)state.x[2]);

    switch (sysnum) {
    case Arm64Syscall::exit:   return sys_exit(state);
    case Arm64Syscall::read:   return sys_read(state);
    case Arm64Syscall::write:  return sys_write(state);
    case Arm64Syscall::open:   return sys_open(state);
    case Arm64Syscall::close:  return sys_close(state);
    case Arm64Syscall::getpid: return sys_getpid(state);
    case Arm64Syscall::mmap:   return sys_mmap(state);
    case Arm64Syscall::munmap: return sys_munmap(state);
    default:
        std::fprintf(stderr, "[rrosetta] UNHANDLED syscall %llu\n",
                     (unsigned long long)sysnum);
        state.x[0] = static_cast<uint64_t>(-ENOSYS);
        return true; // keep running
    }
}

bool SyscallTranslator::copy_guest_string(uint64_t address, std::string& out,
                                            size_t max_length) const {
    out.clear();
    if (!guest_to_host_ || address == 0) return false;
    for (size_t i = 0; i < max_length; ++i) {
        if (address > UINT64_MAX - i) return false;
        uint8_t* byte = guest_to_host_(address + i, 1);
        if (!byte) return false;
        if (*byte == 0) return true;
        out.push_back(static_cast<char>(*byte));
    }
    return false;
}

// ── Syscall implementations ───────────────────────────────────────────────────

bool SyscallTranslator::sys_exit(CpuState& state) {
    int code = (int)state.x[0];
    std::fprintf(stderr, "[rrosetta] exit(%d)\n", code);
    ::_exit(code);
    return false; // unreachable
}

bool SyscallTranslator::sys_write(CpuState& state) {
    int     fd    = (int)state.x[0];
    const size_t count = static_cast<size_t>(state.x[2]);
    void* buf = nullptr;
    if (count != 0) {
        buf = guest_to_host_ ? guest_to_host_(state.x[1], count) : nullptr;
        if (!buf) {
            state.x[0] = static_cast<uint64_t>(-EFAULT);
            return true;
        }
    }

    ssize_t ret = ::write(fd, buf, count);
    if (ret < 0) {
        state.x[0] = static_cast<uint64_t>(-errno);
    } else {
        state.x[0] = (uint64_t)ret;
    }
    return true;
}

bool SyscallTranslator::sys_read(CpuState& state) {
    int    fd    = (int)state.x[0];
    const size_t count = static_cast<size_t>(state.x[2]);
    void* buf = nullptr;
    if (count != 0) {
        buf = guest_to_host_ ? guest_to_host_(state.x[1], count) : nullptr;
        if (!buf) {
            state.x[0] = static_cast<uint64_t>(-EFAULT);
            return true;
        }
    }

    ssize_t ret = ::read(fd, buf, count);
    if (ret < 0) {
        state.x[0] = static_cast<uint64_t>(-errno);
    } else {
        state.x[0] = (uint64_t)ret;
    }
    return true;
}

bool SyscallTranslator::sys_open(CpuState& state) {
    std::string path;
    if (!copy_guest_string(state.x[0], path)) {
        state.x[0] = static_cast<uint64_t>(-EFAULT);
        return true;
    }
    const int flags = static_cast<int>(state.x[1]);
    const int mode = static_cast<int>(state.x[2]);

    int fd = ::open(path.c_str(), flags, mode);
    if (fd < 0) {
        state.x[0] = static_cast<uint64_t>(-errno);
    } else {
        state.x[0] = (uint64_t)fd;
    }
    return true;
}

bool SyscallTranslator::sys_close(CpuState& state) {
    int fd  = (int)state.x[0];
    int ret = ::close(fd);
    state.x[0] = ret < 0 ? static_cast<uint64_t>(-errno) : 0;
    return true;
}

bool SyscallTranslator::sys_getpid(CpuState& state) {
    state.x[0] = (uint64_t)::getpid();
    return true;
}

bool SyscallTranslator::sys_mmap(CpuState& state) {
    if (!guest_mmap_) {
        state.x[0] = static_cast<uint64_t>(-ENOSYS);
        return true;
    }
    const int64_t result = guest_mmap_(state.x[0], static_cast<size_t>(state.x[1]),
        static_cast<int>(state.x[2]), static_cast<int>(state.x[3]),
        static_cast<int>(state.x[4]), static_cast<int64_t>(state.x[5]));
    state.x[0] = static_cast<uint64_t>(result);
    return true;
}

bool SyscallTranslator::sys_munmap(CpuState& state) {
    if (!guest_munmap_) {
        state.x[0] = static_cast<uint64_t>(-ENOSYS);
        return true;
    }
    const int64_t result = guest_munmap_(state.x[0], static_cast<size_t>(state.x[1]));
    state.x[0] = static_cast<uint64_t>(result);
    return true;
}
