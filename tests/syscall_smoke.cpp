#include "syscall/syscall_translator.h"
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>

int main() {
    uint8_t memory[256]{};
    auto translate = [&](uint64_t address, size_t size) -> uint8_t* {
        if (address < 0x1000) return nullptr;
        const uint64_t offset = address - 0x1000;
        if (offset >= sizeof(memory) || size > sizeof(memory) - offset) return nullptr;
        return memory + offset;
    };
    SyscallTranslator syscalls(translate);
    CpuState state{};

    int pipe_fds[2];
    assert(::pipe(pipe_fds) == 0);
    std::memcpy(memory, "hello", 5);
    state.x[16] = Arm64Syscall::write;
    state.x[0] = static_cast<uint64_t>(pipe_fds[1]);
    state.x[1] = 0x1000;
    state.x[2] = 5;
    assert(syscalls.handle(state));
    assert(state.x[0] == 5);
    char pipe_data[5]{};
    assert(::read(pipe_fds[0], pipe_data, sizeof(pipe_data)) == 5);
    assert(std::memcmp(pipe_data, "hello", 5) == 0);

    assert(::write(pipe_fds[1], "world", 5) == 5);
    state.x[16] = Arm64Syscall::read;
    state.x[0] = static_cast<uint64_t>(pipe_fds[0]);
    state.x[1] = 0x1010;
    state.x[2] = 5;
    assert(syscalls.handle(state));
    assert(state.x[0] == 5);
    assert(std::memcmp(memory + 16, "world", 5) == 0);
    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);

    char file_path[] = "/tmp/reverta-syscall-open-XXXXXX";
    const int tmp_fd = ::mkstemp(file_path);
    assert(tmp_fd >= 0);
    ::close(tmp_fd);
    std::memcpy(memory + 32, file_path, std::strlen(file_path) + 1);
    state.x[16] = Arm64Syscall::open;
    state.x[0] = 0x1020;
    state.x[1] = O_RDONLY;
    state.x[2] = 0;
    assert(syscalls.handle(state));
    assert(static_cast<int64_t>(state.x[0]) >= 0);
    const int opened_fd = static_cast<int>(state.x[0]);
    ::close(opened_fd);
    ::unlink(file_path);

    state.x[16] = Arm64Syscall::write;
    state.x[0] = 1;
    state.x[1] = 0x10f0;
    state.x[2] = 32; // crosses the end of the mapped guest buffer
    assert(syscalls.handle(state));
    assert(static_cast<int64_t>(state.x[0]) == -EFAULT);
    return 0;
}
