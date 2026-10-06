#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

// Represents a loaded segment in the guest address space
struct Segment {
    std::string name;
    uint64_t vmaddr;   // virtual address in guest space
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint8_t* mapped;   // pointer in host address space
};

// Represents a loaded ARM64 Mach-O binary
struct LoadedBinary {
    std::vector<Segment> segments;
    uint64_t entry_point;     // virtual address of entry point
    uint64_t base_address;    // ASLR slide base
    uint64_t stack_top;       // initial stack pointer
    std::vector<std::string> dylibs; // required dylibs (for future use)
    bool is_pie;
};

class MachOLoader {
public:
    MachOLoader();
    ~MachOLoader();

    // Load a static ARM64 Mach-O executable from path
    // Returns nullopt on failure, sets error_msg
    std::optional<LoadedBinary> load(const std::string& path);

    const std::string& error() const { return error_msg_; }

private:
    bool parse_load_commands(const uint8_t* data, size_t size, LoadedBinary& binary);
    bool map_segments(const uint8_t* data, size_t size, LoadedBinary& binary);
    bool setup_stack(LoadedBinary& binary, int argc, const char** argv);

    std::string error_msg_;
    static constexpr size_t STACK_SIZE = 8 * 1024 * 1024; // 8MB stack
};
