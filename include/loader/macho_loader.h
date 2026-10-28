#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

// Represents a loaded segment in the guest address space.
struct Segment {
    std::string name;
    uint64_t vmaddr;   // Mach-O preferred virtual address, before slide
    uint64_t mapped_vmaddr = 0; // guest address after slide; zero means vmaddr for tests
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint8_t* mapped;   // host pointer for the mapped segment
};

// Represents a loaded ARM64 Mach-O executable. image_data retains the selected
// thin Mach-O slice so the dynamic linker can inspect its load commands after
// the original file mapping has been released.
struct LoadedBinary {
    std::vector<Segment> segments;
    uint64_t entry_point = 0;     // raw file offset or preferred PC until segments are mapped; guest VA after load
    bool entry_point_is_file_offset = false;
    uint64_t base_address = 0;    // slide applied to preferred virtual addresses
    uint64_t stack_base = 0;      // host-backed guest stack range start
    uint64_t stack_size = 0;
    uint64_t stack_top = 0;       // initial stack pointer (exclusive upper bound)
    std::vector<std::string> dylibs;
    std::vector<std::string> weak_dylibs;
    std::vector<std::string> rpaths;
    std::string path;
    uint32_t filetype = 0;
    std::vector<uint8_t> image_data;
    bool is_pie = false;
};

class MachOLoader {
public:
    MachOLoader();
    ~MachOLoader();

    // Load a 64-bit ARM64 Mach-O executable or a universal binary containing
    // an ARM64 slice. Returns nullopt and sets error() on malformed input.
    std::optional<LoadedBinary> load(const std::string& path, uint64_t slide_override = 0);

    const std::string& error() const { return error_msg_; }

    // Apply final Mach-O segment protections after the linker has written fixups.
    bool finalize_protections(const LoadedBinary& binary);

private:
    bool parse_load_commands(const uint8_t* data, size_t size, LoadedBinary& binary);
    bool map_segments(const uint8_t* data, size_t size, LoadedBinary& binary, uint64_t slide_override);
    bool setup_stack(LoadedBinary& binary, int argc, const char** argv);

    std::string error_msg_;
    static constexpr size_t STACK_SIZE = 8 * 1024 * 1024;
};
