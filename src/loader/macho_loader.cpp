#include "loader/macho_loader.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach/vm_prot.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <cstdio>

// ARM64 CPU type
static constexpr cpu_type_t    CPU_TYPE_ARM64   = 0x0100000C;
static constexpr cpu_subtype_t CPU_SUBTYPE_ARM64_ALL = 0;

MachOLoader::MachOLoader() = default;
MachOLoader::~MachOLoader() = default;

std::optional<LoadedBinary> MachOLoader::load(const std::string& path) {
    // Open and map the file
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        error_msg_ = "Cannot open: " + path;
        return std::nullopt;
    }

    struct stat st;
    if (::fstat(fd, &st) < 0) {
        error_msg_ = "Cannot stat: " + path;
        ::close(fd);
        return std::nullopt;
    }
    size_t file_size = static_cast<size_t>(st.st_size);

    auto* data = static_cast<uint8_t*>(
        ::mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
    ::close(fd);

    if (data == MAP_FAILED) {
        error_msg_ = "Cannot mmap file";
        return std::nullopt;
    }

    // Check magic
    if (file_size < 4) {
        error_msg_ = "File too small";
        ::munmap(data, file_size);
        return std::nullopt;
    }

    uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
    const uint8_t* macho_data = data;
    size_t macho_size = file_size;

    // Handle fat binary — pick the ARM64 slice
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        auto* fat = reinterpret_cast<const fat_header*>(data);
        uint32_t narch = OSSwapBigToHostInt32(fat->nfat_arch);
        auto* archs = reinterpret_cast<const fat_arch*>(fat + 1);
        bool found = false;
        for (uint32_t i = 0; i < narch; i++) {
            cpu_type_t ct = static_cast<cpu_type_t>(OSSwapBigToHostInt32(archs[i].cputype));
            if (ct == CPU_TYPE_ARM64) {
                uint32_t off = OSSwapBigToHostInt32(archs[i].offset);
                uint32_t sz  = OSSwapBigToHostInt32(archs[i].size);
                macho_data = data + off;
                macho_size = sz;
                found = true;
                break;
            }
        }
        if (!found) {
            error_msg_ = "No ARM64 slice in fat binary";
            ::munmap(data, file_size);
            return std::nullopt;
        }
        magic = *reinterpret_cast<const uint32_t*>(macho_data);
    }

    // Expect 64-bit Mach-O
    if (magic != MH_MAGIC_64) {
        error_msg_ = "Not a 64-bit Mach-O (magic=0x" + std::to_string(magic) + ")";
        ::munmap(data, file_size);
        return std::nullopt;
    }

    auto* mh = reinterpret_cast<const mach_header_64*>(macho_data);
    if (mh->cputype != CPU_TYPE_ARM64) {
        error_msg_ = "Not an ARM64 binary";
        ::munmap(data, file_size);
        return std::nullopt;
    }

    LoadedBinary binary{};
    binary.is_pie = (mh->flags & MH_PIE) != 0;

    if (!parse_load_commands(macho_data, macho_size, binary)) {
        ::munmap(data, file_size);
        return std::nullopt;
    }

    if (!map_segments(macho_data, macho_size, binary)) {
        ::munmap(data, file_size);
        return std::nullopt;
    }

    ::munmap(data, file_size);
    return binary;
}

bool MachOLoader::parse_load_commands(const uint8_t* data, size_t /*size*/, LoadedBinary& binary) {
    auto* mh = reinterpret_cast<const mach_header_64*>(data);
    const uint8_t* lc_ptr = data + sizeof(mach_header_64);

    bool found_entry = false;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        auto* lc = reinterpret_cast<const load_command*>(lc_ptr);

        switch (lc->cmd) {
        case LC_SEGMENT_64: {
            auto* seg = reinterpret_cast<const segment_command_64*>(lc);
            Segment s{};
            s.name    = std::string(seg->segname, strnlen(seg->segname, 16));
            s.vmaddr  = seg->vmaddr;
            s.vmsize  = seg->vmsize;
            s.fileoff = seg->fileoff;
            s.filesize = seg->filesize;
            s.maxprot  = seg->maxprot;
            s.initprot = seg->initprot;
            s.mapped   = nullptr;
            binary.segments.push_back(s);
            break;
        }
        case LC_MAIN: {
            auto* em = reinterpret_cast<const entry_point_command*>(lc);
            binary.entry_point = em->entryoff; // relative to __TEXT
            found_entry = true;
            break;
        }
        case LC_UNIXTHREAD: {
            // Older binaries use LC_UNIXTHREAD instead of LC_MAIN
            // ARM64 thread state: x[0..28], fp, lr, sp, pc, cpsr
            const uint32_t* state = reinterpret_cast<const uint32_t*>(lc_ptr + 16);
            // pc is at offset 32 (after x0-x30, sp)
            binary.entry_point = reinterpret_cast<const uint64_t*>(state)[32];
            found_entry = true;
            break;
        }
        case LC_LOAD_DYLIB: {
            auto* dl = reinterpret_cast<const dylib_command*>(lc);
            const char* name = reinterpret_cast<const char*>(lc_ptr) + dl->dylib.name.offset;
            binary.dylibs.emplace_back(name);
            break;
        }
        default:
            break;
        }
        lc_ptr += lc->cmdsize;
    }

    if (!found_entry) {
        error_msg_ = "No entry point found in binary";
        return false;
    }

    return true;
}

bool MachOLoader::map_segments(const uint8_t* data, size_t /*size*/, LoadedBinary& binary) {
    // For PIE binaries we pick a base slide
    uint64_t slide = binary.is_pie ? 0x100000000ULL : 0;
    binary.base_address = slide;

    for (auto& seg : binary.segments) {
        if (seg.vmsize == 0) continue;

        // Determine host mmap protection
        int prot = PROT_NONE;
        if (seg.initprot & VM_PROT_READ)    prot |= PROT_READ;
        if (seg.initprot & VM_PROT_WRITE)   prot |= PROT_WRITE;
        if (seg.initprot & VM_PROT_EXECUTE) prot |= PROT_EXEC;

        // Allocate memory at the guest virtual address (+ slide)
        void* addr = ::mmap(
            reinterpret_cast<void*>(seg.vmaddr + slide),
            seg.vmsize,
            PROT_READ | PROT_WRITE, // write first so we can copy
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1, 0);

        if (addr == MAP_FAILED) {
            // Try without MAP_FIXED (ASLR conflict) — just pick any address
            addr = ::mmap(nullptr, seg.vmsize,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) {
                error_msg_ = "Failed to mmap segment " + seg.name;
                return false;
            }
            // Adjust slide
            uint64_t actual = reinterpret_cast<uint64_t>(addr);
            slide = actual - seg.vmaddr;
            binary.base_address = slide;
        }

        seg.mapped = static_cast<uint8_t*>(addr);

        // Copy file content into the segment
        if (seg.filesize > 0) {
            std::memcpy(seg.mapped, data + seg.fileoff, seg.filesize);
        }

        // Apply correct protection
        ::mprotect(addr, seg.vmsize, prot);
    }

    // Resolve entry point: LC_MAIN gives offset from __TEXT vmaddr
    // Find __TEXT vmaddr
    for (auto& seg : binary.segments) {
        if (seg.name == "__TEXT") {
            binary.entry_point = seg.vmaddr + slide + binary.entry_point;
            break;
        }
    }

    // Allocate stack
    void* stack = ::mmap(nullptr, STACK_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        error_msg_ = "Failed to allocate stack";
        return false;
    }
    binary.stack_top = reinterpret_cast<uint64_t>(stack) + STACK_SIZE;
    // Align to 16 bytes
    binary.stack_top &= ~0xFULL;

    return true;
}
