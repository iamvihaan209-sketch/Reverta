#include "loader/macho_loader.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <libkern/OSByteOrder.h>
#include <mach/vm_prot.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <cstdio>
#include <limits>

MachOLoader::MachOLoader() = default;
MachOLoader::~MachOLoader() = default;

std::optional<LoadedBinary> MachOLoader::load(const std::string& path) {
    error_msg_.clear();
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        error_msg_ = "Cannot open: " + path;
        return std::nullopt;
    }

    struct stat st {};
    if (::fstat(fd, &st) < 0 || st.st_size <= 0) {
        error_msg_ = "Cannot stat file or file is empty: " + path;
        ::close(fd);
        return std::nullopt;
    }
    if (static_cast<uintmax_t>(st.st_size) > std::numeric_limits<size_t>::max()) {
        error_msg_ = "File is too large for this process";
        ::close(fd);
        return std::nullopt;
    }
    const size_t file_size = static_cast<size_t>(st.st_size);
    auto* data = static_cast<uint8_t*>(
        ::mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0));
    ::close(fd);
    if (data == MAP_FAILED) {
        error_msg_ = "Cannot mmap file";
        return std::nullopt;
    }

    const uint8_t* macho_data = data;
    size_t macho_size = file_size;
    if (file_size < sizeof(uint32_t)) {
        error_msg_ = "File too small";
        ::munmap(data, file_size);
        return std::nullopt;
    }

    uint32_t magic = 0;
    std::memcpy(&magic, data, sizeof(magic));
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        if (file_size < sizeof(fat_header)) {
            error_msg_ = "Truncated universal-binary header";
            ::munmap(data, file_size);
            return std::nullopt;
        }
        const auto* fat = reinterpret_cast<const fat_header*>(data);
        const uint32_t narch = OSSwapBigToHostInt32(fat->nfat_arch);
        const size_t arch_bytes = static_cast<size_t>(narch) * sizeof(fat_arch);
        if (narch > (file_size - sizeof(fat_header)) / sizeof(fat_arch)) {
            error_msg_ = "Universal-binary architecture table is out of bounds";
            ::munmap(data, file_size);
            return std::nullopt;
        }
        const auto* archs = reinterpret_cast<const fat_arch*>(data + sizeof(fat_header));
        bool found = false;
        for (uint32_t i = 0; i < narch; ++i) {
            const cpu_type_t ct = static_cast<cpu_type_t>(
                OSSwapBigToHostInt32(static_cast<uint32_t>(archs[i].cputype)));
            if (ct != CPU_TYPE_ARM64) continue;
            const uint32_t off = OSSwapBigToHostInt32(archs[i].offset);
            const uint32_t sz = OSSwapBigToHostInt32(archs[i].size);
            if (off > file_size || sz > file_size - off ||
                sz < sizeof(mach_header_64)) {
                error_msg_ = "ARM64 slice range is invalid";
                ::munmap(data, file_size);
                return std::nullopt;
            }
            macho_data = data + off;
            macho_size = sz;
            found = true;
            break;
        }
        (void)arch_bytes;
        if (!found) {
            error_msg_ = "No ARM64 slice in universal binary";
            ::munmap(data, file_size);
            return std::nullopt;
        }
        std::memcpy(&magic, macho_data, sizeof(magic));
    }

    if (macho_size < sizeof(mach_header_64) || magic != MH_MAGIC_64) {
        error_msg_ = "Not a supported 64-bit Mach-O executable";
        ::munmap(data, file_size);
        return std::nullopt;
    }
    const auto* mh = reinterpret_cast<const mach_header_64*>(macho_data);
    if (mh->cputype != CPU_TYPE_ARM64) {
        error_msg_ = "Mach-O slice is not ARM64";
        ::munmap(data, file_size);
        return std::nullopt;
    }

    LoadedBinary binary{};
    binary.is_pie = (mh->flags & MH_PIE) != 0;
    binary.image_data.assign(macho_data, macho_data + macho_size);
    if (!parse_load_commands(binary.image_data.data(), binary.image_data.size(), binary) ||
        !map_segments(binary.image_data.data(), binary.image_data.size(), binary)) {
        ::munmap(data, file_size);
        return std::nullopt;
    }

    ::munmap(data, file_size);
    return binary;
}

bool MachOLoader::parse_load_commands(const uint8_t* data, size_t size, LoadedBinary& binary) {
    if (!data || size < sizeof(mach_header_64)) {
        error_msg_ = "Truncated Mach-O header";
        return false;
    }
    const auto* mh = reinterpret_cast<const mach_header_64*>(data);
    if (mh->magic != MH_MAGIC_64 || mh->sizeofcmds > size - sizeof(mach_header_64)) {
        error_msg_ = "Invalid Mach-O header or load-command region";
        return false;
    }
    const uint8_t* cursor = data + sizeof(mach_header_64);
    const uint8_t* end = cursor + mh->sizeofcmds;
    bool found_entry = false;

    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (static_cast<size_t>(end - cursor) < sizeof(load_command)) {
            error_msg_ = "Truncated load command";
            return false;
        }
        const auto* lc = reinterpret_cast<const load_command*>(cursor);
        if (lc->cmdsize < sizeof(load_command) ||
            lc->cmdsize > static_cast<size_t>(end - cursor)) {
            error_msg_ = "Invalid load-command size";
            return false;
        }

        switch (lc->cmd) {
        case LC_SEGMENT_64: {
            if (lc->cmdsize < sizeof(segment_command_64)) {
                error_msg_ = "Truncated LC_SEGMENT_64";
                return false;
            }
            const auto* seg = reinterpret_cast<const segment_command_64*>(cursor);
            const size_t section_bytes = static_cast<size_t>(seg->nsects) * sizeof(section_64);
            if (seg->nsects > (lc->cmdsize - sizeof(segment_command_64)) / sizeof(section_64) ||
                seg->filesize > seg->vmsize ||
                seg->fileoff > size || seg->filesize > size - seg->fileoff ||
                seg->vmsize > std::numeric_limits<uint64_t>::max() - seg->vmaddr) {
                error_msg_ = "Invalid segment bounds";
                return false;
            }
            (void)section_bytes;
            Segment s{};
            s.name = std::string(seg->segname, strnlen(seg->segname, sizeof(seg->segname)));
            s.vmaddr = seg->vmaddr;
            s.vmsize = seg->vmsize;
            s.fileoff = seg->fileoff;
            s.filesize = seg->filesize;
            s.maxprot = seg->maxprot;
            s.initprot = seg->initprot;
            s.mapped = nullptr;
            binary.segments.push_back(std::move(s));
            break;
        }
        case LC_MAIN: {
            if (lc->cmdsize < sizeof(entry_point_command)) {
                error_msg_ = "Truncated LC_MAIN";
                return false;
            }
            const auto* em = reinterpret_cast<const entry_point_command*>(cursor);
            binary.entry_point = em->entryoff;
            found_entry = true;
            break;
        }
        case LC_UNIXTHREAD: {
            // ARM64 thread state stores PC after x0-x28, fp, lr and sp.
            constexpr size_t arm64_pc_end = 16 + 33 * sizeof(uint64_t);
            if (lc->cmdsize < arm64_pc_end) {
                error_msg_ = "Truncated ARM64 LC_UNIXTHREAD state";
                return false;
            }
            const uint64_t* state = reinterpret_cast<const uint64_t*>(cursor + 16);
            binary.entry_point = state[32];
            found_entry = true;
            break;
        }
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
        case LC_LOAD_UPWARD_DYLIB: {
            if (lc->cmdsize < sizeof(dylib_command)) {
                error_msg_ = "Truncated dylib load command";
                return false;
            }
            const auto* dl = reinterpret_cast<const dylib_command*>(cursor);
            if (dl->dylib.name.offset >= lc->cmdsize) {
                error_msg_ = "Dylib name offset is out of bounds";
                return false;
            }
            const char* name = reinterpret_cast<const char*>(cursor + dl->dylib.name.offset);
            const size_t remaining = lc->cmdsize - dl->dylib.name.offset;
            const void* terminator = std::memchr(name, '\0', remaining);
            if (!terminator) {
                error_msg_ = "Unterminated dylib name";
                return false;
            }
            binary.dylibs.emplace_back(name, static_cast<const char*>(terminator) - name);
            break;
        }
        default:
            break;
        }
        cursor += lc->cmdsize;
    }

    if (cursor != end) {
        error_msg_ = "Load-command sizes do not match sizeofcmds";
        return false;
    }
    if (!found_entry) {
        error_msg_ = "No entry point found in binary";
        return false;
    }
    if (binary.segments.empty()) {
        error_msg_ = "Mach-O contains no segments";
        return false;
    }
    return true;
}

bool MachOLoader::map_segments(const uint8_t* data, size_t size, LoadedBinary& binary) {
    uint64_t slide = binary.is_pie ? 0x100000000ULL : 0;
    binary.base_address = slide;

    for (auto& seg : binary.segments) {
        if (seg.vmsize == 0) continue;
        if (seg.filesize > seg.vmsize || seg.fileoff > size ||
            seg.filesize > size - seg.fileoff ||
            seg.vmsize > std::numeric_limits<size_t>::max()) {
            error_msg_ = "Segment range exceeds the selected Mach-O image";
            return false;
        }

        int prot = PROT_NONE;
        if (seg.initprot & VM_PROT_READ) prot |= PROT_READ;
        if (seg.initprot & VM_PROT_WRITE) prot |= PROT_WRITE;
        if (seg.initprot & VM_PROT_EXECUTE) prot |= PROT_EXEC;

        if (seg.vmaddr > std::numeric_limits<uint64_t>::max() - slide) {
            error_msg_ = "Slid segment address overflows";
            return false;
        }
        seg.mapped_vmaddr = seg.vmaddr + slide;
        void* requested = reinterpret_cast<void*>(seg.mapped_vmaddr);
        void* addr = ::mmap(requested, static_cast<size_t>(seg.vmsize),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (addr == MAP_FAILED) {
            error_msg_ = "Failed to map segment " + seg.name +
                " at requested guest address";
            return false;
        }
        seg.mapped = static_cast<uint8_t*>(addr);
        if (seg.filesize)
            std::memcpy(seg.mapped, data + seg.fileoff, static_cast<size_t>(seg.filesize));
        // Keep the mapped segment writable while the dynamic linker applies
        // relocations. finalize_protections() restores the Mach-O protections.
    }

    bool text_found = false;
    for (const auto& seg : binary.segments) {
        if (seg.name == "__TEXT") {
            if (seg.vmaddr > std::numeric_limits<uint64_t>::max() - slide ||
                binary.entry_point > std::numeric_limits<uint64_t>::max() - (seg.vmaddr + slide)) {
                error_msg_ = "Entry-point address overflows";
                return false;
            }
            binary.entry_point = seg.vmaddr + slide + binary.entry_point;
            text_found = true;
            break;
        }
    }
    if (!text_found) {
        error_msg_ = "No __TEXT segment found";
        return false;
    }

    void* stack = ::mmap(nullptr, STACK_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        error_msg_ = "Failed to allocate stack";
        return false;
    }
    binary.stack_top = reinterpret_cast<uint64_t>(stack) + STACK_SIZE;
    binary.stack_top &= ~0xFULL;
    return true;
}

bool MachOLoader::finalize_protections(const LoadedBinary& binary) {
    for (const auto& seg : binary.segments) {
        if (!seg.mapped || seg.vmsize == 0) continue;
        int prot = PROT_NONE;
        if (seg.initprot & VM_PROT_READ) prot |= PROT_READ;
        if (seg.initprot & VM_PROT_WRITE) prot |= PROT_WRITE;
        if (seg.initprot & VM_PROT_EXECUTE) prot |= PROT_EXEC;
        if (::mprotect(seg.mapped, static_cast<size_t>(seg.vmsize), prot) != 0) {
            error_msg_ = "Failed to set segment protections for " + seg.name;
            return false;
        }
    }
    return true;
}
