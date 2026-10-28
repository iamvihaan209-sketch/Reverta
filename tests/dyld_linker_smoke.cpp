#include "dylink/dyld_linker.h"
#include "dylib/dylib_interceptor.h"
#include <mach-o/loader.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

// Minimal interceptor implementation for this isolated linker test target.
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

static std::vector<uint8_t> make_macho(const std::vector<uint8_t>& binds,
                                       const std::vector<uint8_t>& rebases = {}) {
    const size_t commands_size = sizeof(segment_command_64) + sizeof(dyld_info_command);
    const size_t payload_off = sizeof(mach_header_64) + commands_size;
    std::vector<uint8_t> image(payload_off + rebases.size() + binds.size(), 0);
    auto* mh = reinterpret_cast<mach_header_64*>(image.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->ncmds = 2;
    mh->sizeofcmds = static_cast<uint32_t>(commands_size);

    auto* seg = reinterpret_cast<segment_command_64*>(image.data() + sizeof(mach_header_64));
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(segment_command_64);
    std::memcpy(seg->segname, "__DATA", 6);
    seg->vmaddr = 0x1000;
    seg->vmsize = 0x1000;

    auto* di = reinterpret_cast<dyld_info_command*>(
        image.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    di->cmd = LC_DYLD_INFO_ONLY;
    di->cmdsize = sizeof(dyld_info_command);
    di->rebase_off = static_cast<uint32_t>(payload_off);
    di->rebase_size = static_cast<uint32_t>(rebases.size());
    di->bind_off = static_cast<uint32_t>(payload_off + rebases.size());
    di->bind_size = static_cast<uint32_t>(binds.size());
    if (!rebases.empty())
        std::memcpy(image.data() + payload_off, rebases.data(), rebases.size());
    if (!binds.empty())
        std::memcpy(image.data() + di->bind_off, binds.data(), binds.size());
    return image;
}

static std::vector<uint8_t> make_chained_macho() {
    const size_t commands_size = sizeof(segment_command_64) + sizeof(linkedit_data_command);
    const size_t payload_off = sizeof(mach_header_64) + commands_size;
    std::vector<uint8_t> payload(60, 0);
    auto put32 = [&](size_t off, uint32_t value) { std::memcpy(payload.data() + off, &value, 4); };
    auto put16 = [&](size_t off, uint16_t value) { std::memcpy(payload.data() + off, &value, 2); };
    // dyld_chained_fixups_header
    put32(0, 0);  // fixups_version
    put32(4, 28); // starts_offset
    put32(8, 60); // imports_offset (no imports)
    put32(12, 60);// symbols_offset (empty pool)
    put32(16, 0); // imports_count
    put32(20, 1); // DYLD_CHAINED_IMPORT
    put32(24, 0); // uncompressed symbols
    // starts_in_image with one segment; segment info is 8 bytes after starts_offset.
    put32(28, 1);
    put32(32, 8);
    // starts_in_segment: size, page size, pointer format, segment offset,
    // max_valid_pointer, page_count, one page start.
    put32(36, 24);
    put16(40, 4096);
    put16(42, 2); // DYLD_CHAINED_PTR_64
    put32(44, 0); put32(48, 0); // segment_offset low/high
    put32(52, 0); // max_valid_pointer
    put16(56, 1); // page_count
    put16(58, 8); // chain begins at offset 8 in page

    std::vector<uint8_t> image(payload_off + payload.size(), 0);
    auto* mh = reinterpret_cast<mach_header_64*>(image.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->ncmds = 2;
    mh->sizeofcmds = static_cast<uint32_t>(commands_size);
    auto* seg = reinterpret_cast<segment_command_64*>(image.data() + sizeof(mach_header_64));
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(segment_command_64);
    std::memcpy(seg->segname, "__DATA", 6);
    seg->vmaddr = 0x1000;
    seg->vmsize = 0x1000;
    auto* cf = reinterpret_cast<linkedit_data_command*>(
        image.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    cf->cmd = LC_DYLD_CHAINED_FIXUPS;
    cf->cmdsize = sizeof(linkedit_data_command);
    cf->dataoff = static_cast<uint32_t>(payload_off);
    cf->datasize = static_cast<uint32_t>(payload.size());
    std::memcpy(image.data() + payload_off, payload.data(), payload.size());
    return image;
}

int main() {
    auto& interceptor = DylibInterceptor::instance();
    interceptor.register_symbol("_test_import", [](uint64_t*, int) -> uint64_t { return 0; });

    // SET_SYMBOL("_test_import"), SET_SEGMENT_AND_OFFSET(0, 8), DO_BIND, DONE.
    const std::vector<uint8_t> binds = {
        0x40, '_','t','e','s','t','_','i','m','p','o','r','t',0,
        0x70, 0x08, 0x90, 0x00
    };
    auto image = make_macho(binds);
    uint8_t guest_memory[32]{};
    auto translate = [&](uint64_t address) -> uint8_t* {
        if (address < 0x1000 || address - 0x1000 > sizeof(guest_memory) - sizeof(uint64_t))
            return nullptr;
        return guest_memory + (address - 0x1000);
    };

    DyldLinker& linker = DyldLinker::instance();
    assert(linker.apply_fixups(image.data(), image.size(), 0, translate));
    uint64_t patched = 0;
    std::memcpy(&patched, guest_memory + 8, sizeof(patched));
    assert(patched == linker.resolve_symbol("_test_import"));

    // Classic pointer rebase adds the selected image's slide to a pointer slot.
    auto rebase_image = make_macho({}, {0x20, 0x08, 0x51, 0x00});
    uint64_t original_pointer = 0x1234;
    std::memcpy(guest_memory + 8, &original_pointer, sizeof(original_pointer));
    auto translate_slid = [&](uint64_t address) -> uint8_t* {
        if (address < 0x2000 || address - 0x2000 > sizeof(guest_memory) - sizeof(uint64_t))
            return nullptr;
        return guest_memory + (address - 0x2000);
    };
    assert(linker.apply_fixups(rebase_image.data(), rebase_image.size(), 0x1000,
                               translate_slid));
    uint64_t rebased = 0;
    std::memcpy(&rebased, guest_memory + 8, sizeof(rebased));
    assert(rebased == 0x2234);

    // A bounded DYLD_CHAINED_PTR_64 rebase also applies the image slide.
    auto chained_image = make_chained_macho();
    original_pointer = 0x1234;
    std::memcpy(guest_memory + 8, &original_pointer, sizeof(original_pointer));
    assert(linker.apply_fixups(chained_image.data(), chained_image.size(), 0x1000,
                               translate_slid));
    rebased = 0;
    std::memcpy(&rebased, guest_memory + 8, sizeof(rebased));
    assert(rebased == 0x2234);

    // A truncated ULEB in SET_SEGMENT_AND_OFFSET must be rejected, not read past end.
    auto truncated = make_macho({0x70, 0x80});
    assert(!linker.apply_fixups(truncated.data(), truncated.size(), 0, translate));

    // No fixup commands is a valid no-op for a minimal Mach-O header.
    mach_header_64 empty{};
    empty.magic = MH_MAGIC_64;
    empty.cputype = CPU_TYPE_ARM64;
    assert(linker.apply_fixups(reinterpret_cast<const uint8_t*>(&empty),
                               sizeof(empty), 0, translate));
    return 0;
}
