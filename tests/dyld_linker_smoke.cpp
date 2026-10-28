#include "dylink/dyld_linker.h"
#include "dylib/dylib_interceptor.h"
#include <mach-o/loader.h>
#include <cassert>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
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

static std::vector<uint8_t> make_export_macho() {
    const std::vector<uint8_t> trie = {
        0x00, 0x01, '_','f','o','o',0x00, 0x08, // root with one "_foo" child at offset 8
        0x02, 0x00, 0x20, 0x00               // terminal: flags=regular, address=0x20, no children
    };
    const size_t commands_size = sizeof(segment_command_64) + sizeof(linkedit_data_command);
    const size_t payload_off = sizeof(mach_header_64) + commands_size;
    std::vector<uint8_t> image(payload_off + trie.size(), 0);
    auto* mh = reinterpret_cast<mach_header_64*>(image.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->ncmds = 2;
    mh->sizeofcmds = static_cast<uint32_t>(commands_size);
    auto* seg = reinterpret_cast<segment_command_64*>(image.data() + sizeof(mach_header_64));
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(segment_command_64);
    std::memcpy(seg->segname, "__TEXT", 6);
    seg->vmaddr = 0x100000000ULL;
    seg->vmsize = 0x1000;
    auto* ex = reinterpret_cast<linkedit_data_command*>(
        image.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    ex->cmd = LC_DYLD_EXPORTS_TRIE;
    ex->cmdsize = sizeof(linkedit_data_command);
    ex->dataoff = static_cast<uint32_t>(payload_off);
    ex->datasize = static_cast<uint32_t>(trie.size());
    std::memcpy(image.data() + payload_off, trie.data(), trie.size());
    return image;
}

static std::vector<uint8_t> make_bundled_dylib(const std::string& symbol) {
    std::vector<uint8_t> trie = {0x00, 0x01};
    for (char ch : symbol) trie.push_back(static_cast<uint8_t>(ch));
    trie.push_back(0);
    trie.push_back(static_cast<uint8_t>(trie.size() + 1)); // child node offset
    trie.insert(trie.end(), {0x02, 0x00, 0x20, 0x00}); // regular export at image + 0x20

    const size_t commands_size = sizeof(segment_command_64) + sizeof(linkedit_data_command);
    const size_t payload_off = sizeof(mach_header_64) + commands_size;
    std::vector<uint8_t> image(payload_off + trie.size(), 0);
    auto* mh = reinterpret_cast<mach_header_64*>(image.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->filetype = MH_DYLIB;
    mh->ncmds = 2;
    mh->sizeofcmds = static_cast<uint32_t>(commands_size);
    auto* seg = reinterpret_cast<segment_command_64*>(image.data() + sizeof(mach_header_64));
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(segment_command_64);
    std::memcpy(seg->segname, "__TEXT", 6);
    seg->vmaddr = 0x100000000ULL;
    seg->vmsize = 0x1000;
    auto* ex = reinterpret_cast<linkedit_data_command*>(
        image.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    ex->cmd = LC_DYLD_EXPORTS_TRIE;
    ex->cmdsize = sizeof(linkedit_data_command);
    ex->dataoff = static_cast<uint32_t>(payload_off);
    ex->datasize = static_cast<uint32_t>(trie.size());
    std::memcpy(image.data() + payload_off, trie.data(), trie.size());
    return image;
}

static std::vector<uint8_t> make_parent_dylib(
    const std::string& symbol, const std::string& dependency, const std::string& rpath) {
    auto align8 = [](size_t n) { return (n + 7) & ~size_t{7}; };
    std::vector<uint8_t> trie = {0x00, 0x01};
    for (char ch : symbol) trie.push_back(static_cast<uint8_t>(ch));
    trie.push_back(0);
    trie.push_back(static_cast<uint8_t>(trie.size() + 1));
    trie.insert(trie.end(), {0x02, 0x00, 0x20, 0x00});

    const size_t rpath_size = align8(sizeof(rpath_command) + rpath.size() + 1);
    const size_t dependency_size = align8(sizeof(dylib_command) + dependency.size() + 1);
    const size_t commands_size = sizeof(segment_command_64) + rpath_size +
                                 dependency_size + sizeof(linkedit_data_command);
    const size_t payload_off = sizeof(mach_header_64) + commands_size;
    std::vector<uint8_t> image(payload_off + trie.size(), 0);
    auto* mh = reinterpret_cast<mach_header_64*>(image.data());
    mh->magic = MH_MAGIC_64;
    mh->cputype = CPU_TYPE_ARM64;
    mh->filetype = MH_DYLIB;
    mh->ncmds = 4;
    mh->sizeofcmds = static_cast<uint32_t>(commands_size);
    uint8_t* cursor = image.data() + sizeof(mach_header_64);
    auto* seg = reinterpret_cast<segment_command_64*>(cursor);
    seg->cmd = LC_SEGMENT_64;
    seg->cmdsize = sizeof(segment_command_64);
    std::memcpy(seg->segname, "__TEXT", 6);
    seg->vmaddr = 0x100000000ULL;
    seg->vmsize = 0x1000;
    cursor += sizeof(segment_command_64);

    auto* rp = reinterpret_cast<rpath_command*>(cursor);
    rp->cmd = LC_RPATH;
    rp->cmdsize = static_cast<uint32_t>(rpath_size);
    rp->path.offset = sizeof(rpath_command);
    std::memcpy(cursor + rp->path.offset, rpath.c_str(), rpath.size() + 1);
    cursor += rpath_size;

    auto* dl = reinterpret_cast<dylib_command*>(cursor);
    dl->cmd = LC_LOAD_DYLIB;
    dl->cmdsize = static_cast<uint32_t>(dependency_size);
    dl->dylib.name.offset = sizeof(dylib_command);
    std::memcpy(cursor + dl->dylib.name.offset, dependency.c_str(), dependency.size() + 1);
    cursor += dependency_size;

    auto* ex = reinterpret_cast<linkedit_data_command*>(cursor);
    ex->cmd = LC_DYLD_EXPORTS_TRIE;
    ex->cmdsize = sizeof(linkedit_data_command);
    ex->dataoff = static_cast<uint32_t>(payload_off);
    ex->datasize = static_cast<uint32_t>(trie.size());
    std::memcpy(image.data() + payload_off, trie.data(), trie.size());
    return image;
}

static void write_bytes(const std::string& path, const std::vector<uint8_t>& bytes) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    size_t written = 0;
    while (written < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + written, bytes.size() - written);
        assert(n > 0);
        written += static_cast<size_t>(n);
    }
    ::close(fd);
}

static std::vector<uint8_t> make_chained_macho(bool with_import = false) {
    const size_t commands_size = sizeof(segment_command_64) + sizeof(linkedit_data_command);
    const size_t payload_off = sizeof(mach_header_64) + commands_size;
    std::vector<uint8_t> payload(with_import ? 80 : 60, 0);
    auto put32 = [&](size_t off, uint32_t value) { std::memcpy(payload.data() + off, &value, 4); };
    auto put16 = [&](size_t off, uint16_t value) { std::memcpy(payload.data() + off, &value, 2); };
    // dyld_chained_fixups_header
    put32(0, 0);  // fixups_version
    put32(4, 28); // starts_offset
    put32(8, 60); // imports_offset
    put32(12, with_import ? 64 : 60); // symbols_offset
    put32(16, with_import ? 1 : 0); // imports_count
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
    if (with_import) {
        put32(60, 0); // import name offset 0, ordinal 0
        std::memcpy(payload.data() + 64, "_test_import", 13);
    }

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

    // Signed bind addends are applied without unsigned wraparound.
    const std::vector<uint8_t> negative_addend_bind = {
        0x40, '_','t','e','s','t','_','i','m','p','o','r','t',0,
        0x70, 0x08, 0x60, 0x7f, 0x90, 0x00
    };
    auto negative_addend_image = make_macho(negative_addend_bind);
    std::memset(guest_memory, 0, sizeof(guest_memory));
    assert(linker.apply_fixups(negative_addend_image.data(), negative_addend_image.size(),
                               0, translate));
    std::memcpy(&patched, guest_memory + 8, sizeof(patched));
    assert(patched == linker.resolve_symbol("_test_import") - 1);

    const std::vector<uint8_t> underflow_addend_bind = {
        0x40, '_','t','e','s','t','_','i','m','p','o','r','t',0,
        0x70, 0x08, 0x60, 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7f,
        0x90, 0x00
    };
    auto underflow_addend_image = make_macho(underflow_addend_bind);
    std::memset(guest_memory, 0, sizeof(guest_memory));
    assert(!linker.apply_fixups(underflow_addend_image.data(), underflow_addend_image.size(),
                                0, translate));

    // Export-trie parsing resolves a regular export relative to slid __TEXT.
    auto export_image = make_export_macho();
    assert(linker.link(export_image.data(), export_image.size(), 0x1000, {}));
    assert(linker.resolve_symbol("_foo") == 0x100001020ULL);
    auto malformed_export = export_image;
    auto* bad_export = reinterpret_cast<linkedit_data_command*>(
        malformed_export.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    bad_export->dataoff = UINT32_MAX;
    assert(!linker.link(malformed_export.data(), malformed_export.size(), 0x1000, {}));

    // Load absolute and @rpath bundled MH_DYLIBs and resolve their exports.
    char directory_template[] = "/tmp/reverta-dylib-test-XXXXXX";
    char* directory_raw = ::mkdtemp(directory_template);
    assert(directory_raw != nullptr);
    const std::string directory = directory_raw;
    const std::string frameworks = directory + "/Frameworks";
    assert(::mkdir(frameworks.c_str(), 0700) == 0);
    const std::string bundled_path = directory + "/libbundled.dylib";
    const std::string rpath_path = frameworks + "/librpath.dylib";
    write_bytes(bundled_path, make_bundled_dylib("_bundled"));
    write_bytes(rpath_path, make_bundled_dylib("_rpathlib"));
    const std::string executable_path = directory + "/main";
    assert(linker.link(export_image.data(), export_image.size(), 0x1000,
                       {bundled_path, "@rpath/librpath.dylib"}, executable_path,
                       {"@executable_path/Frameworks"}));
    assert(linker.resolve_symbol("_bundled") == 0x1100000020ULL);
    assert(linker.resolve_symbol("_rpathlib") == 0x1200000020ULL);
    ::unlink(bundled_path.c_str());
    ::unlink(rpath_path.c_str());
    ::rmdir(frameworks.c_str());
    ::rmdir(directory.c_str());

    // A nested dylib resolves @rpath using its own inherited LC_RPATH entry.
    char nested_template[] = "/tmp/reverta-nested-test-XXXXXX";
    char* nested_raw = ::mkdtemp(nested_template);
    assert(nested_raw != nullptr);
    const std::string nested_root = nested_raw;
    const std::string nested_frameworks = nested_root + "/Frameworks";
    const std::string nested_children = nested_frameworks + "/Children";
    assert(::mkdir(nested_frameworks.c_str(), 0700) == 0);
    assert(::mkdir(nested_children.c_str(), 0700) == 0);
    const std::string parent_path = nested_frameworks + "/libparent.dylib";
    const std::string child_path = nested_children + "/libchild.dylib";
    write_bytes(parent_path, make_parent_dylib(
        "_parent", "@rpath/libchild.dylib", "@loader_path/Children"));
    write_bytes(child_path, make_bundled_dylib("_child"));
    const std::string nested_executable = nested_root + "/main";
    assert(linker.link(export_image.data(), export_image.size(), 0x1000,
                       {"@rpath/libparent.dylib"}, nested_executable,
                       {"@executable_path/Frameworks"}));
    assert(linker.resolve_symbol("_parent") == 0x1300000020ULL);
    assert(linker.resolve_symbol("_child") == 0x1400000020ULL);
    ::unlink(parent_path.c_str());
    ::unlink(child_path.c_str());
    ::rmdir(nested_children.c_str());
    ::rmdir(nested_frameworks.c_str());
    ::rmdir(nested_root.c_str());

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

    // Chained bind import ordinal 0 resolves through the registered interceptor.
    auto chained_bind_image = make_chained_macho(true);
    const uint64_t bind_pointer = uint64_t{1} << 63;
    std::memcpy(guest_memory + 8, &bind_pointer, sizeof(bind_pointer));
    assert(linker.apply_fixups(chained_bind_image.data(), chained_bind_image.size(),
                               0x1000, translate_slid));
    uint64_t chained_bound = 0;
    std::memcpy(&chained_bound, guest_memory + 8, sizeof(chained_bound));
    assert(chained_bound == linker.resolve_symbol("_test_import"));

    // The signed 8-bit addend encoded in a chained pointer is applied safely.
    const uint64_t negative_pointer_addend =
        (uint64_t{1} << 63) | (uint64_t{0xff} << 24);
    std::memcpy(guest_memory + 8, &negative_pointer_addend, sizeof(negative_pointer_addend));
    assert(linker.apply_fixups(chained_bind_image.data(), chained_bind_image.size(),
                               0x1000, translate_slid));
    std::memcpy(&chained_bound, guest_memory + 8, sizeof(chained_bound));
    assert(chained_bound == linker.resolve_symbol("_test_import") - 1);

    // Reject a chained-fixup payload that claims to extend beyond the file.
    auto malformed_chain = chained_image;
    auto* bad_cf = reinterpret_cast<linkedit_data_command*>(
        malformed_chain.data() + sizeof(mach_header_64) + sizeof(segment_command_64));
    bad_cf->datasize = UINT32_MAX;
    assert(!linker.apply_fixups(malformed_chain.data(), malformed_chain.size(),
                                0x1000, translate_slid));

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
