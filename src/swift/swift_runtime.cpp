#include "swift/swift_runtime.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>

SwiftRuntime& SwiftRuntime::instance() {
    static SwiftRuntime rt;
    return rt;
}

GuestPtr SwiftRuntime::alloc_object(GuestPtr metadata_ptr,
                                     size_t required_size,
                                     size_t required_alignment) {
    // Swift object layout: [metadata ptr][strong refcount][weak refcount][fields...]
    size_t header = 16; // metadata + refcount
    size_t total  = header + required_size;
    if (required_alignment < 16) required_alignment = 16;

    void* mem = nullptr;
    ::posix_memalign(&mem, required_alignment, total);
    if (!mem) return 0;
    ::memset(mem, 0, total);

    auto* words = static_cast<uint64_t*>(mem);
    words[0] = metadata_ptr; // HeapMetadata pointer
    words[1] = 2;            // strong refcount (1 + 1 for "immortal" bias)

    GuestPtr obj = reinterpret_cast<GuestPtr>(mem);
    retain_counts_[obj] = 1;

    std::fprintf(stderr, "[swift] alloc_object metadata=0x%llx size=%zu → 0x%llx\n",
                 (unsigned long long)metadata_ptr, required_size,
                 (unsigned long long)obj);
    return obj;
}

void SwiftRuntime::retain(GuestPtr obj) {
    if (obj) retain_counts_[obj]++;
}

bool SwiftRuntime::release(GuestPtr obj) {
    if (!obj) return false;
    auto it = retain_counts_.find(obj);
    if (it == retain_counts_.end()) return false;
    if (--it->second <= 0) {
        retain_counts_.erase(it);
        ::free(reinterpret_cast<void*>(obj));
        return true;
    }
    return false;
}

GuestPtr SwiftRuntime::get_type_by_name(const char* mangled_name) {
    if (!mangled_name) return 0;
    auto it = metadata_by_name_.find(mangled_name);
    if (it != metadata_by_name_.end())
        return it->second->guest_addr;
    std::fprintf(stderr, "[swift] get_type_by_name: unknown '%s'\n", mangled_name);
    return 0;
}

void SwiftRuntime::register_metadata(SwiftTypeMetadata* meta) {
    metadata_by_name_[meta->name] = meta;
}

SwiftTypeMetadata* SwiftRuntime::lookup_metadata(const std::string& name) {
    auto it = metadata_by_name_.find(name);
    return it != metadata_by_name_.end() ? it->second : nullptr;
}

void SwiftRuntime::begin_access(GuestPtr /*pointer*/, void* /*scratch*/,
                                 uint32_t /*flags*/, void* /*pc*/) {
    // Stub: single-threaded, no enforcement needed
}

void SwiftRuntime::end_access(void* /*scratch*/) {
    // Stub
}

void SwiftRuntime::register_stub(const std::string& mangled, StubFn fn) {
    stubs_[mangled] = std::move(fn);
}

SwiftRuntime::StubFn SwiftRuntime::lookup_stub(const std::string& mangled) {
    auto it = stubs_.find(mangled);
    return it != stubs_.end() ? it->second : nullptr;
}

void SwiftRuntime::install_stdlib_stubs() {
    // swift_allocObject
    register_stub("swift_allocObject", [this](uint64_t* args, int) -> uint64_t {
        return alloc_object(args[0], (size_t)args[1], (size_t)args[2]);
    });

    // swift_retain
    register_stub("swift_retain", [this](uint64_t* args, int) -> uint64_t {
        retain(args[0]); return args[0];
    });

    // swift_release
    register_stub("swift_release", [this](uint64_t* args, int) -> uint64_t {
        release(args[0]); return 0;
    });

    // swift_bridgeObjectRetain
    register_stub("swift_bridgeObjectRetain", [this](uint64_t* args, int) -> uint64_t {
        retain(args[0]); return args[0];
    });

    // swift_bridgeObjectRelease
    register_stub("swift_bridgeObjectRelease", [this](uint64_t* args, int) -> uint64_t {
        release(args[0]); return 0;
    });

    // swift_beginAccess
    register_stub("swift_beginAccess", [this](uint64_t* args, int) -> uint64_t {
        begin_access(args[0], reinterpret_cast<void*>(args[1]),
                     (uint32_t)args[2], reinterpret_cast<void*>(args[3]));
        return 0;
    });

    // swift_endAccess
    register_stub("swift_endAccess", [this](uint64_t* args, int) -> uint64_t {
        end_access(reinterpret_cast<void*>(args[0]));
        return 0;
    });

    // Swift.print — the most basic thing a Swift app does
    register_stub("$ss5print_9separator10terminatoryypd_S2StF",
    [](uint64_t* args, int) -> uint64_t {
        // args[0] = variadic array pointer (simplified)
        const char* msg = reinterpret_cast<const char*>(args[0]);
        if (msg) std::fprintf(stdout, "%s\n", msg);
        return 0;
    });

    // swift_getTypeByName
    register_stub("swift_getTypeByMangledNameInContext",
    [this](uint64_t* args, int) -> uint64_t {
        const char* name = reinterpret_cast<const char*>(args[0]);
        return get_type_by_name(name);
    });

    std::fprintf(stderr, "[swift] stdlib stubs installed (%zu stubs)\n", stubs_.size());
}
