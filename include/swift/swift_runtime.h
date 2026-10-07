#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>

using GuestPtr = uint64_t;

// Swift type metadata kinds (mirrors swift/ABI/MetadataKind.def)
enum class SwiftMetadataKind : uint32_t {
    Class        = 0,
    Struct       = 0x200,
    Enum         = 0x201,
    Optional     = 0x202,
    Tuple        = 0x301,
    Function     = 0x302,
    Protocol     = 0x303,
    Metatype     = 0x304,
    ObjCClassWrapper = 0x400,
    Unknown      = 0xFFFF,
};

// Minimal Swift type metadata header (what we care about)
struct SwiftTypeMetadata {
    SwiftMetadataKind kind;
    std::string       name;
    uint32_t          instance_size;
    uint32_t          instance_alignment;
    GuestPtr          guest_addr; // where this lives in guest memory
};

// Swift witness table entry
struct SwiftWitnessTable {
    std::string protocol_name;
    std::unordered_map<std::string, GuestPtr> witnesses; // method name → IMP
};

// Swift runtime — handles swift_allocObject, type metadata lookups,
// protocol witness dispatch, and basic stdlib bridges
class SwiftRuntime {
public:
    static SwiftRuntime& instance();

    // Called from dylib shim when guest calls swift_allocObject
    GuestPtr alloc_object(GuestPtr metadata_ptr, size_t required_size, size_t required_alignment);

    // swift_retain / swift_release
    void retain(GuestPtr obj);
    bool release(GuestPtr obj); // returns true if deallocated

    // swift_getTypeByName — look up metadata by mangled name
    GuestPtr get_type_by_name(const char* mangled_name);

    // Register metadata parsed from __swift5_types section
    void register_metadata(SwiftTypeMetadata* meta);
    SwiftTypeMetadata* lookup_metadata(const std::string& name);

    // swift_beginAccess / swift_endAccess (exclusivity enforcement)
    // We stub these — single-threaded interpreter doesn't need real enforcement
    void begin_access(GuestPtr pointer, void* scratch, uint32_t flags, void* pc);
    void end_access(void* scratch);

    // Install host stubs for stdlib functions
    // e.g. swift_print, Swift.print(_:), swift_bridgeObjectRetain, etc.
    void install_stdlib_stubs();

    // Lookup a stub by mangled symbol name
    using StubFn = std::function<uint64_t(uint64_t*, int)>;
    void   register_stub(const std::string& mangled, StubFn fn);
    StubFn lookup_stub(const std::string& mangled);

private:
    SwiftRuntime() = default;

    std::unordered_map<std::string, SwiftTypeMetadata*> metadata_by_name_;
    std::unordered_map<GuestPtr,    int32_t>            retain_counts_;
    std::unordered_map<std::string, StubFn>             stubs_;
};
