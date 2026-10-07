#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>

using GuestPtr = uint64_t;

// ── Swift runtime ABI (ARM64) ─────────────────────────────────────────────────
// Swift metadata kinds
enum class SwiftMetadataKind : uint32_t {
    Class          = 0,
    Struct         = 0x200,
    Enum           = 0x201,
    Optional       = 0x202,
    ForeignClass   = 0x203,
    Opaque         = 0x300,
    Tuple          = 0x301,
    Function       = 0x302,
    Existential    = 0x303,
    Metatype       = 0x304,
    ObjCWrapper    = 0x305,
};

struct SwiftTypeMetadata {
    uint64_t kind;       // SwiftMetadataKind
    // followed by type-specific fields
};

struct SwiftClassMetadata {
    // ObjC class header (isa, superclass, cache, vtable)
    GuestPtr isa;
    GuestPtr superclass;
    GuestPtr cache_data[2];
    GuestPtr rodata;        // class_ro_t | 1 (Swift flag)
    // Swift-specific
    uint32_t flags;
    uint32_t instance_addr_point;
    uint32_t instance_size;
    uint16_t instance_align_mask;
    uint16_t reserved;
    uint32_t class_obj_size;
    GuestPtr description; // TargetClassDescriptor*
};

// ── Host Swift bridge ─────────────────────────────────────────────────────────
class SwiftBridge {
public:
    using HostFunc = std::function<uint64_t(uint64_t, uint64_t, uint64_t,
                                            uint64_t, uint64_t, uint64_t)>;

    SwiftBridge();

    // Register all built-in Swift runtime stubs
    void register_builtins();

    // Look up a Swift runtime function by its mangled symbol name.
    // Returns 0 if not found (caller should fall through to guest code).
    uint64_t lookup(const std::string& symbol) const;

    // Dispatch a call to a known Swift runtime symbol
    // Returns {handled, return_value}
    std::pair<bool, uint64_t> call(const std::string& symbol,
        uint64_t a0, uint64_t a1, uint64_t a2,
        uint64_t a3, uint64_t a4, uint64_t a5);

    // Swift string interop helpers
    static std::string swift_string_to_std(uint64_t swift_str_ptr);

private:
    std::unordered_map<std::string, HostFunc> stubs_;

    void register_memory();      // swift_allocObject, swift_retain, etc.
    void register_casting();     // swift_dynamicCast, swift_isClassType, etc.
    void register_existentials();
    void register_stdlib();      // print, assert, fatalError, etc.
};
