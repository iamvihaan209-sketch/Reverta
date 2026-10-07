#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

// ── ObjC ABI types ────────────────────────────────────────────────────────────
// We mirror the ARM64 ObjC ABI structs so we can read them out of
// the guest binary's __DATA/__objc_* sections.

using GuestPtr = uint64_t; // a pointer in guest address space

struct GuestMethod {
    GuestPtr name;   // SEL (pointer to C string)
    GuestPtr types;  // method type encoding string
    GuestPtr imp;    // IMP — pointer to implementation code
};

struct GuestIvar {
    GuestPtr offset; // pointer to uint32_t offset value
    GuestPtr name;
    GuestPtr type;
    uint32_t alignment_raw;
    uint32_t size;
};

struct GuestClassRO {
    uint32_t flags;
    uint32_t instance_start;
    uint32_t instance_size;
    uint32_t reserved;
    GuestPtr ivar_layout;
    GuestPtr name;       // class name C string
    GuestPtr base_methods;   // method_list_t*
    GuestPtr base_protocols;
    GuestPtr ivars;          // ivar_list_t*
    GuestPtr weak_ivar_layout;
    GuestPtr base_properties;
};

struct GuestClass {
    GuestPtr metaclass;
    GuestPtr superclass;
    GuestPtr cache;
    GuestPtr vtable;
    GuestPtr data; // class_rw_t* | class_ro_t* (low bit = 0 means ro)
};

// ── Host-side ObjC bridge ─────────────────────────────────────────────────────
// Maps guest SEL/IMP values to host implementations so we can intercept
// calls to system frameworks (NSObject, NSString, etc.) without needing
// to JIT-translate the frameworks themselves.

class ObjcBridge {
public:
    using HostIMP = std::function<uint64_t(uint64_t self, uint64_t sel,
                                           uint64_t a2, uint64_t a3,
                                           uint64_t a4, uint64_t a5)>;

    ObjcBridge();

    // Register all built-in host stubs (NSObject, NSString, etc.)
    void register_builtins();

    // Scan guest binary's ObjC sections and register guest classes/methods
    void register_guest_classes(const uint8_t* base, uint64_t slide,
                                const uint8_t* sel_refs, size_t sel_refs_size,
                                const uint8_t* classlist, size_t classlist_size);

    // Core dispatch — called by the interpreter when it hits a BL to objc_msgSend
    // Returns the IMP (host function or guest code pointer) for (receiver, sel)
    // If returns 0, the message was handled entirely by a host stub.
    uint64_t msg_send(uint64_t self, uint64_t sel_ptr,
                      uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5);

    // SEL interning — returns a stable uint64_t "address" for a selector name
    uint64_t intern_sel(const std::string& name);
    std::string sel_name(uint64_t sel) const;

    // Class lookup by name
    uint64_t class_named(const std::string& name) const;

private:
    // sel value → name
    std::unordered_map<uint64_t, std::string> sel_to_name_;
    std::unordered_map<std::string, uint64_t> name_to_sel_;
    uint64_t next_sel_ = 0x8000000000000000ULL; // high range, won't clash with guest

    // class name → { sel → HostIMP }
    std::unordered_map<std::string,
        std::unordered_map<uint64_t, HostIMP>> host_methods_;

    // class name → guest class ptr
    std::unordered_map<std::string, uint64_t> guest_classes_;

    // guest class ptr → { sel → guest IMP }
    std::unordered_map<uint64_t,
        std::unordered_map<uint64_t, uint64_t>> guest_methods_;

    void register_nsobject();
    void register_nsstring();
    void register_nsarray();
    void register_nsdictionary();
    void register_nslog();

    uint64_t lookup_guest_imp(uint64_t cls, uint64_t sel) const;
};
