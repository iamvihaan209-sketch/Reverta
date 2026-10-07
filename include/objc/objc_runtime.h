#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

// ── Opaque guest-side ObjC types ──────────────────────────────────────────────
// These are guest virtual addresses (ARM64 pointers inside translated binary)

using GuestPtr  = uint64_t;
using SEL       = uint64_t; // guest selector (pointer to C string in guest mem)
using IMP       = uint64_t; // guest IMP (function pointer in guest mem)

// Method descriptor
struct ObjCMethod {
    std::string name;      // selector string e.g. "initWithFrame:"
    std::string types;     // type encoding e.g. "v16@0:8"
    IMP         imp;       // guest address of implementation
};

// Ivar descriptor
struct ObjCIvar {
    std::string name;
    std::string type;
    uint32_t    offset;
    uint32_t    size;
};

// Class descriptor (mirrors ARM64 ObjC class_ro_t / class_t)
struct ObjCClass {
    std::string name;
    ObjCClass*  superclass = nullptr;
    ObjCClass*  metaclass  = nullptr;
    uint32_t    instance_size = 0;
    bool        is_meta = false;

    std::unordered_map<std::string, ObjCMethod> methods;
    std::unordered_map<std::string, ObjCMethod> class_methods;
    std::vector<ObjCIvar> ivars;

    // Host implementation override — if set, bypasses guest IMP
    // Signature: (receiver, sel, args...) → result
    using HostIMP = std::function<uint64_t(GuestPtr, const std::string&, uint64_t*, int)>;
    std::unordered_map<std::string, HostIMP> host_overrides;

    ObjCMethod* lookup_method(const std::string& sel);
};

// ── ObjC Runtime ─────────────────────────────────────────────────────────────
class ObjCRuntime {
public:
    static ObjCRuntime& instance();

    // Register a class parsed from the guest binary's __objc_classlist
    void register_class(ObjCClass* cls);

    // Lookup a class by name
    ObjCClass* lookup_class(const std::string& name);

    // Register a selector string, return its canonical guest address
    // (we store selectors in a host table, map them to fake guest addresses)
    GuestPtr register_selector(const std::string& name);
    std::string selector_name(GuestPtr sel);

    // Core message send — called when guest code invokes objc_msgSend
    // receiver: guest ptr to ObjC object (first word is ISA = GuestPtr to class)
    // sel:      selector (guest ptr to selector string)
    // args:     remaining arguments (x2..x7 from ARM64 ABI)
    // returns:  x0 result
    uint64_t msg_send(GuestPtr receiver, GuestPtr sel,
                      uint64_t* args, int nargs);

    // objc_getClass / objc_lookUpClass
    GuestPtr get_class(const std::string& name);

    // alloc / init helpers
    GuestPtr alloc(GuestPtr cls_ptr);
    void     retain(GuestPtr obj);
    void     release(GuestPtr obj);

    // Install host overrides for system classes (NSObject, NSString, etc.)
    void install_system_overrides();

    // Parse __objc_classlist section from a loaded binary segment
    void parse_classlist(const uint8_t* section_data, size_t size,
                         uint64_t vmaddr_slide);

private:
    ObjCRuntime() = default;

    std::unordered_map<std::string, ObjCClass*> classes_;
    std::unordered_map<std::string, GuestPtr>   sel_to_ptr_;
    std::unordered_map<GuestPtr, std::string>   ptr_to_sel_;
    GuestPtr next_sel_ptr_ = 0xDEAD'0000'0000'0000ULL;

    // Object retain counts (guest ptr → count)
    std::unordered_map<GuestPtr, int32_t> retain_counts_;
};
