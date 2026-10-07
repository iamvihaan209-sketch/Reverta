#include "objc/objc_runtime.h"
#include <cstdio>
#include <cstring>

// ── ObjCClass ─────────────────────────────────────────────────────────────────
ObjCMethod* ObjCClass::lookup_method(const std::string& sel) {
    // Check own methods
    auto it = methods.find(sel);
    if (it != methods.end()) return &it->second;
    // Walk superclass chain
    if (superclass) return superclass->lookup_method(sel);
    return nullptr;
}

// ── ObjCRuntime ───────────────────────────────────────────────────────────────
ObjCRuntime& ObjCRuntime::instance() {
    static ObjCRuntime rt;
    return rt;
}

void ObjCRuntime::register_class(ObjCClass* cls) {
    classes_[cls->name] = cls;
}

ObjCClass* ObjCRuntime::lookup_class(const std::string& name) {
    auto it = classes_.find(name);
    return it != classes_.end() ? it->second : nullptr;
}

GuestPtr ObjCRuntime::register_selector(const std::string& name) {
    auto it = sel_to_ptr_.find(name);
    if (it != sel_to_ptr_.end()) return it->second;
    GuestPtr p = next_sel_ptr_++;
    sel_to_ptr_[name] = p;
    ptr_to_sel_[p]    = name;
    return p;
}

std::string ObjCRuntime::selector_name(GuestPtr sel) {
    auto it = ptr_to_sel_.find(sel);
    return it != ptr_to_sel_.end() ? it->second : "<unknown>";
}

GuestPtr ObjCRuntime::get_class(const std::string& name) {
    auto it = classes_.find(name);
    if (it == classes_.end()) return 0;
    return reinterpret_cast<GuestPtr>(it->second);
}

uint64_t ObjCRuntime::msg_send(GuestPtr receiver, GuestPtr sel_ptr,
                                uint64_t* args, int nargs) {
    if (receiver == 0) return 0; // nil message → nil

    std::string sel = selector_name(sel_ptr);
    if (sel.empty()) {
        // Try reading sel as a raw C string (guest memory)
        sel = reinterpret_cast<const char*>(sel_ptr);
    }

    std::fprintf(stderr, "[objc] msgSend receiver=0x%llx sel=%s\n",
                 (unsigned long long)receiver, sel.c_str());

    // First word of object is ISA pointer → points to ObjCClass*
    auto* obj_isa = reinterpret_cast<GuestPtr*>(receiver);
    auto* cls = reinterpret_cast<ObjCClass*>(*obj_isa);
    if (!cls) {
        std::fprintf(stderr, "[objc] msgSend: nil ISA\n");
        return 0;
    }

    // Check for host override first
    auto ho = cls->host_overrides.find(sel);
    if (ho != cls->host_overrides.end()) {
        return ho->second(receiver, sel, args, nargs);
    }

    // Look up method in class hierarchy
    ObjCMethod* m = cls->lookup_method(sel);
    if (!m) {
        std::fprintf(stderr, "[objc] msgSend: unrecognized selector '%s' for class '%s'\n",
                     sel.c_str(), cls->name.c_str());
        return 0;
    }

    // Return the guest IMP address — the interpreter/JIT will call it
    // In a full implementation we'd tail-call into it here
    // For now return the IMP so the caller can dispatch
    return m->imp;
}

GuestPtr ObjCRuntime::alloc(GuestPtr cls_ptr) {
    auto* cls = reinterpret_cast<ObjCClass*>(cls_ptr);
    if (!cls) return 0;

    // Allocate zeroed memory for the object
    size_t sz = cls->instance_size ? cls->instance_size : 64;
    auto* mem = static_cast<GuestPtr*>(::calloc(1, sz));
    if (!mem) return 0;

    // Set ISA
    mem[0] = cls_ptr;

    GuestPtr obj = reinterpret_cast<GuestPtr>(mem);
    retain_counts_[obj] = 1;
    return obj;
}

void ObjCRuntime::retain(GuestPtr obj) {
    if (obj) retain_counts_[obj]++;
}

void ObjCRuntime::release(GuestPtr obj) {
    if (!obj) return;
    auto it = retain_counts_.find(obj);
    if (it == retain_counts_.end()) return;
    if (--it->second <= 0) {
        retain_counts_.erase(it);
        ::free(reinterpret_cast<void*>(obj));
    }
}

// ── System class overrides ────────────────────────────────────────────────────
void ObjCRuntime::install_system_overrides() {
    // NSObject
    {
        auto* cls = new ObjCClass();
        cls->name = "NSObject";
        cls->instance_size = 16;

        cls->host_overrides["alloc"] = [this](GuestPtr recv, const std::string&,
                                               uint64_t*, int) -> uint64_t {
            return alloc(recv);
        };
        cls->host_overrides["init"] = [](GuestPtr recv, const std::string&,
                                          uint64_t*, int) -> uint64_t {
            return recv; // default init returns self
        };
        cls->host_overrides["retain"] = [this](GuestPtr recv, const std::string&,
                                                uint64_t*, int) -> uint64_t {
            retain(recv); return recv;
        };
        cls->host_overrides["release"] = [this](GuestPtr recv, const std::string&,
                                                  uint64_t*, int) -> uint64_t {
            release(recv); return 0;
        };
        cls->host_overrides["dealloc"] = [this](GuestPtr recv, const std::string&,
                                                  uint64_t*, int) -> uint64_t {
            retain_counts_.erase(recv);
            ::free(reinterpret_cast<void*>(recv));
            return 0;
        };
        cls->host_overrides["class"] = [](GuestPtr recv, const std::string&,
                                           uint64_t*, int) -> uint64_t {
            return *reinterpret_cast<GuestPtr*>(recv); // ISA
        };
        cls->host_overrides["description"] = [](GuestPtr recv, const std::string&,
                                                  uint64_t*, int) -> uint64_t {
            // Returns a basic NSString-like pointer (stub)
            std::fprintf(stderr, "[objc] description called on 0x%llx\n",
                         (unsigned long long)recv);
            return 0;
        };
        register_class(cls);
    }

    // NSString (minimal)
    {
        auto* cls = new ObjCClass();
        cls->name = "NSString";
        cls->instance_size = 32;

        cls->host_overrides["stringWithUTF8String:"] = [](GuestPtr, const std::string&,
                                                            uint64_t* args, int) -> uint64_t {
            const char* cstr = reinterpret_cast<const char*>(args[0]);
            std::fprintf(stderr, "[objc] NSString stringWithUTF8String: \"%s\"\n", cstr ? cstr : "(null)");
            // Allocate a tiny stub NSString object
            auto* mem = static_cast<uint64_t*>(::calloc(1, 32));
            mem[0] = 0; // ISA stub
            mem[1] = reinterpret_cast<uint64_t>(cstr ? ::strdup(cstr) : nullptr);
            return reinterpret_cast<uint64_t>(mem);
        };
        cls->host_overrides["UTF8String"] = [](GuestPtr recv, const std::string&,
                                                uint64_t*, int) -> uint64_t {
            auto* mem = reinterpret_cast<uint64_t*>(recv);
            return mem[1]; // stored C string pointer
        };
        cls->host_overrides["length"] = [](GuestPtr recv, const std::string&,
                                            uint64_t*, int) -> uint64_t {
            auto* mem = reinterpret_cast<uint64_t*>(recv);
            const char* s = reinterpret_cast<const char*>(mem[1]);
            return s ? ::strlen(s) : 0;
        };
        register_class(cls);
    }

    // NSArray (minimal)
    {
        auto* cls = new ObjCClass();
        cls->name = "NSArray";
        cls->instance_size = 32;
        cls->host_overrides["count"] = [](GuestPtr, const std::string&,
                                           uint64_t*, int) -> uint64_t { return 0; };
        register_class(cls);
    }

    // NSDictionary (minimal)
    {
        auto* cls = new ObjCClass();
        cls->name = "NSDictionary";
        cls->instance_size = 32;
        cls->host_overrides["count"] = [](GuestPtr, const std::string&,
                                           uint64_t*, int) -> uint64_t { return 0; };
        register_class(cls);
    }
}

void ObjCRuntime::parse_classlist(const uint8_t* /*data*/, size_t /*size*/,
                                   uint64_t /*slide*/) {
    // TODO: walk __objc_classlist to register guest classes
    // Each entry is a pointer to an ObjC class_t struct in guest memory
    // For now, system classes cover the common case
}
