#include "runtime/objc_bridge.h"
#include <cstdio>
#include <cstring>
#include <objc/runtime.h>
#include <objc/message.h>
#include <Foundation/Foundation.h>

ObjcBridge::ObjcBridge() {}

void ObjcBridge::register_builtins() {
    register_nsobject();
    register_nsstring();
    register_nsarray();
    register_nsdictionary();
    register_nslog();
}

// ── SEL interning ─────────────────────────────────────────────────────────────
uint64_t ObjcBridge::intern_sel(const std::string& name) {
    auto it = name_to_sel_.find(name);
    if (it != name_to_sel_.end()) return it->second;
    uint64_t sel = next_sel_++;
    name_to_sel_[name] = sel;
    sel_to_name_[sel]  = name;
    return sel;
}

std::string ObjcBridge::sel_name(uint64_t sel) const {
    auto it = sel_to_name_.find(sel);
    return it != sel_to_name_.end() ? it->second : "<unknown-sel>";
}

uint64_t ObjcBridge::class_named(const std::string& name) const {
    auto it = guest_classes_.find(name);
    return it != guest_classes_.end() ? it->second : 0;
}

// ── msg_send dispatch ─────────────────────────────────────────────────────────
uint64_t ObjcBridge::msg_send(uint64_t self, uint64_t sel_val,
                               uint64_t a2, uint64_t a3,
                               uint64_t a4, uint64_t a5)
{
    std::string sel_str = sel_name(sel_val);
    if (sel_str.empty()) {
        // Try treating sel_val as a pointer to a C string (guest SEL)
        sel_str = reinterpret_cast<const char*>(sel_val);
        sel_val = intern_sel(sel_str);
    }

    // Walk host method table: try exact class name lookup via isa
    // For now we use a simplified flat lookup by sel name only,
    // checking NSObject first, then specific classes.
    for (auto& [cls_name, methods] : host_methods_) {
        auto mit = methods.find(sel_val);
        if (mit != methods.end()) {
            return mit->second(self, sel_val, a2, a3, a4, a5);
        }
    }

    // Fall through to guest IMP lookup
    uint64_t imp = lookup_guest_imp(self, sel_val);
    if (imp) return imp; // caller (interpreter) will jump to this

    std::fprintf(stderr, "[rrosetta/objc] unhandled -[? %s] self=0x%llx\n",
                 sel_str.c_str(), (unsigned long long)self);
    return 0;
}

uint64_t ObjcBridge::lookup_guest_imp(uint64_t cls, uint64_t sel) const {
    auto cit = guest_methods_.find(cls);
    if (cit == guest_methods_.end()) return 0;
    auto mit = cit->second.find(sel);
    return mit != cit->second.end() ? mit->second : 0;
}

// ── Guest class registration ──────────────────────────────────────────────────
void ObjcBridge::register_guest_classes(
        const uint8_t* /*base*/, uint64_t /*slide*/,
        const uint8_t* sel_refs,  size_t sel_refs_size,
        const uint8_t* classlist, size_t classlist_size)
{
    // Intern all SEL refs from __objc_selrefs
    if (sel_refs) {
        size_t count = sel_refs_size / sizeof(uint64_t);
        auto* ptrs = reinterpret_cast<const uint64_t*>(sel_refs);
        for (size_t i = 0; i < count; i++) {
            const char* name = reinterpret_cast<const char*>(ptrs[i]);
            if (name) intern_sel(name);
        }
    }

    // Register guest classes from __objc_classlist
    if (classlist) {
        size_t count = classlist_size / sizeof(uint64_t);
        auto* class_ptrs = reinterpret_cast<const uint64_t*>(classlist);
        for (size_t i = 0; i < count; i++) {
            uint64_t cls_ptr = class_ptrs[i];
            if (!cls_ptr) continue;
            auto* gc = reinterpret_cast<const GuestClass*>(cls_ptr);
            uint64_t data = gc->data & ~0x7ULL; // strip flags
            if (!data) continue;
            auto* ro = reinterpret_cast<const GuestClassRO*>(data);
            if (!ro->name) continue;
            std::string name = reinterpret_cast<const char*>(ro->name);
            guest_classes_[name] = cls_ptr;
            std::fprintf(stderr, "[rrosetta/objc] registered guest class: %s\n", name.c_str());
        }
    }
}

// ── Built-in host stubs ───────────────────────────────────────────────────────

void ObjcBridge::register_nsobject() {
    auto& m = host_methods_["NSObject"];

    m[intern_sel("alloc")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        // Forward to real ObjC runtime using the host class
        // self here is the guest Class pointer — we don't have a real mapping yet,
        // so allocate raw memory matching a basic NSObject size
        void* obj = ::calloc(1, 64); // enough for basic NSObject subclasses
        std::fprintf(stderr, "[rrosetta/objc] +[NSObject alloc] → %p\n", obj);
        return reinterpret_cast<uint64_t>(obj);
    };

    m[intern_sel("init")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        return self; // default -init returns self
    };

    m[intern_sel("release")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        // Simplified: just free. Real ARC does ref counting.
        // TODO: ref count table
        (void)self;
        return 0;
    };

    m[intern_sel("retain")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        return self;
    };

    m[intern_sel("autorelease")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        return self;
    };

    m[intern_sel("dealloc")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        ::free(reinterpret_cast<void*>(self));
        return 0;
    };

    m[intern_sel("description")] = [this](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        char buf[64];
        snprintf(buf, sizeof(buf), "<NSObject: 0x%llx>", (unsigned long long)self);
        return intern_sel(buf); // cheap stand-in; real impl returns NSString
    };

    m[intern_sel("class")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        return self; // simplified
    };

    m[intern_sel("respondsToSelector:")] = [this](uint64_t, uint64_t, uint64_t sel2, uint64_t, uint64_t, uint64_t) -> uint64_t {
        // Return YES if we have a stub for it
        for (auto& [cls, methods] : host_methods_) {
            if (methods.count(sel2)) return 1;
        }
        return 0;
    };
}

void ObjcBridge::register_nsstring() {
    auto& m = host_methods_["NSString"];

    m[intern_sel("stringWithUTF8String:")] = [](uint64_t, uint64_t, uint64_t cstr, uint64_t, uint64_t, uint64_t) -> uint64_t {
        // Create a real NSString on the host and return its pointer
        const char* s = reinterpret_cast<const char*>(cstr);
        NSString* str = [NSString stringWithUTF8String:s];
        std::fprintf(stderr, "[rrosetta/objc] +[NSString stringWithUTF8String:\"%s\"]\n", s);
        return reinterpret_cast<uint64_t>((__bridge_retained void*)str);
    };

    m[intern_sel("length")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSString* str = (__bridge NSString*)reinterpret_cast<void*>(self);
        return (uint64_t)[str length];
    };

    m[intern_sel("UTF8String")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSString* str = (__bridge NSString*)reinterpret_cast<void*>(self);
        return reinterpret_cast<uint64_t>([str UTF8String]);
    };

    m[intern_sel("stringByAppendingString:")] = [](uint64_t self, uint64_t, uint64_t other, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSString* a = (__bridge NSString*)reinterpret_cast<void*>(self);
        NSString* b = (__bridge NSString*)reinterpret_cast<void*>(other);
        NSString* r = [a stringByAppendingString:b];
        return reinterpret_cast<uint64_t>((__bridge_retained void*)r);
    };

    m[intern_sel("isEqualToString:")] = [](uint64_t self, uint64_t, uint64_t other, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSString* a = (__bridge NSString*)reinterpret_cast<void*>(self);
        NSString* b = (__bridge NSString*)reinterpret_cast<void*>(other);
        return [a isEqualToString:b] ? 1 : 0;
    };
}

void ObjcBridge::register_nsarray() {
    auto& m = host_methods_["NSArray"];

    m[intern_sel("array")] = [](uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSArray* a = [NSArray array];
        return reinterpret_cast<uint64_t>((__bridge_retained void*)a);
    };

    m[intern_sel("count")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSArray* a = (__bridge NSArray*)reinterpret_cast<void*>(self);
        return (uint64_t)[a count];
    };

    m[intern_sel("objectAtIndex:")] = [](uint64_t self, uint64_t, uint64_t idx, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSArray* a = (__bridge NSArray*)reinterpret_cast<void*>(self);
        id obj = [a objectAtIndex:(NSUInteger)idx];
        return reinterpret_cast<uint64_t>((__bridge void*)obj);
    };
}

void ObjcBridge::register_nsdictionary() {
    auto& m = host_methods_["NSDictionary"];

    m[intern_sel("dictionary")] = [](uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSDictionary* d = [NSDictionary dictionary];
        return reinterpret_cast<uint64_t>((__bridge_retained void*)d);
    };

    m[intern_sel("objectForKey:")] = [](uint64_t self, uint64_t, uint64_t key, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSDictionary* d = (__bridge NSDictionary*)reinterpret_cast<void*>(self);
        id k = (__bridge id)reinterpret_cast<void*>(key);
        id v = [d objectForKey:k];
        return reinterpret_cast<uint64_t>((__bridge void*)v);
    };

    m[intern_sel("count")] = [](uint64_t self, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSDictionary* d = (__bridge NSDictionary*)reinterpret_cast<void*>(self);
        return (uint64_t)[d count];
    };
}

void ObjcBridge::register_nslog() {
    // NSLog is a C function but often called via ObjC; handled in dyld_stub too
    auto& m = host_methods_["__global"];
    m[intern_sel("NSLog")] = [](uint64_t, uint64_t, uint64_t fmt_ptr, uint64_t, uint64_t, uint64_t) -> uint64_t {
        NSString* fmt = (__bridge NSString*)reinterpret_cast<void*>(fmt_ptr);
        NSLog(@"%@", fmt);
        return 0;
    };
}
