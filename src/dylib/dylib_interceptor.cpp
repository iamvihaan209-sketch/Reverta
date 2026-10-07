#include "dylib/dylib_interceptor.h"
#include "objc/objc_runtime.h"
#include "swift/swift_runtime.h"
#include "foundation/foundation_stubs.h"
#include "appkit/appkit_stubs.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <cerrno>

DylibInterceptor& DylibInterceptor::instance() {
    static DylibInterceptor di;
    return di;
}

void DylibInterceptor::register_symbol(const std::string& name, HostFn fn) {
    symbols_[name] = std::move(fn);
}

HostFn DylibInterceptor::lookup(const std::string& name) const {
    auto it = symbols_.find(name);
    return it != symbols_.end() ? it->second : nullptr;
}

bool DylibInterceptor::has_symbol(const std::string& name) const {
    return symbols_.count(name) > 0;
}

GuestPtr DylibInterceptor::allocate_trampoline(const std::string& name) {
    auto it = name_to_trampoline_.find(name);
    if (it != name_to_trampoline_.end()) return it->second;

    GuestPtr addr = next_trampoline_++;
    trampoline_to_name_[addr] = name;
    name_to_trampoline_[name] = addr;
    return addr;
}

uint64_t DylibInterceptor::dispatch_trampoline(GuestPtr pc, uint64_t* args, int nargs) {
    auto it = trampoline_to_name_.find(pc);
    if (it == trampoline_to_name_.end()) {
        std::fprintf(stderr, "[dylib] unknown trampoline PC 0x%llx\n",
                     (unsigned long long)pc);
        return 0;
    }
    const std::string& name = it->second;
    auto fn_it = symbols_.find(name);
    if (fn_it == symbols_.end()) {
        std::fprintf(stderr, "[dylib] no host impl for '%s'\n", name.c_str());
        return 0;
    }
    std::fprintf(stderr, "[dylib] → %s\n", name.c_str());
    return fn_it->second(args, nargs);
}

// ── Install all stubs ─────────────────────────────────────────────────────────
void DylibInterceptor::install_all() {
    install_objc_stubs();
    install_swift_stubs();
    install_foundation_stubs();
    install_appkit_stubs();
    install_posix_stubs();
    install_libsystem_stubs();
    std::fprintf(stderr, "[dylib] %zu symbols registered\n", symbols_.size());
}

// ── ObjC stubs ────────────────────────────────────────────────────────────────
void DylibInterceptor::install_objc_stubs() {
    auto& rt = ObjCRuntime::instance();
    rt.install_system_overrides();

    register_symbol("objc_msgSend", [&rt](uint64_t* args, int nargs) -> uint64_t {
        return rt.msg_send(args[0], args[1], args + 2, nargs - 2);
    });
    register_symbol("objc_msgSend_stret", [&rt](uint64_t* args, int nargs) -> uint64_t {
        // stret: args[0] = struct return buf, args[1] = receiver, args[2] = sel
        return rt.msg_send(args[1], args[2], args + 3, nargs - 3);
    });
    register_symbol("objc_getClass", [&rt](uint64_t* args, int) -> uint64_t {
        const char* name = reinterpret_cast<const char*>(args[0]);
        return rt.get_class(name ? name : "");
    });
    register_symbol("objc_lookUpClass", [&rt](uint64_t* args, int) -> uint64_t {
        const char* name = reinterpret_cast<const char*>(args[0]);
        return rt.get_class(name ? name : "");
    });
    register_symbol("objc_retain", [&rt](uint64_t* args, int) -> uint64_t {
        rt.retain(args[0]); return args[0];
    });
    register_symbol("objc_release", [&rt](uint64_t* args, int) -> uint64_t {
        rt.release(args[0]); return 0;
    });
    register_symbol("objc_autorelease", [](uint64_t* args, int) -> uint64_t {
        return args[0]; // stub: no autorelease pool
    });
    register_symbol("objc_autoreleasePoolPush", [](uint64_t*, int) -> uint64_t {
        // Use a stable non-zero opaque token for the guest autorelease pool.
        return 0xA0700001ULL; // fake token
    });
    register_symbol("objc_autoreleasePoolPop", [](uint64_t*, int) -> uint64_t {
        return 0;
    });
    register_symbol("sel_registerName", [&rt](uint64_t* args, int) -> uint64_t {
        const char* name = reinterpret_cast<const char*>(args[0]);
        return rt.register_selector(name ? name : "");
    });
    register_symbol("sel_getName", [&rt](uint64_t* args, int) -> uint64_t {
        std::string s = rt.selector_name(args[0]);
        return reinterpret_cast<uint64_t>(::strdup(s.c_str())); // leaks, fine for now
    });
}

// ── Swift stubs ───────────────────────────────────────────────────────────────
void DylibInterceptor::install_swift_stubs() {
    auto& rt = SwiftRuntime::instance();
    rt.install_stdlib_stubs();

    // Enumerate all installed stubs and register them here
    // (SwiftRuntime holds them; we proxy them through DylibInterceptor)
    static const char* swift_syms[] = {
        "swift_allocObject",
        "swift_retain",
        "swift_release",
        "swift_bridgeObjectRetain",
        "swift_bridgeObjectRelease",
        "swift_beginAccess",
        "swift_endAccess",
        "swift_getTypeByMangledNameInContext",
        nullptr
    };
    for (int i = 0; swift_syms[i]; i++) {
        std::string sym = swift_syms[i];
        register_symbol(sym, [&rt, sym](uint64_t* args, int nargs) -> uint64_t {
            auto fn = rt.lookup_stub(sym);
            return fn ? fn(args, nargs) : 0ULL;
        });
    }
}

// ── Foundation / CF stubs ─────────────────────────────────────────────────────
void DylibInterceptor::install_foundation_stubs() {
    auto& fb = FoundationStubs::instance();

    register_symbol("CFStringCreateWithCString", [&fb](uint64_t* a, int) -> uint64_t {
        return fb.CFStringCreateWithCString(a[0], reinterpret_cast<const char*>(a[1]), (uint32_t)a[2]);
    });
    register_symbol("CFStringGetCStringPtr", [&fb](uint64_t* a, int) -> uint64_t {
        return reinterpret_cast<uint64_t>(fb.CFStringGetCStringPtr(a[0], (uint32_t)a[1]));
    });
    register_symbol("CFStringGetCString", [&fb](uint64_t* a, int) -> uint64_t {
        return fb.CFStringGetCString(a[0], reinterpret_cast<char*>(a[1]), (int64_t)a[2], (uint32_t)a[3]) ? 1 : 0;
    });
    register_symbol("CFStringGetLength", [&fb](uint64_t* a, int) -> uint64_t {
        return (uint64_t)fb.CFStringGetLength(a[0]);
    });
    register_symbol("CFDataCreate", [&fb](uint64_t* a, int) -> uint64_t {
        return fb.CFDataCreate(a[0], reinterpret_cast<const uint8_t*>(a[1]), (int64_t)a[2]);
    });
    register_symbol("CFDataGetBytePtr", [&fb](uint64_t* a, int) -> uint64_t {
        return reinterpret_cast<uint64_t>(fb.CFDataGetBytePtr(a[0]));
    });
    register_symbol("CFDataGetLength", [&fb](uint64_t* a, int) -> uint64_t {
        return (uint64_t)fb.CFDataGetLength(a[0]);
    });
    register_symbol("CFArrayGetCount", [&fb](uint64_t* a, int) -> uint64_t {
        return (uint64_t)fb.CFArrayGetCount(a[0]);
    });
    register_symbol("CFArrayGetValueAtIndex", [&fb](uint64_t* a, int) -> uint64_t {
        return fb.CFArrayGetValueAtIndex(a[0], (int64_t)a[1]);
    });
    register_symbol("CFDictionaryGetValue", [&fb](uint64_t* a, int) -> uint64_t {
        return fb.CFDictionaryGetValue(a[0], a[1]);
    });
    register_symbol("CFRetain", [&fb](uint64_t* a, int) -> uint64_t {
        return fb.CFRetain(a[0]);
    });
    register_symbol("CFRelease", [&fb](uint64_t* a, int) -> uint64_t {
        fb.CFRelease(a[0]); return 0;
    });
    register_symbol("CFGetRetainCount", [&fb](uint64_t* a, int) -> uint64_t {
        return (uint64_t)fb.CFGetRetainCount(a[0]);
    });
    register_symbol("CFGetTypeID", [&fb](uint64_t* a, int) -> uint64_t {
        return fb.CFGetTypeID(a[0]);
    });
    register_symbol("NSLog", [](uint64_t* a, int) -> uint64_t {
        // NSLog(format, ...) — just print the format string
        const char* fmt = reinterpret_cast<const char*>(a[0]);
        std::fprintf(stderr, "[NSLog] %s\n", fmt ? fmt : "(null)");
        return 0;
    });
}

// ── AppKit stubs ──────────────────────────────────────────────────────────────
void DylibInterceptor::install_appkit_stubs() {
    auto& ak = AppKitStubs::instance();

    register_symbol("NSApplicationMain", [&ak](uint64_t* a, int) -> uint64_t {
        std::fprintf(stderr, "[appkit] NSApplicationMain argc=%llu\n", (unsigned long long)a[0]);
        ak.NSApplication_sharedApplication();
        ak.NSApplication_run(0);
        return 0;
    });
    register_symbol("NSApp", [&ak](uint64_t*, int) -> uint64_t {
        return ak.NSApplication_sharedApplication();
    });
    register_symbol("CFRunLoopRun", [&ak](uint64_t*, int) -> uint64_t {
        ak.CFRunLoopRun(); return 0;
    });
    register_symbol("CFRunLoopGetMain", [&ak](uint64_t*, int) -> uint64_t {
        return ak.CFRunLoopGetMain();
    });
    register_symbol("CFRunLoopStop", [&ak](uint64_t* a, int) -> uint64_t {
        ak.CFRunLoopStop(a[0]); return 0;
    });
}

// ── POSIX / libSystem stubs ───────────────────────────────────────────────────
void DylibInterceptor::install_posix_stubs() {
    register_symbol("malloc", [](uint64_t* a, int) -> uint64_t {
        return reinterpret_cast<uint64_t>(::malloc((size_t)a[0]));
    });
    register_symbol("calloc", [](uint64_t* a, int) -> uint64_t {
        return reinterpret_cast<uint64_t>(::calloc((size_t)a[0], (size_t)a[1]));
    });
    register_symbol("realloc", [](uint64_t* a, int) -> uint64_t {
        return reinterpret_cast<uint64_t>(::realloc(reinterpret_cast<void*>(a[0]), (size_t)a[1]));
    });
    register_symbol("free", [](uint64_t* a, int) -> uint64_t {
        ::free(reinterpret_cast<void*>(a[0])); return 0;
    });
    register_symbol("memcpy", [](uint64_t* a, int) -> uint64_t {
        ::memcpy(reinterpret_cast<void*>(a[0]), reinterpret_cast<void*>(a[1]), (size_t)a[2]);
        return a[0];
    });
    register_symbol("memset", [](uint64_t* a, int) -> uint64_t {
        ::memset(reinterpret_cast<void*>(a[0]), (int)a[1], (size_t)a[2]);
        return a[0];
    });
    register_symbol("strlen", [](uint64_t* a, int) -> uint64_t {
        const char* s = reinterpret_cast<const char*>(a[0]);
        return s ? ::strlen(s) : 0;
    });
    register_symbol("strcmp", [](uint64_t* a, int) -> uint64_t {
        const char* s1 = reinterpret_cast<const char*>(a[0]);
        const char* s2 = reinterpret_cast<const char*>(a[1]);
        return (uint64_t)(int64_t)::strcmp(s1 ? s1 : "", s2 ? s2 : "");
    });
    register_symbol("printf", [](uint64_t* a, int) -> uint64_t {
        const char* fmt = reinterpret_cast<const char*>(a[0]);
        if (fmt) std::fprintf(stdout, "%s", fmt);
        return 0;
    });
    register_symbol("puts", [](uint64_t* a, int) -> uint64_t {
        const char* s = reinterpret_cast<const char*>(a[0]);
        return (uint64_t)(int64_t)::puts(s ? s : "");
    });
    register_symbol("exit", [](uint64_t* a, int) -> uint64_t {
        ::exit((int)a[0]); return 0;
    });
    register_symbol("abort", [](uint64_t*, int) -> uint64_t {
        ::abort(); return 0;
    });
    register_symbol("mmap", [](uint64_t* a, int) -> uint64_t {
        void* r = ::mmap(reinterpret_cast<void*>(a[0]), (size_t)a[1],
                         (int)a[2], (int)a[3], (int)a[4], (off_t)a[5]);
        return r == MAP_FAILED ? (uint64_t)-1 : reinterpret_cast<uint64_t>(r);
    });
    register_symbol("munmap", [](uint64_t* a, int) -> uint64_t {
        return (uint64_t)(int64_t)::munmap(reinterpret_cast<void*>(a[0]), (size_t)a[1]);
    });
}

void DylibInterceptor::install_libsystem_stubs() {
    // dyld / libSystem bootstrap stubs
    register_symbol("_dyld_get_image_count", [](uint64_t*, int) -> uint64_t { return 1; });
    register_symbol("_dyld_get_image_name", [](uint64_t*, int) -> uint64_t {
        static const char* name = "reverta_guest";
        return reinterpret_cast<uint64_t>(name);
    });
    register_symbol("dyld_get_sdk_version", [](uint64_t*, int) -> uint64_t {
        return 0x000C0000; // 12.0.0
    });
    register_symbol("__stack_chk_fail", [](uint64_t*, int) -> uint64_t {
        std::fprintf(stderr, "[dylib] stack smash detected\n");
        ::abort(); return 0;
    });
    register_symbol("__stack_chk_guard", [](uint64_t*, int) -> uint64_t {
        return 0xDEADBEEFDEADBEEFULL;
    });
}
