#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>

using GuestPtr = uint64_t;

// A host function that handles a guest dylib call.
// args[0..7] mirror ARM64 x0-x7 at the call site.
// Returns the value to put in x0.
using HostFn = std::function<uint64_t(uint64_t* args, int nargs)>;

// DylibInterceptor sits between the loader and the interpreter.
// When the guest binary tries to call an external symbol (e.g. objc_msgSend,
// CFStringCreateWithCString, NSApplicationMain), we redirect it to a HostFn
// instead of crashing on an unmapped address.
//
// How it works:
//   1. Loader sees LC_DYLD_INFO / LC_DYLD_EXPORTS_TRIE stub entries
//   2. For each imported symbol, allocate_trampoline() hands out a fake guest
//      address. Nothing is mapped there.
//   3. When a guest BL/BR lands on that address, the interpreter's PC hook
//      (is_trampoline) dispatches the bound HostFn and returns to the caller.
//      SVC is not used for this; every SVC goes to the syscall handler.
//
class DylibInterceptor {
public:
    static DylibInterceptor& instance();

    // Register a host implementation for a symbol name
    void register_symbol(const std::string& name, HostFn fn);

    // Look up a host function by symbol name
    HostFn lookup(const std::string& name) const;

    // Allocate a guest trampoline address for a symbol.
    // Returns a fake guest PC; a guest branch to that PC calls the associated
    // HostFn (see is_trampoline below).
    GuestPtr allocate_trampoline(const std::string& name);

    // True if pc is a trampoline address handed out by allocate_trampoline.
    // Trampolines are not mapped guest memory; the interpreter's PC hook
    // dispatches them when a guest branch lands on one.
    bool is_trampoline(GuestPtr pc) const { return trampoline_to_name_.count(pc) != 0; }

    // Runs the HostFn bound to a trampoline PC and returns its result (x0).
    uint64_t dispatch_trampoline(GuestPtr pc, uint64_t* args, int nargs);

    // Install all known system library stubs (ObjC, Swift, CF, AppKit, POSIX)
    void install_all();

    bool has_symbol(const std::string& name) const;

private:
    DylibInterceptor() = default;

    std::unordered_map<std::string, HostFn>  symbols_;
    std::unordered_map<GuestPtr, std::string> trampoline_to_name_;
    std::unordered_map<std::string, GuestPtr> name_to_trampoline_;

    // Trampoline addresses live in a reserved fake region
    GuestPtr next_trampoline_ = 0xBEEF'0000'0000'0000ULL;

    void install_objc_stubs();
    void install_swift_stubs();
    void install_foundation_stubs();
    void install_appkit_stubs();
    void install_posix_stubs();
    void install_libsystem_stubs();
};
