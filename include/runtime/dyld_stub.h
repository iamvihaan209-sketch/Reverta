#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>
#include <vector>

using GuestPtr = uint64_t;

// ── Dynamic linker stub ───────────────────────────────────────────────────────
// Handles __DATA.__got, __DATA.__la_symbol_ptr, and __DATA.__stub_helper
// patching so that guest calls into system dylibs land in our host stubs
// rather than trying to jump to non-existent ARM64 framework code.

class DyldStub {
public:
    using HostStub = std::function<uint64_t(uint64_t, uint64_t, uint64_t,
                                            uint64_t, uint64_t, uint64_t)>;

    DyldStub();

    // Register all framework stubs (libc, libSystem, CoreFoundation, AppKit…)
    void register_builtins();

    // Patch a loaded binary's GOT and lazy symbol pointer tables
    // so every external symbol redirects to our stubs.
    void patch_got(uint8_t* base, uint64_t slide,
                   const uint8_t* got_section,    size_t got_size,
                   const uint8_t* la_syms_section, size_t la_size,
                   const std::vector<std::string>& import_symbols);

    // Symbol lookup — returns host stub address or 0
    uint64_t resolve(const std::string& symbol) const;

    // Called by interpreter when PC lands on a stub trampoline address
    // Returns {handled, result}
    std::pair<bool, uint64_t> dispatch(uint64_t stub_addr,
        uint64_t a0, uint64_t a1, uint64_t a2,
        uint64_t a3, uint64_t a4, uint64_t a5);

private:
    std::unordered_map<std::string, HostStub> stubs_;
    std::unordered_map<uint64_t, std::string> addr_to_sym_; // trampoline addr → symbol

    void register_libsystem();
    void register_libc();
    void register_libdispatch();
    void register_corefoundation();
    void register_foundation();
    void register_appkit();
    void register_objc_runtime();
};
