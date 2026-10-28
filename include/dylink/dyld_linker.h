#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

using GuestPtr = uint64_t;

struct DylibSymbol {
    std::string name;
    GuestPtr    value;
    bool        is_stub;
};

struct LoadedDylib {
    std::string path;
    std::string install_name;
    uint64_t    base;
    bool        is_stub_dylib;
    std::unordered_map<std::string, DylibSymbol> exports;
};

struct Fixup {
    uint64_t    target_vmaddr;
    std::string symbol_name;
    bool        is_bind;
    int64_t     addend;
};

class DyldLinker {
public:
    static DyldLinker& instance();

    bool link(const uint8_t* binary_data, size_t binary_size,
              uint64_t slide,
              const std::vector<std::string>& required_dylibs);

    GuestPtr resolve_symbol(const std::string& name);
    void     patch_got_slot(uint8_t* host_addr, const std::string& symbol);

    bool apply_fixups(const uint8_t* binary_data, size_t binary_size,
                      uint64_t slide,
                      const std::function<uint8_t*(uint64_t)>& guest_to_host);

    void register_dylib(LoadedDylib lib);
    static bool is_system_dylib(const std::string& path);

private:
    DyldLinker() = default;

    bool parse_dyld_info(const uint8_t* data, size_t size,
                         uint64_t slide,
                         const std::function<uint8_t*(uint64_t)>& g2h);
    bool parse_chained_fixups(const uint8_t* data, size_t size,
                               uint64_t slide,
                               const std::function<uint8_t*(uint64_t)>& g2h);
    bool parse_exports(const uint8_t* data, size_t size, uint64_t slide);

    std::vector<LoadedDylib> dylibs_;
    std::unordered_map<std::string, GuestPtr> symbol_map_;
};
