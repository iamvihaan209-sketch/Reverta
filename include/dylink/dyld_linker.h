#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <unordered_set>
#include "loader/macho_loader.h"

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
              const std::vector<std::string>& required_dylibs,
              const std::string& executable_path = {},
              const std::vector<std::string>& executable_rpaths = {});

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
    bool load_dependency(const std::string& install_name,
                         const std::string& loader_path,
                         const std::string& executable_path,
                         const std::vector<std::string>& loader_rpaths,
                         const std::vector<std::string>& executable_rpaths,
                         size_t depth);

    std::vector<LoadedDylib> dylibs_;
    std::unordered_map<std::string, GuestPtr> symbol_map_;
    std::vector<LoadedBinary> loaded_binaries_;
    std::unordered_set<std::string> loaded_paths_;
    std::unordered_set<std::string> loading_paths_;
    uint64_t next_dylib_slide_ = 0x1000000000ULL;
};
