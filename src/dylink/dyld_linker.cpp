#include "dylink/dyld_linker.h"
#include "dylib/dylib_interceptor.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <cstdio>
#include <cstring>
#include <functional>

DyldLinker& DyldLinker::instance() {
    static DyldLinker dl;
    return dl;
}

bool DyldLinker::is_system_dylib(const std::string& path) {
    static const char* prefixes[] = {
        "/usr/lib/", "/System/Library/", "/usr/local/lib/",
        "/usr/lib/swift/", nullptr
    };
    for (int i = 0; prefixes[i]; i++)
        if (path.find(prefixes[i]) == 0) return true;
    return false;
}

void DyldLinker::register_dylib(LoadedDylib lib) {
    for (auto& [name, sym] : lib.exports)
        symbol_map_[name] = sym.value;
    dylibs_.push_back(std::move(lib));
}

GuestPtr DyldLinker::resolve_symbol(const std::string& name) {
    if (name.empty()) {
        std::fprintf(stderr, "[dyld] refusing to resolve an empty symbol name\\n");
        return 0;
    }

    auto it = symbol_map_.find(name);
    if (it != symbol_map_.end()) return it->second;

    auto& di = DylibInterceptor::instance();
    if (di.has_symbol(name)) {
        GuestPtr t = di.allocate_trampoline(name);
        symbol_map_[name] = t;
        return t;
    }

    std::string alt = (name[0] == '_') ? name.substr(1) : "_" + name;
    if (di.has_symbol(alt)) {
        GuestPtr t = di.allocate_trampoline(alt);
        symbol_map_[name] = t;
        return t;
    }

    std::fprintf(stderr, "[dyld] unresolved symbol: %s\n", name.c_str());
    return 0;
}

void DyldLinker::patch_got_slot(uint8_t* host_addr, const std::string& symbol) {
    GuestPtr val = resolve_symbol(symbol);
    if (!val) {
        std::fprintf(stderr, "[dyld] can't patch GOT for %s\n", symbol.c_str());
        return;
    }
    *reinterpret_cast<uint64_t*>(host_addr) = val;
    std::fprintf(stderr, "[dyld] GOT[%s] = 0x%llx\n", symbol.c_str(),
                 (unsigned long long)val);
}

bool DyldLinker::parse_dyld_info(const uint8_t* data, size_t size,
                                  uint64_t slide,
                                  const std::function<uint8_t*(uint64_t)>& g2h) {
    if (!data || size < sizeof(mach_header_64)) return false;
    auto* mh = reinterpret_cast<const mach_header_64*>(data);
    if (mh->magic != MH_MAGIC_64) return false;
    if (mh->sizeofcmds > size - sizeof(mach_header_64)) return false;
    const uint8_t* lc = data + sizeof(mach_header_64);

    const uint8_t* bind_data = nullptr;
    uint32_t       bind_size = 0;
    const uint8_t* lazy_bind_data = nullptr;
    uint32_t       lazy_bind_size = 0;

    const uint8_t* command_end = lc + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc > command_end || static_cast<size_t>(command_end - lc) < sizeof(load_command))
            return false;
        auto* cmd = reinterpret_cast<const load_command*>(lc);
        if (cmd->cmdsize < sizeof(load_command) ||
            static_cast<size_t>(command_end - lc) < cmd->cmdsize) return false;
        if (cmd->cmd == LC_DYLD_INFO || cmd->cmd == LC_DYLD_INFO_ONLY) {
            if (cmd->cmdsize < sizeof(dyld_info_command)) return false;
            auto* di = reinterpret_cast<const dyld_info_command*>(lc);
            if (di->bind_off > size || di->bind_size > size - di->bind_off ||
                di->lazy_bind_off > size || di->lazy_bind_size > size - di->lazy_bind_off)
                return false;
            bind_data      = data + di->bind_off;
            bind_size      = di->bind_size;
            lazy_bind_data = data + di->lazy_bind_off;
            lazy_bind_size = di->lazy_bind_size;
        }
        lc += cmd->cmdsize;
    }

    auto process_binds = [&](const uint8_t* bd, uint32_t bs) {
        if (!bd || !bs) return;
        std::string sym_name;
        uint64_t    seg_offset = 0;
        int         seg_index  = 0;
        int64_t     addend     = 0;
        (void)addend;

        std::vector<uint64_t> seg_vmaddrs;
        const uint8_t* slc = data + sizeof(mach_header_64);
        auto* smh = reinterpret_cast<const mach_header_64*>(data);
        for (uint32_t i = 0; i < smh->ncmds; i++) {
            auto* sc = reinterpret_cast<const load_command*>(slc);
            if (sc->cmd == LC_SEGMENT_64) {
                auto* seg = reinterpret_cast<const segment_command_64*>(slc);
                seg_vmaddrs.push_back(seg->vmaddr + slide);
            }
            slc += sc->cmdsize;
        }

        const uint8_t* p   = bd;
        const uint8_t* end = bd + bs;
        while (p < end) {
            uint8_t byte = *p++;
            uint8_t op   = byte & 0xF0;
            uint8_t imm  = byte & 0x0F;

            switch (op) {
            case 0x00: return; // DONE
            case 0x10: break;  // SET_DYLIB_ORDINAL_IMM
            case 0x20: case 0x30: { // SET_DYLIB_ORDINAL_ULEB / SET_DYLIB_SPECIAL_IMM
                uint64_t v = 0; int sh = 0;
                while (*p & 0x80) { v |= (uint64_t)(*p++ & 0x7F) << sh; sh += 7; }
                v |= (uint64_t)(*p++ & 0x7F) << sh;
                (void)v;
                break;
            }
            case 0x40: { // SET_SYMBOL_TRAILING_FLAGS_IMM
                sym_name = reinterpret_cast<const char*>(p);
                p += sym_name.size() + 1;
                break;
            }
            case 0x50: break; // SET_TYPE_IMM
            case 0x60: { // SET_ADDEND_SLEB
                int64_t v = 0; int sh = 0; uint8_t b2;
                do { b2=*p++; v|=(int64_t)(b2&0x7F)<<sh; sh+=7; } while(b2&0x80);
                if (sh < 64 && (b2 & 0x40)) v |= -(1LL<<sh);
                addend = v;
                break;
            }
            case 0x70: // SET_SEGMENT_AND_OFFSET_ULEB
                seg_index = imm;
                { uint64_t v=0; int sh=0;
                  while(*p&0x80){v|=(uint64_t)(*p++&0x7F)<<sh;sh+=7;}
                  v|=(uint64_t)(*p++&0x7F)<<sh; seg_offset=v; }
                break;
            case 0x80: { // ADD_ADDR_ULEB
                uint64_t v=0; int sh=0;
                while(*p&0x80){v|=(uint64_t)(*p++&0x7F)<<sh;sh+=7;}
                v|=(uint64_t)(*p++&0x7F)<<sh; seg_offset += v;
                break;
            }
            case 0x90: { // DO_BIND
                if (seg_index < (int)seg_vmaddrs.size() && !sym_name.empty()) {
                    uint8_t* host = g2h(seg_vmaddrs[seg_index] + seg_offset);
                    if (host) patch_got_slot(host, sym_name);
                }
                seg_offset += 8;
                break;
            }
            case 0xA0: { // DO_BIND_ADD_ADDR_ULEB
                uint64_t v=0; int sh=0;
                while(*p&0x80){v|=(uint64_t)(*p++&0x7F)<<sh;sh+=7;}
                v|=(uint64_t)(*p++&0x7F)<<sh;
                if (seg_index < (int)seg_vmaddrs.size() && !sym_name.empty()) {
                    uint8_t* host = g2h(seg_vmaddrs[seg_index] + seg_offset);
                    if (host) patch_got_slot(host, sym_name);
                }
                seg_offset += v + 8;
                break;
            }
            case 0xB0: { // DO_BIND_ADD_ADDR_IMM_SCALED
                if (seg_index < (int)seg_vmaddrs.size() && !sym_name.empty()) {
                    uint8_t* host = g2h(seg_vmaddrs[seg_index] + seg_offset);
                    if (host) patch_got_slot(host, sym_name);
                }
                seg_offset += (uint64_t)imm * 8 + 8;
                break;
            }
            case 0xC0: { // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                uint64_t count=0; int sh=0;
                while(*p&0x80){count|=(uint64_t)(*p++&0x7F)<<sh;sh+=7;}
                count|=(uint64_t)(*p++&0x7F)<<sh;
                uint64_t skip=0; sh=0;
                while(*p&0x80){skip|=(uint64_t)(*p++&0x7F)<<sh;sh+=7;}
                skip|=(uint64_t)(*p++&0x7F)<<sh;
                for (uint64_t j=0; j<count; j++) {
                    if (seg_index < (int)seg_vmaddrs.size() && !sym_name.empty()) {
                        uint8_t* host = g2h(seg_vmaddrs[seg_index] + seg_offset);
                        if (host) patch_got_slot(host, sym_name);
                    }
                    seg_offset += skip + 8;
                }
                break;
            }
            default: break;
            }
        }
    };

    process_binds(bind_data, bind_size);
    process_binds(lazy_bind_data, lazy_bind_size);
    return true;
}

bool DyldLinker::parse_chained_fixups(const uint8_t* data, size_t size,
                                       uint64_t slide,
                                       const std::function<uint8_t*(uint64_t)>& g2h) {
    if (!data || size < sizeof(mach_header_64)) return false;
    auto* mh = reinterpret_cast<const mach_header_64*>(data);
    if (mh->magic != MH_MAGIC_64) return false;
    if (mh->sizeofcmds > size - sizeof(mach_header_64)) return false;
    const uint8_t* lc = data + sizeof(mach_header_64);

    const uint8_t* command_end = lc + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc > command_end || static_cast<size_t>(command_end - lc) < sizeof(load_command))
            return false;
        auto* cmd = reinterpret_cast<const load_command*>(lc);
        if (cmd->cmdsize < sizeof(load_command) ||
            static_cast<size_t>(command_end - lc) < cmd->cmdsize) return false;
        if (cmd->cmd == LC_DYLD_CHAINED_FIXUPS) {
            if (cmd->cmdsize < sizeof(linkedit_data_command)) return false;
            auto* cf = reinterpret_cast<const linkedit_data_command*>(lc);
            if (cf->dataoff > size || cf->datasize > size - cf->dataoff ||
                cf->datasize < 28) return false;
            const uint8_t* fixups = data + cf->dataoff;

            struct ChainedHeader {
                uint32_t fixups_version, starts_offset, imports_offset;
                uint32_t symbols_offset, imports_count, imports_format, symbols_format;
            };
            struct ImportEntry {
                uint32_t lib_ordinal : 8;
                uint32_t weak_import : 1;
                uint32_t name_offset : 23;
            };
            auto* hdr = reinterpret_cast<const ChainedHeader*>(fixups);
            const ImportEntry* imports = reinterpret_cast<const ImportEntry*>(
                fixups + hdr->imports_offset);
            const char* sym_pool = reinterpret_cast<const char*>(
                fixups + hdr->symbols_offset);

            std::vector<std::string> import_names;
            for (uint32_t j = 0; j < hdr->imports_count; j++)
                import_names.emplace_back(sym_pool + imports[j].name_offset);

            struct SegStarts {
                uint32_t size; uint16_t first_page_input_file_offset;
                uint16_t page_count; uint16_t page_start[1];
            };
            struct StartsInImage { uint32_t seg_count; uint32_t seg_info_offset[1]; };
            auto* starts = reinterpret_cast<const StartsInImage*>(
                fixups + hdr->starts_offset);

            std::vector<uint64_t> seg_vmaddrs;
            const uint8_t* slc2 = data + sizeof(mach_header_64);
            auto* smh2 = reinterpret_cast<const mach_header_64*>(data);
            for (uint32_t j = 0; j < smh2->ncmds; j++) {
                auto* sc = reinterpret_cast<const load_command*>(slc2);
                if (sc->cmd == LC_SEGMENT_64) {
                    auto* seg = reinterpret_cast<const segment_command_64*>(slc2);
                    seg_vmaddrs.push_back(seg->vmaddr + slide);
                }
                slc2 += sc->cmdsize;
            }

            for (uint32_t s = 0; s < starts->seg_count; s++) {
                if (!starts->seg_info_offset[s]) continue;
                auto* ss = reinterpret_cast<const SegStarts*>(
                    fixups + hdr->starts_offset + starts->seg_info_offset[s]);
                for (uint16_t pg = 0; pg < ss->page_count; pg++) {
                    if (ss->page_start[pg] == 0xFFFF) continue;
                    uint64_t page_addr = (s < seg_vmaddrs.size())
                        ? seg_vmaddrs[s] + pg * 4096 : 0;
                    uint8_t* page_host = g2h(page_addr);
                    if (!page_host) continue;
                    uint64_t chain_off = ss->page_start[pg];
                    while (true) {
                        uint8_t* slot = page_host + chain_off;
                        uint64_t val  = *reinterpret_cast<uint64_t*>(slot);
                        bool is_bind  = (val >> 63) & 1;
                        if (is_bind) {
                            uint32_t ord  = (val >> 32) & 0xFF;
                            uint32_t next = (val >> 51) & 0xFFF;
                            if (ord < import_names.size())
                                patch_got_slot(slot, import_names[ord]);
                            if (!next) break;
                            chain_off += next * 4;
                        } else {
                            uint64_t target = (val & 0x3FFFFFFFFFULL) + slide;
                            *reinterpret_cast<uint64_t*>(slot) = target;
                            uint32_t next = (val >> 51) & 0x7FF;
                            if (!next) break;
                            chain_off += next * 4;
                        }
                    }
                }
            }
        }
        lc += cmd->cmdsize;
    }
    return true;
}

bool DyldLinker::apply_fixups(const uint8_t* data, size_t size,
                               uint64_t slide,
                               const std::function<uint8_t*(uint64_t)>& g2h) {
    if (!data || !g2h) return false;
    std::fprintf(stderr, "[dyld] applying fixups (slide=0x%llx)\n",
                 (unsigned long long)slide);
    const bool classic_ok = parse_dyld_info(data, size, slide, g2h);
    const bool chained_ok = parse_chained_fixups(data, size, slide, g2h);
    return classic_ok && chained_ok;
}

bool DyldLinker::link(const uint8_t* /*data*/, size_t /*size*/,
                       uint64_t /*slide*/,
                       const std::vector<std::string>& required_dylibs) {
    for (auto& path : required_dylibs) {
        if (is_system_dylib(path)) {
            LoadedDylib dl{};
            dl.path = dl.install_name = path;
            dl.base = 0; dl.is_stub_dylib = true;
            register_dylib(std::move(dl));
            std::fprintf(stderr, "[dyld] stub: %s\n", path.c_str());
        } else {
            std::fprintf(stderr, "[dyld] TODO: load bundled dylib %s\n", path.c_str());
        }
    }
    return true;
}
