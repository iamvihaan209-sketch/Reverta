#include "dylink/dyld_linker.h"
#include "dylib/dylib_interceptor.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <functional>
#include <unordered_set>

namespace {
bool read_uleb128(const uint8_t*& p, const uint8_t* end, uint64_t& value) {
    value = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 10 && p < end; ++i) {
        const uint8_t byte = *p++;
        const uint8_t payload = byte & 0x7f;
        if (shift == 63 && payload > 1) return false;
        if (shift > 63 && payload != 0) return false;
        if (shift < 64) value |= static_cast<uint64_t>(payload) << shift;
        if ((byte & 0x80) == 0) return true;
        shift += 7;
    }
    return false;
}

bool read_sleb128(const uint8_t*& p, const uint8_t* end, int64_t& value) {
    uint64_t bits = 0;
    unsigned shift = 0;
    uint8_t byte = 0;
    for (unsigned i = 0; i < 10 && p < end; ++i) {
        byte = *p++;
        const uint8_t payload = byte & 0x7f;
        if (shift == 63 && payload != 0 && payload != 0x7f) return false;
        if (shift < 64) bits |= static_cast<uint64_t>(payload) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40)) bits |= (~uint64_t{0}) << shift;
            value = static_cast<int64_t>(bits);
            return true;
        }
    }
    return false;
}
} // namespace

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

    const uint8_t* rebase_data = nullptr;
    uint32_t       rebase_size = 0;
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
            if (di->rebase_off > size || di->rebase_size > size - di->rebase_off ||
                di->bind_off > size || di->bind_size > size - di->bind_off ||
                di->lazy_bind_off > size || di->lazy_bind_size > size - di->lazy_bind_off)
                return false;
            rebase_data    = data + di->rebase_off;
            rebase_size    = di->rebase_size;
            bind_data      = data + di->bind_off;
            bind_size      = di->bind_size;
            lazy_bind_data = data + di->lazy_bind_off;
            lazy_bind_size = di->lazy_bind_size;
        }
        lc += cmd->cmdsize;
    }

    auto process_rebases = [&](const uint8_t* rd, uint32_t rs) -> bool {
        if (rs == 0) return true;
        if (!rd) return false;
        std::vector<uint64_t> seg_vmaddrs;
        const uint8_t* slc = data + sizeof(mach_header_64);
        for (uint32_t i = 0; i < mh->ncmds; ++i) {
            const auto* sc = reinterpret_cast<const load_command*>(slc);
            if (sc->cmd == LC_SEGMENT_64) {
                const auto* seg = reinterpret_cast<const segment_command_64*>(slc);
                if (seg->vmaddr > UINT64_MAX - slide) return false;
                seg_vmaddrs.push_back(seg->vmaddr + slide);
            }
            slc += sc->cmdsize;
        }

        const uint8_t* p = rd;
        const uint8_t* end = rd + rs;
        uint32_t seg_index = 0;
        uint64_t seg_offset = 0;
        uint8_t type = 1; // DYLD_REBASE_TYPE_POINTER
        auto rebase_once = [&]() -> bool {
            if (type != 1 || seg_index >= seg_vmaddrs.size() ||
                seg_offset > UINT64_MAX - seg_vmaddrs[seg_index]) return false;
            uint8_t* host = g2h(seg_vmaddrs[seg_index] + seg_offset);
            if (!host) return false;
            uint64_t value = 0;
            std::memcpy(&value, host, sizeof(value));
            if (value > UINT64_MAX - slide) return false;
            value += slide;
            std::memcpy(host, &value, sizeof(value));
            return true;
        };

        while (p < end) {
            const uint8_t byte = *p++;
            const uint8_t op = byte & 0xf0;
            const uint8_t imm = byte & 0x0f;
            uint64_t u = 0;
            switch (op) {
            case 0x00: return true; // DONE
            case 0x10: // SET_TYPE_IMM
                if (imm != 1) {
                    std::fprintf(stderr, "[dyld] unsupported classic rebase type %u\n", imm);
                    return false;
                }
                type = imm;
                break;
            case 0x20: // SET_SEGMENT_AND_OFFSET_ULEB
                seg_index = imm;
                if (!read_uleb128(p, end, seg_offset)) return false;
                break;
            case 0x30: // ADD_ADDR_ULEB
                if (!read_uleb128(p, end, u) || u > UINT64_MAX - seg_offset) return false;
                seg_offset += u;
                break;
            case 0x40: // ADD_ADDR_IMM_SCALED
                if (seg_offset > UINT64_MAX - static_cast<uint64_t>(imm) * 8) return false;
                seg_offset += static_cast<uint64_t>(imm) * 8;
                break;
            case 0x50: // DO_REBASE_IMM_TIMES
                for (uint8_t n = 0; n < imm; ++n) {
                    if (!rebase_once() || seg_offset > UINT64_MAX - 8) return false;
                    seg_offset += 8;
                }
                break;
            case 0x60: // DO_REBASE_ULEB_TIMES
                if (!read_uleb128(p, end, u) || u > rs) return false;
                for (uint64_t n = 0; n < u; ++n) {
                    if (!rebase_once() || seg_offset > UINT64_MAX - 8) return false;
                    seg_offset += 8;
                }
                break;
            case 0x70: // DO_REBASE_ADD_ADDR_ULEB
                if (!read_uleb128(p, end, u) || !rebase_once() ||
                    seg_offset > UINT64_MAX - 8 || u > UINT64_MAX - seg_offset - 8) return false;
                seg_offset += u + 8;
                break;
            case 0x80: { // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                uint64_t count = 0, skip = 0;
                if (!read_uleb128(p, end, count) || !read_uleb128(p, end, skip) ||
                    count > rs) return false;
                for (uint64_t n = 0; n < count; ++n) {
                    if (!rebase_once() || seg_offset > UINT64_MAX - 8 ||
                        skip > UINT64_MAX - seg_offset - 8) return false;
                    seg_offset += skip + 8;
                }
                break;
            }
            default:
                return false;
            }
        }
        return true;
    };

    auto process_binds = [&](const uint8_t* bd, uint32_t bs) -> bool {
        if (bs == 0) return true;
        if (!bd) return false;

        std::vector<uint64_t> seg_vmaddrs;
        const uint8_t* slc = data + sizeof(mach_header_64);
        for (uint32_t i = 0; i < mh->ncmds; ++i) {
            const auto* sc = reinterpret_cast<const load_command*>(slc);
            if (sc->cmd == LC_SEGMENT_64) {
                const auto* seg = reinterpret_cast<const segment_command_64*>(slc);
                if (seg->vmaddr > UINT64_MAX - slide) return false;
                seg_vmaddrs.push_back(seg->vmaddr + slide);
            }
            slc += sc->cmdsize;
        }

        const uint8_t* p = bd;
        const uint8_t* end = bd + bs;
        std::string sym_name;
        uint64_t seg_offset = 0;
        uint32_t seg_index = 0;
        int64_t addend = 0;
        (void)addend;

        auto bind_once = [&]() -> bool {
            if (seg_index >= seg_vmaddrs.size() || sym_name.empty()) return false;
            if (seg_offset > UINT64_MAX - seg_vmaddrs[seg_index]) return false;
            uint8_t* host = g2h(seg_vmaddrs[seg_index] + seg_offset);
            if (!host) {
                std::fprintf(stderr, "[dyld] bind target is not mapped: %s\n", sym_name.c_str());
                return false;
            }
            const GuestPtr resolved = resolve_symbol(sym_name);
            if (!resolved) return false;
            const GuestPtr value = resolved + static_cast<uint64_t>(addend);
            std::memcpy(host, &value, sizeof(value));
            return true;
        };

        while (p < end) {
            const uint8_t byte = *p++;
            const uint8_t op = byte & 0xf0;
            const uint8_t imm = byte & 0x0f;
            uint64_t u = 0;
            switch (op) {
            case 0x00: return true; // DONE
            case 0x10: // SET_DYLIB_ORDINAL_IMM
            case 0x30: // SET_DYLIB_SPECIAL_IMM
            case 0x50: // SET_TYPE_IMM
                break;
            case 0x20: // SET_DYLIB_ORDINAL_ULEB
                if (!read_uleb128(p, end, u)) return false;
                break;
            case 0x40: { // SET_SYMBOL_TRAILING_FLAGS_IMM
                const void* nul = std::memchr(p, '\0', static_cast<size_t>(end - p));
                if (!nul) return false;
                const auto* terminator = static_cast<const uint8_t*>(nul);
                sym_name.assign(reinterpret_cast<const char*>(p),
                                static_cast<size_t>(terminator - p));
                p = terminator + 1;
                break;
            }
            case 0x60: // SET_ADDEND_SLEB
                if (!read_sleb128(p, end, addend)) return false;
                break;
            case 0x70: // SET_SEGMENT_AND_OFFSET_ULEB
                seg_index = imm;
                if (!read_uleb128(p, end, seg_offset)) return false;
                break;
            case 0x80: // ADD_ADDR_ULEB
                if (!read_uleb128(p, end, u) || u > UINT64_MAX - seg_offset) return false;
                seg_offset += u;
                break;
            case 0x90: // DO_BIND
                if (!bind_once() || seg_offset > UINT64_MAX - 8) return false;
                seg_offset += 8;
                break;
            case 0xa0: // DO_BIND_ADD_ADDR_ULEB
                if (!read_uleb128(p, end, u) || !bind_once() ||
                    seg_offset > UINT64_MAX - 8 || u > UINT64_MAX - seg_offset - 8) return false;
                seg_offset += u + 8;
                break;
            case 0xb0: // DO_BIND_ADD_ADDR_IMM_SCALED
                if (!bind_once() || seg_offset > UINT64_MAX - (static_cast<uint64_t>(imm) * 8 + 8))
                    return false;
                seg_offset += static_cast<uint64_t>(imm) * 8 + 8;
                break;
            case 0xc0: { // DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                uint64_t count = 0, skip = 0;
                if (!read_uleb128(p, end, count) || !read_uleb128(p, end, skip) ||
                    count > bs) return false;
                for (uint64_t n = 0; n < count; ++n) {
                    if (!bind_once() || seg_offset > UINT64_MAX - 8 || skip > UINT64_MAX - seg_offset - 8) return false;
                    seg_offset += skip + 8;
                }
                break;
            }
            default:
                // Threaded binds and unknown future opcodes are not implemented.
                return false;
            }
        }
        return true;
    };
    return process_rebases(rebase_data, rebase_size) &&
           process_binds(bind_data, bind_size) &&
           process_binds(lazy_bind_data, lazy_bind_size);
}

bool DyldLinker::parse_chained_fixups(const uint8_t* data, size_t size,
                                       uint64_t slide,
                                       const std::function<uint8_t*(uint64_t)>& g2h) {
    if (!data || size < sizeof(mach_header_64) || !g2h) return false;
    const auto* mh = reinterpret_cast<const mach_header_64*>(data);
    if (mh->magic != MH_MAGIC_64 ||
        mh->sizeofcmds > size - sizeof(mach_header_64)) return false;

    const uint8_t* cursor = data + sizeof(mach_header_64);
    const uint8_t* command_end = cursor + mh->sizeofcmds;
    const linkedit_data_command* fixup_cmd = nullptr;
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (static_cast<size_t>(command_end - cursor) < sizeof(load_command)) return false;
        const auto* cmd = reinterpret_cast<const load_command*>(cursor);
        if (cmd->cmdsize < sizeof(load_command) ||
            cmd->cmdsize > static_cast<size_t>(command_end - cursor)) return false;
        if (cmd->cmd == LC_DYLD_CHAINED_FIXUPS) {
            if (cmd->cmdsize < sizeof(linkedit_data_command) || fixup_cmd) return false;
            fixup_cmd = reinterpret_cast<const linkedit_data_command*>(cursor);
        }
        cursor += cmd->cmdsize;
    }
    if (!fixup_cmd) return true;

    if (fixup_cmd->dataoff > size || fixup_cmd->datasize > size - fixup_cmd->dataoff ||
        fixup_cmd->datasize < 28) return false;
    const uint8_t* payload = data + fixup_cmd->dataoff;
    const size_t payload_size = fixup_cmd->datasize;
    struct ChainedHeader {
        uint32_t fixups_version, starts_offset, imports_offset;
        uint32_t symbols_offset, imports_count, imports_format, symbols_format;
    } header{};
    std::memcpy(&header, payload, sizeof(header));
    if (header.fixups_version != 0 || header.starts_offset > payload_size ||
        header.imports_offset > payload_size || header.symbols_offset > payload_size ||
        header.symbols_format != 0) return false;

    size_t import_entry_size = 0;
    switch (header.imports_format) {
    case 1: import_entry_size = 4; break;  // DYLD_CHAINED_IMPORT
    case 2: import_entry_size = 8; break;  // DYLD_CHAINED_IMPORT_ADDEND
    case 3: import_entry_size = 16; break; // DYLD_CHAINED_IMPORT_ADDEND64
    default:
        std::fprintf(stderr, "[dyld] unsupported chained import format %u\n",
                     header.imports_format);
        return false;
    }
    if (header.imports_count >
        (payload_size - header.imports_offset) / import_entry_size) return false;

    std::vector<std::string> import_names;
    std::vector<int64_t> import_addends;
    import_names.reserve(header.imports_count);
    import_addends.reserve(header.imports_count);
    for (uint32_t i = 0; i < header.imports_count; ++i) {
        const uint8_t* entry = payload + header.imports_offset +
                               static_cast<size_t>(i) * import_entry_size;
        uint64_t raw = 0;
        std::memcpy(&raw, entry, header.imports_format == 3 ? 8 : 4);
        uint32_t name_offset = 0;
        int64_t addend = 0;
        if (header.imports_format == 3) {
            name_offset = static_cast<uint32_t>(raw >> 32);
            std::memcpy(&addend, entry + 8, sizeof(addend));
        } else {
            name_offset = static_cast<uint32_t>(raw >> 9);
            if (header.imports_format == 2) {
                int32_t small_addend = 0;
                std::memcpy(&small_addend, entry + 4, sizeof(small_addend));
                addend = small_addend;
            }
        }
        if (name_offset >= payload_size - header.symbols_offset) return false;
        const char* name = reinterpret_cast<const char*>(
            payload + header.symbols_offset + name_offset);
        const size_t remaining = payload_size - header.symbols_offset - name_offset;
        const void* nul = std::memchr(name, '\0', remaining);
        if (!nul) return false;
        import_names.emplace_back(name, static_cast<const char*>(nul) - name);
        import_addends.push_back(addend);
    }

    if (header.starts_offset > payload_size - sizeof(uint32_t)) return false;
    uint32_t segment_count = 0;
    std::memcpy(&segment_count, payload + header.starts_offset, sizeof(segment_count));
    const size_t starts_header_size = sizeof(uint32_t) +
        static_cast<size_t>(segment_count) * sizeof(uint32_t);
    if (segment_count > (payload_size - header.starts_offset - sizeof(uint32_t)) /
                        sizeof(uint32_t)) return false;
    const uint8_t* segment_offsets = payload + header.starts_offset + sizeof(uint32_t);

    std::vector<uint64_t> segment_vmaddrs;
    std::vector<uint64_t> segment_vmsizes;
    uint64_t image_base = UINT64_MAX;
    cursor = data + sizeof(mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        const auto* cmd = reinterpret_cast<const load_command*>(cursor);
        if (cmd->cmd == LC_SEGMENT_64) {
            const auto* seg = reinterpret_cast<const segment_command_64*>(cursor);
            if (seg->vmaddr > UINT64_MAX - slide) return false;
            const uint64_t guest_base = seg->vmaddr + slide;
            if (seg->vmsize > UINT64_MAX - guest_base) return false;
            segment_vmaddrs.push_back(guest_base);
            segment_vmsizes.push_back(seg->vmsize);
            if (std::strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0)
                image_base = guest_base;
        }
        cursor += cmd->cmdsize;
    }
    if (image_base == UINT64_MAX && !segment_vmaddrs.empty())
        image_base = *std::min_element(segment_vmaddrs.begin(), segment_vmaddrs.end());
    if (segment_count > segment_vmaddrs.size()) return false;
    (void)starts_header_size;

    for (uint32_t si = 0; si < segment_count; ++si) {
        uint32_t info_offset = 0;
        std::memcpy(&info_offset, segment_offsets + static_cast<size_t>(si) * 4, 4);
        if (!info_offset) continue;
        if (info_offset > payload_size - header.starts_offset) return false;
        const size_t info_pos = static_cast<size_t>(header.starts_offset) + info_offset;
        if (info_pos > payload_size || payload_size - info_pos < 22) return false;
        const uint8_t* info = payload + info_pos;
        uint32_t info_size = 0;
        uint16_t page_size = 0, pointer_format = 0, page_count = 0;
        std::memcpy(&info_size, info, 4);
        std::memcpy(&page_size, info + 4, 2);
        std::memcpy(&pointer_format, info + 6, 2);
        std::memcpy(&page_count, info + 20, 2);
        if (info_size < 22 || info_size > payload_size - info_pos ||
            (page_size != 4096 && page_size != 16384) ||
            (pointer_format != 2 && pointer_format != 6) ||
            page_count > (info_size - 22) / 2 ||
            segment_vmsizes[si] == 0) return false;
        const uint8_t* page_starts = info + 22;
        const size_t starts_array_count = (info_size - 22) / 2;

        for (uint16_t page = 0; page < page_count; ++page) {
            uint16_t raw_start = 0;
            std::memcpy(&raw_start, page_starts + static_cast<size_t>(page) * 2, 2);
            if (raw_start == 0xffff) continue;
            std::vector<uint16_t> starts_for_page;
            if (raw_start & 0x8000) {
                size_t idx = raw_start & 0x7fff;
                bool last = false;
                while (idx < starts_array_count) {
                    uint16_t entry = 0;
                    std::memcpy(&entry, page_starts + idx * 2, 2);
                    starts_for_page.push_back(entry & 0x7fff);
                    ++idx;
                    if (entry & 0x8000) { last = true; break; }
                }
                if (!last) return false;
            } else {
                starts_for_page.push_back(raw_start);
            }

            const uint64_t page_offset = static_cast<uint64_t>(page) * page_size;
            if (page_offset >= segment_vmsizes[si]) return false;
            const uint64_t bytes_in_page = std::min<uint64_t>(
                page_size, segment_vmsizes[si] - page_offset);
            for (uint16_t start_off : starts_for_page) {
                uint64_t chain_off = start_off;
                for (uint64_t hops = 0; hops <= page_size / 4; ++hops) {
                    if (chain_off > bytes_in_page || bytes_in_page - chain_off < 8)
                        return false;
                    const uint64_t guest_slot = segment_vmaddrs[si] + page_offset + chain_off;
                    uint8_t* slot = g2h(guest_slot);
                    if (!slot) return false;
                    uint64_t value = 0;
                    std::memcpy(&value, slot, sizeof(value));
                    const bool is_bind = (value >> 63) != 0;
                    const uint32_t next = static_cast<uint32_t>((value >> 51) & 0xfff);
                    if (is_bind) {
                        const uint32_t ordinal = static_cast<uint32_t>(value & 0xffffff);
                        if (ordinal >= import_names.size()) return false;
                        const int8_t pointer_addend = static_cast<int8_t>((value >> 24) & 0xff);
                        const GuestPtr resolved = resolve_symbol(import_names[ordinal]);
                        if (!resolved) return false;
                        const uint64_t bound = resolved +
                            static_cast<uint64_t>(import_addends[ordinal]) +
                            static_cast<uint64_t>(static_cast<int64_t>(pointer_addend));
                        std::memcpy(slot, &bound, sizeof(bound));
                    } else {
                        uint64_t target = value & ((uint64_t{1} << 36) - 1);
                        if (pointer_format == 2) {
                            target |= ((value >> 36) & 0xff) << 56;
                            if (target > UINT64_MAX - slide) return false;
                            target += slide;
                        } else {
                            if (target > UINT64_MAX - image_base) return false;
                            target += image_base;
                        }
                        std::memcpy(slot, &target, sizeof(target));
                    }
                    if (next == 0) break;
                    if (hops == page_size / 4 ||
                        next > (bytes_in_page - chain_off - 8) / 4) return false;
                    chain_off += static_cast<uint64_t>(next) * 4;
                }
            }
        }
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

bool DyldLinker::parse_exports(const uint8_t* data, size_t size, uint64_t slide) {
    if (!data || size < sizeof(mach_header_64)) return false;
    const auto* mh = reinterpret_cast<const mach_header_64*>(data);
    if (mh->magic != MH_MAGIC_64 ||
        mh->sizeofcmds > size - sizeof(mach_header_64)) return false;

    uint32_t export_off = 0, export_size = 0;
    bool found_exports = false;
    uint64_t image_base = 0;
    const uint8_t* cursor = data + sizeof(mach_header_64);
    const uint8_t* command_end = cursor + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (static_cast<size_t>(command_end - cursor) < sizeof(load_command)) return false;
        const auto* cmd = reinterpret_cast<const load_command*>(cursor);
        if (cmd->cmdsize < sizeof(load_command) ||
            cmd->cmdsize > static_cast<size_t>(command_end - cursor)) return false;
        if (cmd->cmd == LC_SEGMENT_64) {
            if (cmd->cmdsize < sizeof(segment_command_64)) return false;
            const auto* seg = reinterpret_cast<const segment_command_64*>(cursor);
            if (std::strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0) {
                if (seg->vmaddr > UINT64_MAX - slide) return false;
                image_base = seg->vmaddr + slide;
            }
        } else if (cmd->cmd == LC_DYLD_EXPORTS_TRIE) {
            if (cmd->cmdsize < sizeof(linkedit_data_command) || found_exports) return false;
            const auto* ex = reinterpret_cast<const linkedit_data_command*>(cursor);
            export_off = ex->dataoff;
            export_size = ex->datasize;
            found_exports = true;
        } else if (cmd->cmd == LC_DYLD_INFO || cmd->cmd == LC_DYLD_INFO_ONLY) {
            if (cmd->cmdsize < sizeof(dyld_info_command)) return false;
            const auto* di = reinterpret_cast<const dyld_info_command*>(cursor);
            if (di->export_size) {
                if (found_exports) return false;
                export_off = di->export_off;
                export_size = di->export_size;
                found_exports = true;
            }
        }
        cursor += cmd->cmdsize;
    }
    if (!found_exports || export_size == 0) return true;
    if (export_off > size || export_size > size - export_off) return false;
    if (image_base == 0) {
        std::fprintf(stderr, "[dyld] export trie present without a __TEXT segment\n");
        return false;
    }

    const uint8_t* trie = data + export_off;
    const size_t trie_size = export_size;
    std::unordered_set<uint64_t> active;
    std::unordered_map<std::string, GuestPtr> parsed_exports;
    size_t nodes_visited = 0;
    std::function<bool(uint64_t, const std::string&, size_t)> walk;
    walk = [&](uint64_t offset, const std::string& prefix, size_t depth) -> bool {
        if (depth > 1024 || offset >= trie_size || ++nodes_visited > 100000 ||
            !active.insert(offset).second) return false;
        const uint8_t* p = trie + offset;
        const uint8_t* end = trie + trie_size;
        uint64_t terminal_size = 0;
        if (!read_uleb128(p, end, terminal_size) ||
            terminal_size > static_cast<uint64_t>(end - p)) {
            active.erase(offset);
            return false;
        }
        const uint8_t* terminal_end = p + terminal_size;
        if (terminal_size != 0) {
            uint64_t flags = 0, address = 0;
            if (!read_uleb128(p, terminal_end, flags) ||
                (flags & 0x08) != 0 || (flags & 0x10) != 0 || (flags & ~uint64_t{0x1f}) != 0 ||
                !read_uleb128(p, terminal_end, address)) {
                active.erase(offset);
                std::fprintf(stderr, "[dyld] unsupported or malformed export terminal for %s\n",
                             prefix.c_str());
                return false;
            }
            const uint64_t kind = flags & 0x03;
            if (kind == 1) {
                active.erase(offset);
                std::fprintf(stderr, "[dyld] thread-local export is unsupported: %s\n",
                             prefix.c_str());
                return false;
            }
            uint64_t value = address;
            if (kind == 0) {
                if (address > UINT64_MAX - image_base) {
                    active.erase(offset);
                    return false;
                }
                value = image_base + address;
            }
            if (!prefix.empty()) parsed_exports[prefix] = value;
        }
        p = terminal_end;
        if (p >= end) {
            active.erase(offset);
            return false;
        }
        const uint8_t child_count = *p++;
        for (uint8_t child = 0; child < child_count; ++child) {
            const uint8_t* nul = static_cast<const uint8_t*>(
                std::memchr(p, '\0', static_cast<size_t>(end - p)));
            if (!nul) {
                active.erase(offset);
                return false;
            }
            const std::string edge(reinterpret_cast<const char*>(p),
                                   static_cast<size_t>(nul - p));
            p = nul + 1;
            uint64_t child_offset = 0;
            if (edge.empty() || !read_uleb128(p, end, child_offset) ||
                child_offset >= trie_size || !walk(child_offset, prefix + edge, depth + 1)) {
                active.erase(offset);
                return false;
            }
        }
        active.erase(offset);
        return true;
    };
    if (!walk(0, std::string{}, 0)) {
        std::fprintf(stderr, "[dyld] failed to parse export trie safely\n");
        return false;
    }
    for (const auto& [name, value] : parsed_exports)
        symbol_map_[name] = value;
    return true;
}

bool DyldLinker::link(const uint8_t* data, size_t size,
                       uint64_t slide,
                       const std::vector<std::string>& required_dylibs) {
    if (!parse_exports(data, size, slide)) return false;
    for (auto& path : required_dylibs) {
        if (is_system_dylib(path)) {
            LoadedDylib dl{};
            dl.path = dl.install_name = path;
            dl.base = 0; dl.is_stub_dylib = true;
            register_dylib(std::move(dl));
            std::fprintf(stderr, "[dyld] stub: %s\n", path.c_str());
        } else {
            std::fprintf(stderr, "[dyld] bundled dylib loading is not implemented: %s\n", path.c_str());
            return false;
        }
    }
    return true;
}
