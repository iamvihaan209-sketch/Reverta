#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

using GuestPtr = uint64_t;

// CoreFoundation type IDs (mirrors CF internals)
enum class CFTypeTag : uint32_t {
    String      = 0x01,
    Data        = 0x02,
    Array       = 0x03,
    Dictionary  = 0x04,
    Number      = 0x05,
    Boolean     = 0x06,
    URL         = 0x07,
    Date        = 0x08,
    Error       = 0x09,
    Unknown     = 0xFF,
};

// Host-side CF object header
struct CFObject {
    virtual ~CFObject() = default;
    CFTypeTag   tag;
    uint32_t    retain_count;
    // Payload follows in subclasses
};

struct CFStringObj : CFObject {
    std::string value;
};

struct CFDataObj : CFObject {
    std::vector<uint8_t> bytes;
};

struct CFArrayObj : CFObject {
    std::vector<GuestPtr> items;
};

struct CFDictionaryObj : CFObject {
    std::unordered_map<GuestPtr, GuestPtr> map;
};

struct CFNumberObj : CFObject {
    double value;
    bool   is_integer;
    int64_t int_value;
};

// Foundation / CoreFoundation stub layer.
// Maps ARM64 CF function calls to host implementations.
class FoundationStubs {
public:
    static FoundationStubs& instance();

    // Install all CF/Foundation function stubs into the dylib shim
    void install();

    // CFString
    GuestPtr CFStringCreateWithCString(GuestPtr allocator, const char* cstr, uint32_t encoding);
    const char* CFStringGetCStringPtr(GuestPtr cf_str, uint32_t encoding);
    bool CFStringGetCString(GuestPtr cf_str, char* buf, int64_t buf_size, uint32_t encoding);
    int64_t CFStringGetLength(GuestPtr cf_str);

    // CFData
    GuestPtr CFDataCreate(GuestPtr allocator, const uint8_t* bytes, int64_t length);
    const uint8_t* CFDataGetBytePtr(GuestPtr cf_data);
    int64_t CFDataGetLength(GuestPtr cf_data);

    // CFArray
    GuestPtr CFArrayCreate(GuestPtr allocator, const GuestPtr* values, int64_t count, GuestPtr callbacks);
    int64_t CFArrayGetCount(GuestPtr cf_array);
    GuestPtr CFArrayGetValueAtIndex(GuestPtr cf_array, int64_t idx);

    // CFDictionary
    GuestPtr CFDictionaryCreate(GuestPtr allocator, const GuestPtr* keys, const GuestPtr* vals,
                                 int64_t count, GuestPtr key_cbs, GuestPtr val_cbs);
    int64_t CFDictionaryGetCount(GuestPtr cf_dict);
    GuestPtr CFDictionaryGetValue(GuestPtr cf_dict, GuestPtr key);

    // CFNumber
    GuestPtr CFNumberCreate(GuestPtr allocator, uint32_t type, const void* value_ptr);
    bool CFNumberGetValue(GuestPtr cf_num, uint32_t type, void* out);

    // CFRetain / CFRelease / CFGetRetainCount
    GuestPtr CFRetain(GuestPtr obj);
    void     CFRelease(GuestPtr obj);
    int64_t  CFGetRetainCount(GuestPtr obj);

    // CFGetTypeID
    uint64_t CFGetTypeID(GuestPtr obj);

    // NSURL (toll-free bridged with CFURL)
    GuestPtr NSURLWithString(const char* url_string);

private:
    FoundationStubs() = default;

    CFObject* to_host(GuestPtr ptr) {
        return reinterpret_cast<CFObject*>(ptr);
    }
    GuestPtr to_guest(CFObject* obj) {
        return reinterpret_cast<GuestPtr>(obj);
    }
};
