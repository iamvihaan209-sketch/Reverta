#include "foundation/foundation_stubs.h"
#include <cstdlib>
#include <cstdio>
#include <cstring>

FoundationStubs& FoundationStubs::instance() {
    static FoundationStubs fb;
    return fb;
}

// ── CFString ──────────────────────────────────────────────────────────────────
GuestPtr FoundationStubs::CFStringCreateWithCString(GuestPtr /*alloc*/,
                                                     const char* cstr,
                                                     uint32_t /*enc*/) {
    auto* obj = new CFStringObj();
    obj->tag          = CFTypeTag::String;
    obj->retain_count = 1;
    obj->value        = cstr ? cstr : "";
    std::fprintf(stderr, "[CF] CFStringCreateWithCString \"%s\"\n", obj->value.c_str());
    return to_guest(obj);
}

const char* FoundationStubs::CFStringGetCStringPtr(GuestPtr cf_str, uint32_t /*enc*/) {
    auto* obj = dynamic_cast<CFStringObj*>(to_host(cf_str));
    return obj ? obj->value.c_str() : nullptr;
}

bool FoundationStubs::CFStringGetCString(GuestPtr cf_str, char* buf,
                                          int64_t buf_size, uint32_t /*enc*/) {
    auto* obj = dynamic_cast<CFStringObj*>(to_host(cf_str));
    if (!obj || !buf || buf_size <= 0) return false;
    ::strncpy(buf, obj->value.c_str(), (size_t)buf_size - 1);
    buf[buf_size - 1] = '\0';
    return true;
}

int64_t FoundationStubs::CFStringGetLength(GuestPtr cf_str) {
    auto* obj = dynamic_cast<CFStringObj*>(to_host(cf_str));
    return obj ? (int64_t)obj->value.size() : 0;
}

// ── CFData ────────────────────────────────────────────────────────────────────
GuestPtr FoundationStubs::CFDataCreate(GuestPtr /*alloc*/,
                                        const uint8_t* bytes, int64_t length) {
    auto* obj = new CFDataObj();
    obj->tag          = CFTypeTag::Data;
    obj->retain_count = 1;
    if (bytes && length > 0)
        obj->bytes.assign(bytes, bytes + length);
    return to_guest(obj);
}

const uint8_t* FoundationStubs::CFDataGetBytePtr(GuestPtr cf_data) {
    auto* obj = dynamic_cast<CFDataObj*>(to_host(cf_data));
    return obj && !obj->bytes.empty() ? obj->bytes.data() : nullptr;
}

int64_t FoundationStubs::CFDataGetLength(GuestPtr cf_data) {
    auto* obj = dynamic_cast<CFDataObj*>(to_host(cf_data));
    return obj ? (int64_t)obj->bytes.size() : 0;
}

// ── CFArray ───────────────────────────────────────────────────────────────────
GuestPtr FoundationStubs::CFArrayCreate(GuestPtr /*alloc*/,
                                         const GuestPtr* values, int64_t count,
                                         GuestPtr /*callbacks*/) {
    auto* obj = new CFArrayObj();
    obj->tag          = CFTypeTag::Array;
    obj->retain_count = 1;
    for (int64_t i = 0; i < count; i++)
        obj->items.push_back(values[i]);
    return to_guest(obj);
}

int64_t FoundationStubs::CFArrayGetCount(GuestPtr cf_array) {
    auto* obj = dynamic_cast<CFArrayObj*>(to_host(cf_array));
    return obj ? (int64_t)obj->items.size() : 0;
}

GuestPtr FoundationStubs::CFArrayGetValueAtIndex(GuestPtr cf_array, int64_t idx) {
    auto* obj = dynamic_cast<CFArrayObj*>(to_host(cf_array));
    if (!obj || idx < 0 || idx >= (int64_t)obj->items.size()) return 0;
    return obj->items[(size_t)idx];
}

// ── CFDictionary ──────────────────────────────────────────────────────────────
GuestPtr FoundationStubs::CFDictionaryCreate(GuestPtr /*alloc*/,
                                              const GuestPtr* keys,
                                              const GuestPtr* vals,
                                              int64_t count,
                                              GuestPtr /*kcb*/, GuestPtr /*vcb*/) {
    auto* obj = new CFDictionaryObj();
    obj->tag          = CFTypeTag::Dictionary;
    obj->retain_count = 1;
    for (int64_t i = 0; i < count; i++)
        obj->map[keys[i]] = vals[i];
    return to_guest(obj);
}

int64_t FoundationStubs::CFDictionaryGetCount(GuestPtr cf_dict) {
    auto* obj = dynamic_cast<CFDictionaryObj*>(to_host(cf_dict));
    return obj ? (int64_t)obj->map.size() : 0;
}

GuestPtr FoundationStubs::CFDictionaryGetValue(GuestPtr cf_dict, GuestPtr key) {
    auto* obj = dynamic_cast<CFDictionaryObj*>(to_host(cf_dict));
    if (!obj) return 0;
    auto it = obj->map.find(key);
    return it != obj->map.end() ? it->second : 0;
}

// ── CFNumber ──────────────────────────────────────────────────────────────────
GuestPtr FoundationStubs::CFNumberCreate(GuestPtr /*alloc*/,
                                          uint32_t type, const void* value_ptr) {
    auto* obj = new CFNumberObj();
    obj->tag          = CFTypeTag::Number;
    obj->retain_count = 1;
    // type: 1=SInt8..9=SInt64, 10=Float32, 11=Float64
    switch (type) {
    case 1: obj->int_value = *static_cast<const int8_t*>(value_ptr);  obj->is_integer = true; break;
    case 2: obj->int_value = *static_cast<const int16_t*>(value_ptr); obj->is_integer = true; break;
    case 3: obj->int_value = *static_cast<const int32_t*>(value_ptr); obj->is_integer = true; break;
    case 4: obj->int_value = *static_cast<const int64_t*>(value_ptr); obj->is_integer = true; break;
    case 10: obj->value = *static_cast<const float*>(value_ptr);  obj->is_integer = false; break;
    case 11: obj->value = *static_cast<const double*>(value_ptr); obj->is_integer = false; break;
    default: obj->int_value = 0; obj->is_integer = true; break;
    }
    return to_guest(obj);
}

bool FoundationStubs::CFNumberGetValue(GuestPtr cf_num, uint32_t type, void* out) {
    auto* obj = dynamic_cast<CFNumberObj*>(to_host(cf_num));
    if (!obj || !out) return false;
    switch (type) {
    case 3: *static_cast<int32_t*>(out) = (int32_t)obj->int_value; break;
    case 4: *static_cast<int64_t*>(out) = obj->int_value; break;
    case 11: *static_cast<double*>(out) = obj->is_integer ? (double)obj->int_value : obj->value; break;
    default: return false;
    }
    return true;
}

// ── Retain / Release ──────────────────────────────────────────────────────────
GuestPtr FoundationStubs::CFRetain(GuestPtr obj_ptr) {
    auto* obj = to_host(obj_ptr);
    if (obj) obj->retain_count++;
    return obj_ptr;
}

void FoundationStubs::CFRelease(GuestPtr obj_ptr) {
    auto* obj = to_host(obj_ptr);
    if (!obj) return;
    if (--obj->retain_count <= 0) {
        delete obj;
    }
}

int64_t FoundationStubs::CFGetRetainCount(GuestPtr obj_ptr) {
    auto* obj = to_host(obj_ptr);
    return obj ? obj->retain_count : 0;
}

uint64_t FoundationStubs::CFGetTypeID(GuestPtr obj_ptr) {
    auto* obj = to_host(obj_ptr);
    return obj ? static_cast<uint64_t>(obj->tag) : 0;
}

GuestPtr FoundationStubs::NSURLWithString(const char* url_string) {
    // Reuse CFString as a simple stub
    return CFStringCreateWithCString(0, url_string, 0);
}

void FoundationStubs::install() {
    std::fprintf(stderr, "[foundation] stubs installed\n");
    // Actual symbol binding happens in dylib shim (dylib_interceptor.cpp)
}
