#include "appkit/appkit_stubs.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

AppKitStubs& AppKitStubs::instance() {
    static AppKitStubs ak;
    return ak;
}

// ── NSApplication ─────────────────────────────────────────────────────────────
GuestPtr AppKitStubs::NSApplication_sharedApplication() {
    if (!shared_app_) {
        auto* mem = static_cast<uint64_t*>(::calloc(1, 64));
        shared_app_ = reinterpret_cast<GuestPtr>(mem);
        std::fprintf(stderr, "[appkit] NSApplication sharedApplication → 0x%llx\n",
                     (unsigned long long)shared_app_);
    }
    return shared_app_;
}

void AppKitStubs::NSApplication_run(GuestPtr /*app*/) {
    std::fprintf(stderr, "[appkit] NSApplication run — stub event loop starting\n");
    running_ = true;
    // In a real implementation this would pump a CFRunLoop.
    // For now just return immediately so the process doesn't hang.
    std::fprintf(stderr, "[appkit] NSApplication run — stub event loop exiting\n");
}

void AppKitStubs::NSApplication_setDelegate(GuestPtr /*app*/, GuestPtr delegate) {
    std::fprintf(stderr, "[appkit] NSApplication setDelegate 0x%llx\n",
                 (unsigned long long)delegate);
}

void AppKitStubs::NSApplication_terminate(GuestPtr /*app*/, GuestPtr /*sender*/) {
    std::fprintf(stderr, "[appkit] NSApplication terminate\n");
    ::_exit(0);
}

void AppKitStubs::NSApplication_activateIgnoringOtherApps(GuestPtr /*app*/, bool flag) {
    std::fprintf(stderr, "[appkit] activateIgnoringOtherApps: %d\n", flag);
}

// ── NSWindow ──────────────────────────────────────────────────────────────────
GuestPtr AppKitStubs::NSWindow_initWithContentRect(CGRect rect, uint32_t style,
                                                    uint32_t /*backing*/, bool /*defer*/) {
    auto* mem = static_cast<uint64_t*>(::calloc(1, 128));
    GuestPtr win = reinterpret_cast<GuestPtr>(mem);
    std::fprintf(stderr, "[appkit] NSWindow initWithContentRect {{%.0f,%.0f},{%.0f,%.0f}} style=%u → 0x%llx\n",
                 rect.origin.x, rect.origin.y, rect.size.width, rect.size.height,
                 style, (unsigned long long)win);
    return win;
}

void AppKitStubs::NSWindow_makeKeyAndOrderFront(GuestPtr win, GuestPtr /*sender*/) {
    std::fprintf(stderr, "[appkit] NSWindow 0x%llx makeKeyAndOrderFront\n",
                 (unsigned long long)win);
}

void AppKitStubs::NSWindow_setTitle(GuestPtr win, const char* title) {
    std::fprintf(stderr, "[appkit] NSWindow 0x%llx setTitle: \"%s\"\n",
                 (unsigned long long)win, title ? title : "(null)");
}

void AppKitStubs::NSWindow_close(GuestPtr win) {
    std::fprintf(stderr, "[appkit] NSWindow 0x%llx close\n",
                 (unsigned long long)win);
    ::free(reinterpret_cast<void*>(win));
}

GuestPtr AppKitStubs::NSWindow_contentView(GuestPtr win) {
    // Return a stub view (offset into the window allocation)
    return win ? win + 64 : 0;
}

// ── NSView ────────────────────────────────────────────────────────────────────
GuestPtr AppKitStubs::NSView_initWithFrame(CGRect frame) {
    auto* mem = static_cast<uint64_t*>(::calloc(1, 64));
    GuestPtr view = reinterpret_cast<GuestPtr>(mem);
    std::fprintf(stderr, "[appkit] NSView initWithFrame {{%.0f,%.0f},{%.0f,%.0f}} → 0x%llx\n",
                 frame.origin.x, frame.origin.y, frame.size.width, frame.size.height,
                 (unsigned long long)view);
    return view;
}

void AppKitStubs::NSView_setNeedsDisplay(GuestPtr view, bool flag) {
    std::fprintf(stderr, "[appkit] NSView 0x%llx setNeedsDisplay: %d\n",
                 (unsigned long long)view, flag);
}

void AppKitStubs::NSView_addSubview(GuestPtr view, GuestPtr subview) {
    std::fprintf(stderr, "[appkit] NSView 0x%llx addSubview: 0x%llx\n",
                 (unsigned long long)view, (unsigned long long)subview);
}

// ── NSAlert ───────────────────────────────────────────────────────────────────
GuestPtr AppKitStubs::NSAlert_init() {
    auto* mem = static_cast<uint64_t*>(::calloc(1, 64));
    return reinterpret_cast<GuestPtr>(mem);
}

void AppKitStubs::NSAlert_setMessageText(GuestPtr /*alert*/, const char* text) {
    std::fprintf(stderr, "[appkit] NSAlert message: \"%s\"\n", text ? text : "");
}

int64_t AppKitStubs::NSAlert_runModal(GuestPtr /*alert*/) {
    std::fprintf(stderr, "[appkit] NSAlert runModal → NSAlertFirstButtonReturn (1000)\n");
    return 1000; // NSAlertFirstButtonReturn
}

// ── CFRunLoop ─────────────────────────────────────────────────────────────────
void AppKitStubs::CFRunLoopRun() {
    std::fprintf(stderr, "[appkit] CFRunLoopRun — stub (returning immediately)\n");
}

void AppKitStubs::CFRunLoopStop(GuestPtr /*runloop*/) {
    std::fprintf(stderr, "[appkit] CFRunLoopStop\n");
}

GuestPtr AppKitStubs::CFRunLoopGetMain() {
    static uint64_t fake_runloop = 0xCAFECAFECAFECAFEULL;
    return reinterpret_cast<GuestPtr>(&fake_runloop);
}

void AppKitStubs::install() {
    std::fprintf(stderr, "[appkit] stubs installed\n");
}
