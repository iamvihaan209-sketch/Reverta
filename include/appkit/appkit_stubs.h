#pragma once
#include <cstdint>
#include <string>
#include <functional>

using GuestPtr = uint64_t;

// Minimal CGRect / CGPoint / CGSize (mirroring CoreGraphics structs)
struct CGPoint { double x, y; };
struct CGSize  { double width, height; };
struct CGRect  { CGPoint origin; CGSize size; };

// AppKit stub layer.
// Provides enough of NSApplication / NSWindow / NSView to let
// a GUI app's startup path run without crashing.
// Real rendering is NOT implemented — windows open as no-ops.
class AppKitStubs {
public:
    static AppKitStubs& instance();

    void install();

    // NSApplication
    GuestPtr NSApplication_sharedApplication();
    void     NSApplication_run(GuestPtr app);
    void     NSApplication_setDelegate(GuestPtr app, GuestPtr delegate);
    void     NSApplication_terminate(GuestPtr app, GuestPtr sender);
    void     NSApplication_activateIgnoringOtherApps(GuestPtr app, bool flag);

    // NSWindow
    GuestPtr NSWindow_initWithContentRect(CGRect rect, uint32_t style,
                                           uint32_t backing, bool defer);
    void     NSWindow_makeKeyAndOrderFront(GuestPtr win, GuestPtr sender);
    void     NSWindow_setTitle(GuestPtr win, const char* title);
    void     NSWindow_close(GuestPtr win);
    GuestPtr NSWindow_contentView(GuestPtr win);

    // NSView
    GuestPtr NSView_initWithFrame(CGRect frame);
    void     NSView_setNeedsDisplay(GuestPtr view, bool flag);
    void     NSView_addSubview(GuestPtr view, GuestPtr subview);

    // NSAlert (common in apps)
    GuestPtr NSAlert_init();
    void     NSAlert_setMessageText(GuestPtr alert, const char* text);
    int64_t  NSAlert_runModal(GuestPtr alert);

    // RunLoop helpers
    void CFRunLoopRun();
    void CFRunLoopStop(GuestPtr runloop);
    GuestPtr CFRunLoopGetMain();

private:
    AppKitStubs() = default;

    // Fake shared NSApplication singleton
    GuestPtr shared_app_ = 0;
    bool     running_    = false;
};
