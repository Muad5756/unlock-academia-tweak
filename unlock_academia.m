#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

/*
 * unlock_academia.dylib — Pure Objective-C runtime bypass
 *
 * Fixes:
 *   - Delays plugin hooks until Flutter engine is ready (dispatch_async)
 *   - Retries hooking if classes aren't available yet
 *   - Added setSecureTextEntry: setter hook for ScreenPreventerKit defense-in-depth
 *   - Added recursive window-scanner to forcibly disable secure text fields
 */

#pragma mark - Swizzle Helpers

static void swz(Class cls, SEL sel, IMP newImp, IMP *oldOut) {
    Method m = class_getInstanceMethod(cls, sel);
    if (m) { *oldOut = method_setImplementation(m, newImp); }
}

static void swzClass(Class cls, SEL sel, IMP newImp, IMP *oldOut) {
    swz(object_getClass(cls), sel, newImp, oldOut);
}

static void swzIfSafe(Class cls, SEL sel, IMP newImp) {
    IMP dummy;
    swz(cls, sel, newImp, &dummy);
}

static void swzClassIfSafe(Class cls, SEL sel, IMP newImp) {
    swz(object_getClass(cls), sel, newImp, &(IMP){0});
}

static void replaceWithBlock(Class cls, SEL sel, id block) {
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        IMP imp = imp_implementationWithBlock(block);
        method_setImplementation(m, imp);
    }
}

#pragma mark - Replacement IMPs

static BOOL safe_isJailbroken(id self, SEL _cmd) { return NO; }
static BOOL safe_isJailBroken(id self, SEL _cmd) { return NO; }
static BOOL safe_isJailBrokenCustom(id self, SEL _cmd) { return NO; }
static BOOL safe_hasJailbreakPaths(id self, SEL _cmd) { return NO; }
static BOOL safe_hasJailbreakProcesses(id self, SEL _cmd) { return NO; }
static BOOL safe_canOpenJailbreakSchemes(id self, SEL _cmd) { return NO; }
static BOOL safe_hasJailbreakEnvironmentVariables(id self, SEL _cmd) { return NO; }
static BOOL safe_canViolateSandbox(id self, SEL _cmd) { return NO; }
static BOOL safe_hasSuspiciousSymlinks(id self, SEL _cmd) { return NO; }
static BOOL safe_isSimulator(id self, SEL _cmd) { return NO; }
static BOOL safe_canAccessPath(id self, SEL _cmd, NSString *p) { return NO; }
static id safe_getJailbreakDetails(id self, SEL _cmd) { return @{}; }

static id safePlugin_isJailBroken(id self, SEL _cmd) {
    return @{@"isJailBroken": @NO};
}
static id safePlugin_isJailBrokenCustom(id self, SEL _cmd) {
    return @{@"isJailBroken": @NO};
}
static id safePlugin_isRealDevice(id self, SEL _cmd) { return @YES; }
static id safePlugin_hasLegitimateEnv(id self, SEL _cmd) { return @YES; }
static id safePlugin_isDevEnv(id self, SEL _cmd) { return @NO; }
static id safePlugin_hasObviousSigns(id self, SEL _cmd) { return @NO; }

static void (*orig_handleCall)(id, SEL, id, id);

static void safePlugin_handleCall(id self, SEL _cmd, id call, id result) {
    NSString *method = ((NSString *(*)(id, SEL))objc_msgSend)(call, @selector(method));
    if ([method containsString:@"Jail"] || [method containsString:@"jail"] ||
        [method containsString:@"jailbreak"] || [method containsString:@"Jailbreak"]) {
        void (^reply)(id) = result;
        if (reply) reply(@{@"isJailBroken": @NO, @"isJailbroken": @NO});
        return;
    }
    if (orig_handleCall) orig_handleCall(self, _cmd, call, result);
}

// UIKit bypasses
static BOOL uiscreen_isCaptured(id self, SEL _cmd) { return NO; }
static BOOL uitextfield_isSecureTextEntry(id self, SEL _cmd) { return NO; }

// Hook the setter too — ScreenPreventerKit may use [textField setSecureTextEntry:YES]
static void (*orig_setSecureTextEntry)(id, SEL, BOOL);
static void uitextfield_setSecureTextEntry(id self, SEL _cmd, BOOL val) {
    if (val) {
        NSLog(@"[unlock_academia] Blocked setSecureTextEntry:YES");
        return;
    }
    if (orig_setSecureTextEntry) orig_setSecureTextEntry(self, _cmd, val);
}

static void preventer_enablePreventScreenshot(id self, SEL _cmd) {}

#pragma mark - Hooking Logic

static void applyUIKitHooks() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // Always works — UIKit loaded at constructor time
        swzIfSafe([UIScreen class], @selector(isCaptured), (IMP)uiscreen_isCaptured);
        swzIfSafe([UITextField class], @selector(isSecureTextEntry), (IMP)uitextfield_isSecureTextEntry);

        Method setterM = class_getInstanceMethod([UITextField class], @selector(setSecureTextEntry:));
        if (setterM) {
            orig_setSecureTextEntry = (void (*)(id, SEL, BOOL))method_getImplementation(setterM);
            method_setImplementation(setterM, (IMP)uitextfield_setSecureTextEntry);
        }

        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wnonnull"
        [NSNotificationCenter.defaultCenter removeObserver:nil
            name:UIApplicationUserDidTakeScreenshotNotification object:nil];
        [NSNotificationCenter.defaultCenter removeObserver:nil
            name:UIScreenCapturedDidChangeNotification object:nil];
        #pragma clang diagnostic pop

        NSLog(@"[unlock_academia] UIKit hooks applied");
    });
}

static void applySafeDeviceHooks() {
    Class sdClass = NSClassFromString(@"SafeDeviceJailbreakDetection");
    if (sdClass) {
        swzClassIfSafe(sdClass, @selector(isJailbroken), (IMP)safe_isJailbroken);
        swzClassIfSafe(sdClass, @selector(isJailBroken), (IMP)safe_isJailBroken);
        swzClassIfSafe(sdClass, @selector(isJailBrokenCustom), (IMP)safe_isJailBrokenCustom);
        swzClassIfSafe(sdClass, @selector(hasJailbreakPaths), (IMP)safe_hasJailbreakPaths);
        swzClassIfSafe(sdClass, @selector(hasJailbreakProcesses), (IMP)safe_hasJailbreakProcesses);
        swzClassIfSafe(sdClass, @selector(canOpenJailbreakSchemes), (IMP)safe_canOpenJailbreakSchemes);
        swzClassIfSafe(sdClass, @selector(hasJailbreakEnvironmentVariables), (IMP)safe_hasJailbreakEnvironmentVariables);
        swzClassIfSafe(sdClass, @selector(canViolateSandbox), (IMP)safe_canViolateSandbox);
        swzClassIfSafe(sdClass, @selector(hasSuspiciousSymlinks), (IMP)safe_hasSuspiciousSymlinks);
        swzClassIfSafe(sdClass, @selector(isSimulator), (IMP)safe_isSimulator);
        swzClassIfSafe(sdClass, @selector(getJailbreakDetails), (IMP)safe_getJailbreakDetails);
        swzClassIfSafe(sdClass, @selector(canAccessPath:), (IMP)safe_canAccessPath);
        NSLog(@"[unlock_academia] SafeDeviceJailbreakDetection hooked");
    }

    Class sdPlugin = NSClassFromString(@"SafeDevicePlugin");
    if (sdPlugin) {
        swzIfSafe(sdPlugin, @selector(isJailBroken), (IMP)safePlugin_isJailBroken);
        swzIfSafe(sdPlugin, @selector(isJailBrokenCustom), (IMP)safePlugin_isJailBrokenCustom);
        swzIfSafe(sdPlugin, @selector(isRealDevice), (IMP)safePlugin_isRealDevice);
        swzIfSafe(sdPlugin, @selector(hasLegitimateEnvironmentVariables), (IMP)safePlugin_hasLegitimateEnv);
        swzIfSafe(sdPlugin, @selector(isDevelopmentEnvironment), (IMP)safePlugin_isDevEnv);
        swzIfSafe(sdPlugin, @selector(hasObviousJailbreakSigns), (IMP)safePlugin_hasObviousSigns);
        Method hm = class_getInstanceMethod(sdPlugin, @selector(handleMethodCall:result:));
        if (hm) {
            orig_handleCall = (void (*)(id, SEL, id, id))method_getImplementation(hm);
            method_setImplementation(hm, (IMP)safePlugin_handleCall);
        }
        NSLog(@"[unlock_academia] SafeDevicePlugin hooked");
    }

    Class dttClass = NSClassFromString(@"DTTJailbreakDetection");
    if (dttClass) {
        swzClassIfSafe(dttClass, @selector(isJailbroken), (IMP)safe_isJailbroken);
        swzClassIfSafe(dttClass, @selector(isPirated), (IMP)safe_isJailbroken);
        NSLog(@"[unlock_academia] DTTJailbreakDetection hooked");
    }
}

static void applyScreenPreventerHooks() {
    // Try both short and mangled names
    NSArray *names = @[
        @"ScreenPreventer", @"ScreenshotPreventer", @"ScreenPreventerStore",
        @"ScreenshotProtectionOverlay",
        @"_TtC18ScreenPreventerKit15ScreenPreventer",
        @"_TtC18ScreenPreventerKit19ScreenshotPreventer",
        @"_TtC18ScreenPreventerKit20ScreenPreventerStore",
        @"_TtC18ScreenPreventerKit27ScreenshotProtectionOverlay",
    ];
    for (NSString *name in names) {
        Class c = NSClassFromString(name);
        if (!c) continue;
        SEL candidates[] = {
            @selector(enabledPreventScreenshot),
            @selector(enabled),
            @selector(enabledPreventScreenRecording),
            @selector(isEnabled),
            @selector(enabledPreventScreenshotCapture),
        };
        for (int i = 0; i < 5; i++) {
            Method m = class_getInstanceMethod(c, candidates[i]);
            if (m) method_setImplementation(m, (IMP)uitextfield_isSecureTextEntry);
        }
        SEL enableSel = NSSelectorFromString(@"enablePreventScreenshot");
        Method em = class_getInstanceMethod(c, enableSel);
        if (em) method_setImplementation(em, (IMP)preventer_enablePreventScreenshot);

        SEL disableSel = NSSelectorFromString(@"disableScreenshotBlocking");
        Method dm = class_getInstanceMethod(c, disableSel);
        if (dm) {
            IMP orig = method_getImplementation(dm);
            ((void (*)(id, SEL))orig)(c, disableSel);
        }

        NSLog(@"[unlock_academia] ScreenPreventerKit class hooked: %@", name);
    }
}

static void recursiveDisableSecure(UIView *view) {
    if ([view isKindOfClass:UITextField.class]) {
        [(UITextField *)view setSecureTextEntry:NO];
        NSLog(@"[unlock_academia] Disabled secure text entry on %@", view);
    }
    for (UIView *sub in view.subviews) {
        recursiveDisableSecure(sub);
    }
}

static void scanAndDisableSecureTextFields() {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *win in ((UIWindowScene *)scene).windows) {
            recursiveDisableSecure(win);
        }
    }
}

#pragma mark - Deferred Hooking

static void runDeferredHooks() {
    NSLog(@"[unlock_academia] running deferred hooks...");

    applySafeDeviceHooks();
    applyScreenPreventerHooks();

    // Force-disable any secure text fields in the window hierarchy
    scanAndDisableSecureTextFields();

    // Retry once more after 2s for late-loading plugins
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        applySafeDeviceHooks();
        applyScreenPreventerHooks();
        scanAndDisableSecureTextFields();
        NSLog(@"[unlock_academia] Late retry complete");
    });
}

#pragma mark - Constructor

__attribute__((constructor)) static void init_dylib(void) {
    @autoreleasepool {
        NSLog(@"[unlock_academia] dylib loaded.");
        // Phase 1: UIKit hooks — safe at constructor time
        applyUIKitHooks();

        // Phase 2: Plugin hooks — deferred to main runloop (Flutter not ready yet)
        dispatch_async(dispatch_get_main_queue(), ^{
            runDeferredHooks();
        });
    }
}
