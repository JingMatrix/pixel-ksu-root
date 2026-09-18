// mustang — Pixel 10 Pro XL, Android 17
// Build:     CP2A.260705.006
// Kernel:    6.6.118-android15
// Interface: android15-6.6
//
// What this build does not share with its kernel interface. Everything else
// is supplied by the interface header included at the end.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "mustang-CP2A.260705.006-app"
#else
#define BUILD_VARIANT_LABEL "mustang-CP2A.260705.006-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/mustang/mustang:17/CP2A.260705.006/15641320:user/release-keys"
#endif

#include "../kmi/android15-6.6.h"

#endif
