// blazer — Pixel 10 Pro, Android 17
// Build:     CP2A.260705.006
// Kernel:    6.6.118-android15
// Interface: android15-6.6
//
// What this build does not share with its kernel interface. Everything else
// is supplied by the interface header included at the end.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "blazer-CP2A.260705.006-app"
#else
#define BUILD_VARIANT_LABEL "blazer-CP2A.260705.006-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/blazer/blazer:17/CP2A.260705.006/15430684:user/release-keys"
#endif

#include "../kmi/android15-6.6.h"

#endif
