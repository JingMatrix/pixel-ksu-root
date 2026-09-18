/* lib/trigger/amclient.h -- a minimal client for system_server's
 * ActivityManager over the real, shared /dev/binder.
 *
 * A private binderfs device needs root to create (drivers/android/binderfs.c
 * requires CAP_SYS_ADMIN-equivalent to open binder-control), and the real
 * device's context-manager slot and its ServiceManager.addService() are both
 * closed to an unprivileged shell -- confirmed on hardware, not assumed: the
 * first fails because servicemanager already holds the role, and the second
 * is denied with no AVC trace at all (a dontaudit rule), differentiated by
 * running the identical call as shell vs. as root.
 *
 * What is NOT closed, also confirmed on hardware: ServiceManager.getService()
 * ("activity" and everything else `service list` shows), and two of
 * IActivityManager's own calls -- getContentProviderExternal(), which hands
 * back a real Binder into an installed app's process by resolving a
 * <package>.<authority> pair through the app's own manifest, and
 * forceStopPackage(), which tears that same process down on request. This is
 * exactly how Shizuku reaches an app process from plain `adb shell`, and this
 * module is the same technique read off this project's own test app
 * (domainprobe, which already declares a ShizukuProvider) rather than a new
 * one written to prove it.
 *
 * A target built this way is any installed app that declares a reachable
 * component -- not a privileged one. The privilege a caller gets from
 * corrupting kernel state through it does not depend on the target app's own
 * privilege at all: the corruption is in the kernel, and which userspace
 * transaction supplied the free is incidental to what the primitive can
 * reach once landed.
 *
 * The two IActivityManager calls are internal (hidden, not AIDL-stable
 * across releases) rather than public SDK surface, so their transaction
 * codes and this project's understanding of their reply shape were read off
 * a live device via reflection (adb shell app_process + java.lang.reflect
 * against android.app.IActivityManager$Stub), not assumed from AOSP source
 * of a possibly different version. LIB_AM_TXN_* below are what that reflection
 * found on panther's Android 17 (CP2A.260705.006); a different Android
 * version may renumber them; re-derive before reusing off that build. The
 * reply is read without parsing ContentProviderHolder's fields at all: a
 * reply's flat_binder_object table is independent of the surrounding data,
 * so lib_binder_parse()'s existing offset-table walk finds the provider's
 * handle directly, whatever the size or shape of the ProviderInfo/
 * ApplicationInfo payload in front of it.
 */
#ifndef LIB_TRIGGER_AMCLIENT_H
#define LIB_TRIGGER_AMCLIENT_H

#include <stdint.h>

/* Read via reflection against android.app.IActivityManager$Stub on panther,
 * Android 17, CP2A.260705.006. Not a stable ABI across Android versions. */
#define LIB_AM_TXN_getContentProviderExternal 136
#define LIB_AM_TXN_forceStopPackage            91

/* Read via reflection against android.os.IServiceManager$Stub on the same
 * build. Differs from the classic (pre-AIDL) SVC_MGR_CHECK_SERVICE=2. */
#define LIB_AM_TXN_checkService 3

/* Resolve a system service by name, exactly like ServiceManager.getService():
 * a transaction to the real /dev/binder's handle 0. Returns 0 and the
 * service's handle in *out, or -1 (not found, or the call failed). */
int lib_am_check_service(int fd, const char *name, uint32_t *out_handle);

/* IActivityManager.getContentProviderExternal(name, userId, null, tag): hands
 * back a real Binder handle into the app that declares a <provider
 * android:authorities="name"> -- starting that app's process if it is not
 * already running. `am_handle` is the handle lib_am_check_service() resolved
 * for "activity". Returns 0 and the provider's handle in *out, or -1. */
int lib_am_get_content_provider_external(int fd, uint32_t am_handle,
					 const char *authority, int32_t user_id,
					 uint32_t *out_handle);

/* IActivityManager.forceStopPackage(packageName, userId): tears the named
 * app's process down, the same operation `adb shell am force-stop` drives.
 * Returns 0 if the call was accepted (the reply carried no exception), or -1.
 * Whether the process is actually gone is the caller's to observe -- this
 * function only reports whether the request was accepted. */
int lib_am_force_stop_package(int fd, uint32_t am_handle,
			      const char *package, int32_t user_id);

#endif /* LIB_TRIGGER_AMCLIENT_H */
