/* lib/trigger/amclient.h -- a minimal client for system_server's
 * ActivityManager over the real, shared /dev/binder.
 *
 * A private binderfs device needs root to create (drivers/android/binderfs.c
 * requires CAP_SYS_ADMIN-equivalent to open binder-control), and the real
 * device's context-manager slot and its ServiceManager.addService() are both
 * closed to an unprivileged shell: the first because servicemanager already
 * holds the role, the second denied by a dontaudit SELinux rule, which
 * leaves no AVC trace for a caller to diagnose against.
 *
 * What is NOT closed: ServiceManager.getService() ("activity" and everything
 * else `service list` shows), and two of IActivityManager's own calls --
 * getContentProviderExternal(), which hands back a real Binder into an
 * installed app's process by resolving a <package>.<authority> pair through
 * the app's own manifest, and forceStopPackage(), which tears that same
 * process down on request. This is the same technique Shizuku uses to reach
 * an app process from plain `adb shell`; any installed app that declares a
 * reachable provider component is a usable target, root not required.
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
 * codes and reply shape must be read off a live device via reflection (adb
 * shell app_process + java.lang.reflect against
 * android.app.IActivityManager$Stub), not assumed from AOSP source of a
 * possibly different version. LIB_AM_TXN_* below are per-Android-version;
 * re-derive before reusing on a different release. The reply is read
 * without parsing ContentProviderHolder's fields at all: a reply's
 * flat_binder_object table is independent of the surrounding data, so
 * lib_binder_parse()'s existing offset-table walk finds the provider's
 * handle directly, whatever the size or shape of the ProviderInfo/
 * ApplicationInfo payload in front of it.
 */
#ifndef LIB_TRIGGER_AMCLIENT_H
#define LIB_TRIGGER_AMCLIENT_H

#include <stdint.h>

/* Read via reflection against android.app.IActivityManager$Stub. Not a
 * stable ABI across Android versions -- re-derive per target. */
#define LIB_AM_TXN_getContentProviderExternal 136
#define LIB_AM_TXN_forceStopPackage            91

/* Read via reflection against android.os.IServiceManager$Stub on the same
 * target. Differs from the classic (pre-AIDL) SVC_MGR_CHECK_SERVICE=2. */
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
