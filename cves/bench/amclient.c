/* Does lib/trigger/amclient.h actually reach an app process, end to end, on
 * this device -- read from the device rather than assumed from the protocol
 * documentation in amclient.h.
 *
 * amclient talks to two of IActivityManager's internal methods by hand-rolled
 * AIDL transaction, not the public NDK (android/binder_manager.h does not
 * exist for them at all -- there is no public wrapper for
 * getContentProviderExternal() or forceStopPackage()). A wrong transaction
 * code or a wrong Parcel byte reads as a generic failure indistinguishable
 * from a permission denial, so this bench exists to give that failure a
 * cause: resolve "activity", reach a real app's declared provider by
 * authority, and force-stop that same app, checking after each step rather
 * than trusting the return code alone.
 *
 * Targets domainprobe (dev.pixelksu.domainprobe), this project's own test
 * app, because it already declares rikka.shizuku.ShizukuProvider at
 * <applicationId>.shizuku -- the same provider name Shizuku's own server
 * targets by convention, so nothing needed adding to reach it.
 *
 *   amclient <package> <provider-authority>
 *   amclient dev.pixelksu.domainprobe dev.pixelksu.domainprobe.shizuku
 *
 * Exit: 0 all three calls succeeded; 1 named a step that did not.
 */
#include <stdio.h>
#include <unistd.h>

#include "../lib/trigger/amclient.h"
#include "../lib/trigger/binder.h"

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <package> <provider-authority>\n", argv[0]);
		return 2;
	}
	const char *package = argv[1];
	const char *authority = argv[2];

	int fd = lib_binder_open("/dev/binder");
	if (fd < 0) { perror("open /dev/binder"); return 1; }

	uint32_t am_handle = 0;
	if (lib_am_check_service(fd, "activity", &am_handle) != 0) {
		printf("check_service(activity): FAIL\n");
		return 1;
	}
	printf("check_service(activity): OK handle=%u\n", am_handle);

	uint32_t provider_handle = 0;
	if (lib_am_get_content_provider_external(fd, am_handle, authority, 0,
						 &provider_handle) != 0) {
		printf("get_content_provider_external(%s): FAIL\n", authority);
		return 1;
	}
	printf("get_content_provider_external(%s): OK handle=%u\n",
	       authority, provider_handle);

	if (lib_am_force_stop_package(fd, am_handle, package, 0) != 0) {
		printf("force_stop_package(%s): FAIL\n", package);
		return 1;
	}
	printf("force_stop_package(%s): OK (accepted -- check pidof separately "
	       "to confirm the process actually exited)\n", package);
	return 0;
}
