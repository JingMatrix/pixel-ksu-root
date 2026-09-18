/* lib/root/handoff.h -- turning a privileged process into a privilege anyone
 * can ask for.
 *
 * Reaching root inside one process is where a chain's exploitation ends and a
 * separate problem begins: that process exits, and the privilege goes with it.
 * Making it durable and reachable is a distinct piece of work, it is the same
 * work for every chain that gets there, and it is what the difference between
 * "the defect is exploitable" and "the device is rooted" actually consists of.
 *
 * Three steps, each of which can fail independently:
 *
 *   Place the helper somewhere a later, unprivileged process can execute. The
 *   obvious locations are either not executable or not writable, so a private
 *   filesystem is mounted for it -- which also means the placement disappears
 *   on reboot, matching the lifetime of the privilege itself.
 *
 *   Make it reachable from the contexts that will ask. A mount is per-namespace,
 *   so a helper mounted in the chain's own namespace is invisible to a shell
 *   started elsewhere; it has to be placed inside the namespaces that matter as
 *   well.
 *
 *   Label it. Mandatory access control decides what may execute a file by its
 *   label, and a file written by an exploit does not inherit a useful one.
 *
 * What this module does not own is how the privilege was obtained, or what the
 * helper does once running. It takes a path to a helper and the privileged
 * context it is called in, and reports whether each step succeeded.
 */
#ifndef LIB_ROOT_HANDOFF_H
#define LIB_ROOT_HANDOFF_H

#include <sys/types.h>

/* Where the helper is placed, and the label it is given. Both are policy: a
 * caller on a differently-configured device overrides them. */
#ifndef LIB_HANDOFF_DIR
#define LIB_HANDOFF_DIR "/debug_ramdisk"
#endif
#ifndef LIB_HANDOFF_LABEL
#define LIB_HANDOFF_LABEL "u:object_r:system_file:s0"
#endif

struct lib_handoff_report {
	int mounted;      /* a writable, executable filesystem is in place   */
	int installed;    /* the helper was written and made executable      */
	int labelled;     /* a label permitting execution was applied        */
	int published;    /* the helper is visible from other namespaces     */
	int namespaces;   /* how many namespaces it was published into       */
};

/* Is `path` a mount point? Used to decide whether the private filesystem is
 * already in place, since mounting over an existing one is not harmless. */
int lib_handoff_is_mounted(const char *path);

/* Mount a small private filesystem at `dir`, or report that one is already
 * there. Returns 1 if `dir` is usable afterwards, 0 otherwise. */
int lib_handoff_mount(const char *dir);

/* Copy `src` to `dir`/`name`, make it executable, and apply `label`.
 *
 * The copy is written to a temporary name and moved into place, so a process
 * that looks while the copy is in progress never sees a partial helper --
 * which would be executed and fail, rather than not found and retried.
 *
 * Returns 1 on success, 0 on failure with errno set. */
int lib_handoff_install(const char *dir, const char *name, const char *src,
                        const char *label);

/* Make the installed helper visible inside the mount namespace of `pid`.
 *
 * A privileged process can enter another's namespace and place the helper
 * there. This is what makes the privilege reachable from a shell that was
 * started before, or outside, this chain. Returns 1 on success, 0 otherwise. */
int lib_handoff_publish_to(pid_t pid, const char *dir, const char *name,
                           const char *src, const char *label);

/* Find a process by executable name, for choosing a namespace to publish into.
 * Returns its identifier, or 0 if none is running. */
pid_t lib_handoff_find_process(const char *comm);

/* Mount, install and label in one call, filling `report` with what succeeded.
 * Returns 1 only if the helper is installed and executable. */
int lib_handoff_prepare(const char *dir, const char *name, const char *src,
                        const char *label, struct lib_handoff_report *report);

#endif /* LIB_ROOT_HANDOFF_H */
