/* lib/root/install_method.h -- which mechanism turns a kernel r/w primitive
 * into root, chosen at compile time so a chain can be built either way and
 * compared.
 *
 * ROOT_METHOD_CRED_PATCH overwrites a target task's own cred (identity,
 * capabilities, SELinux sid) and clears its seccomp filter in place --
 * cred.h's primitives, orchestrated by the chain itself. It needs the
 * target's task_struct/cred/seccomp field offsets and nothing else.
 *
 * ROOT_METHOD_UMH_WORKQUEUE (install_umh.h) never touches an existing
 * task's cred at all: it forges a work_struct and splices it into
 * system_unbound_wq so the kernel's own call_usermodehelper_exec_work runs
 * a helper binary directly, which starts life with a fresh, correctly
 * initialised root cred. It needs the workqueue/pool/work_struct field
 * offsets instead, plus a scratch region the caller already owns.
 *
 * A target selects one by defining ROOT_METHOD before this header is first
 * included (its own target.h, or a -D on the compiler line); the default
 * is the cred-patch method, since every existing target currently builds
 * against it.
 */
#ifndef LIB_ROOT_INSTALL_METHOD_H
#define LIB_ROOT_INSTALL_METHOD_H

#define ROOT_METHOD_CRED_PATCH    0
#define ROOT_METHOD_UMH_WORKQUEUE 1

#ifndef ROOT_METHOD
#define ROOT_METHOD ROOT_METHOD_CRED_PATCH
#endif

#endif /* LIB_ROOT_INSTALL_METHOD_H */
