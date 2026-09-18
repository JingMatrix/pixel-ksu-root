/* lib/target.h -- how a library module reaches the target description.
 *
 * A module that needs a device fact takes it from the target description, which
 * the build names through TARGET_HEADER. Including that here, once, has two
 * effects worth stating:
 *
 *   A module is self-sufficient. It does not depend on the consuming exploit
 *   having pulled the description in first, which would make the module's
 *   correctness a property of its call site's include order.
 *
 *   A module still compiles without a target. Every fact it needs is declared
 *   with a documented default beside its use, so a standalone build -- a test,
 *   a quick experiment -- works, and a real build silently overrides all of
 *   them. The defaults are never the values a shipped payload uses, because a
 *   stage always names a target.
 *
 * A module that needs no device fact does not include this.
 */
#ifndef LIB_TARGET_H
#define LIB_TARGET_H

#ifdef TARGET_HEADER
#include TARGET_HEADER
#endif

#endif /* LIB_TARGET_H */
