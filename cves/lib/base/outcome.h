/* lib/base/outcome.h -- the vocabulary a shot reports itself with.
 *
 * A run of an exploit answers one question, and the answer has four shapes that
 * a driver must tell apart, because each implies a different next action:
 *
 *   PASS      the question was answered yes. Stop.
 *   MISS      it ran to completion and the answer was no. Retry; a different
 *             draw may answer yes.
 *   WALL      a precondition is permanently absent on this device or kernel.
 *             Retrying is futile; the composition itself is wrong.
 *   REFUSED   setup failed before anything was attempted. Nothing was learned
 *             about the question, and the attempt does not count.
 *
 * Collapsing WALL into MISS is the costly confusion: a driver then grinds
 * thousands of attempts against something that cannot happen. Collapsing
 * REFUSED into MISS is the quieter one: it makes a broken harness look like a
 * low hit rate.
 *
 * The numbers are exit statuses, so a chain that ends in a separate process
 * still reports in this vocabulary. A driver may also key on a printed marker,
 * which wins where both are present — a chain that got its answer and then died
 * on the way out has still answered it.
 */
#ifndef LIB_BASE_OUTCOME_H
#define LIB_BASE_OUTCOME_H

#define LIB_OUTCOME_PASS               0
#define LIB_OUTCOME_MISS               1
#define LIB_OUTCOME_PRECONDITION_FAIL  2
#define LIB_OUTCOME_REFUSED            3
#define LIB_OUTCOME_USAGE              4

#endif /* LIB_BASE_OUTCOME_H */
