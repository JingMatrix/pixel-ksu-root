/* lib/base/logscan.h -- recover a value another process wrote to its log.
 *
 * An observer that watches an exploit from outside cannot compute the
 * addresses that exploit chose: they come out of a leak the observer did not
 * take. But the exploit prints them, because a run that does not name the
 * addresses it used cannot be read afterwards either. So the log is the
 * channel, and this is the parser for it -- no shared memory, no protocol, and
 * nothing the observed process has to do differently.
 *
 * The LAST occurrence wins: a run that re-sprays prints the new address, and
 * the newest one is the one still live.
 */
#ifndef LIB_BASE_LOGSCAN_H
#define LIB_BASE_LOGSCAN_H

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef LIB_LOGSCAN_MAX
#define LIB_LOGSCAN_MAX (256 * 1024)
#endif

/* Whole file into `buf`, NUL-terminated. Returns the byte count, or -1 if the
 * file cannot be opened or is empty -- shared by every scanner below, which
 * differ only in how they parse what this reads. */
static inline ssize_t lib_logscan_slurp(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  ssize_t n;

  if (fd < 0) {
    return -1;
  }
  n = read(fd, buf, cap - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = '\0';
  return n;
}

/* The last `<key><hex>` in `path`, or 0 when the file, the key or a non-zero
 * value is not there. `key` carries its own separator, e.g. "fake_w0=". */
static inline uint64_t lib_log_last_hex(const char *path, const char *key) {
  static char buf[LIB_LOGSCAN_MAX];
  uint64_t found = 0;
  size_t keylen;

  if (lib_logscan_slurp(path, buf, sizeof(buf)) < 0) {
    return 0;
  }
  keylen = strlen(key);
  for (const char *p = buf; (p = strstr(p, key)) != NULL; p++) {
    unsigned long long v = 0;
    if (sscanf(p + keylen, "%llx", &v) == 1 && v) {
      found = (uint64_t)v;
    }
  }
  return found;
}

/* The last `<key><decimal>` in `path`, for the identifiers a process states
 * about itself rather than the addresses it leaked. */
static inline long lib_log_last_dec(const char *path, const char *key) {
  static char buf[LIB_LOGSCAN_MAX];
  long found = 0;
  size_t keylen;

  if (lib_logscan_slurp(path, buf, sizeof(buf)) < 0) {
    return 0;
  }
  keylen = strlen(key);
  for (const char *p = buf; (p = strstr(p, key)) != NULL; p++) {
    long v = 0;
    if (sscanf(p + keylen, "%ld", &v) == 1 && v > 0) {
      found = v;
    }
  }
  return found;
}

#endif /* LIB_BASE_LOGSCAN_H */
