/* lib/trigger/amclient.c -- see amclient.h.
 *
 * The AIDL Parcel encoding hand-rolled here (interface token, UTF-16
 * strings, a null Binder object) was captured from a live Parcel on the
 * target device rather than assumed: Parcel.writeInterfaceToken() on Android
 * 17 writes a 12-byte header before the string (a strict-mode/work-source
 * marker later platforms added), which older write-ups of this technique
 * predate. android/binder_manager.h's AServiceManager_* calls were not used
 * to reach this instead, because they need a symbol this NDK release does
 * not ship and, more importantly, do not exist for IActivityManager's
 * internal methods at all -- there is no public wrapper for
 * getContentProviderExternal() or forceStopPackage() to call.
 */
#include "amclient.h"
#include "binder.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <linux/android/binder.h>

/* Every AIDL request opens with this. The first two words carry
 * IPCThreadState's strict-mode policy and calling-work-source-uid, which a
 * client that never touches either always sends as taken here (unset policy,
 * no work source) -- captured from a real Parcel.writeInterfaceToken() call
 * rather than assumed, because it is not the plain descriptor string alone
 * on this Android version. */
static const uint8_t INTERFACE_TOKEN_HEADER[12] = {
	0x00, 0x00, 0x00, 0x80,
	0xff, 0xff, 0xff, 0xff,
	0x54, 0x53, 0x59, 0x53,
};

/* Every AIDL string is length-prefixed UTF-16LE, null-terminated, padded to
 * 4 bytes -- ASCII-only here, which is everything a service/authority/package
 * name ever is, so each source byte becomes one zero-extended UTF-16 unit. */
static size_t put_str16(uint8_t *p, const char *s)
{
	size_t len = strlen(s);
	size_t off = 0;

	memcpy(p + off, &(uint32_t){(uint32_t)len}, 4);
	off += 4;
	for (size_t i = 0; i < len; i++) {
		p[off++] = (uint8_t)s[i];
		p[off++] = 0;
	}
	p[off++] = 0;
	p[off++] = 0;
	while (off % 4)
		p[off++] = 0;
	return off;
}

static size_t put_i32(uint8_t *p, int32_t v)
{
	memcpy(p, &v, 4);
	return 4;
}

static size_t put_interface_token(uint8_t *p, const char *descriptor)
{
	memcpy(p, INTERFACE_TOKEN_HEADER, sizeof(INTERFACE_TOKEN_HEADER));
	return sizeof(INTERFACE_TOKEN_HEADER) + put_str16(p + sizeof(INTERFACE_TOKEN_HEADER),
							   descriptor);
}

/* A null IBinder argument is a bare 4-byte zero, not a flat_binder_object:
 * the AIDL-generated Proxy checks nullability in Java before ever reaching
 * writeStrongBinder(), so the wire format for "argument absent" is just the
 * presence flag with nothing behind it -- there is no flat_binder_object to
 * put in the offsets table for a null argument at all. A full null-typed
 * flat_binder_object -- what the kernel's own binder_translate_binder()
 * treats binder==0 as -- is a different, 24-byte encoding that
 * IActivityManager rejects as unconsumed Parcel data. */
static size_t put_null_binder(uint8_t *p)
{
	return put_i32(p, 0);
}

/* Issue one transaction and pull the first handle out of the reply's own
 * offset table -- not out of the surrounding bytes, so this works identically
 * whether the reply is a bare IBinder (checkService) or a large Parcelable
 * with the IBinder buried past hundreds of unrelated bytes
 * (getContentProviderExternal's ContentProviderHolder, complete with a
 * nested ApplicationInfo): the offsets are independent of what is around
 * them. lib_binder_parse() already implements this walk. */
/* Issue one transaction and read until a real BR_TRANSACTION/BR_REPLY has
 * been parsed, not just whatever the first read happened to catch.
 *
 * Two distinct gaps confirmed on hardware, not one: lib_binder_open()'s
 * non-blocking fd can return -1/EAGAIN from the same ioctl that fully
 * processed the write, because nothing was ready to read back yet (fast
 * calls like checkService hit this). And a slower call -- forceStopPackage,
 * which does real work server-side tearing a process down -- can instead
 * return rc=0 with a few bytes consumed that are only the completion
 * acknowledgement (BR_TRANSACTION_COMPLETE), with the actual BR_REPLY still
 * pending; parsing that short read reports no transaction at all, which
 * reads as failure even though the call is still in flight and will
 * succeed. Both need the same fix: keep reading until lib_binder_parse()
 * finds a real transaction, not just until the ioctl stops erroring. */
static int transact_until_reply(int fd, uint32_t target, uint32_t code,
				const void *data, size_t dlen,
				const void *offsets, size_t olen,
				uint8_t *rbuf, size_t rlen, struct lib_binder_rx *rx)
{
	size_t consumed = 0;
	int rc = lib_binder_transact_code(fd, target, code, 0, data, dlen,
					  offsets, olen, rbuf, rlen, &consumed);
	if (rc == 0)
		lib_binder_parse(rbuf, consumed, rx);
	while ((rc != 0 && errno == EAGAIN) || (rc == 0 && !rx->got_transaction)) {
		rc = lib_binder_wait_reply(fd, rbuf, rlen, &consumed, 3000);
		if (rc != 0)
			break;
		lib_binder_parse(rbuf, consumed, rx);
	}
	return rc;
}

static int call_get_handle(int fd, uint32_t target, uint32_t code,
			   const void *data, size_t dlen,
			   const void *offsets, size_t olen,
			   uint32_t *out_handle)
{
	uint8_t rbuf[256];
	struct lib_binder_rx rx;

	if (transact_until_reply(fd, target, code, data, dlen, offsets, olen,
				 rbuf, sizeof(rbuf), &rx) != 0)
		return -1;
	if (!rx.got_transaction || rx.failed || !rx.handle)
		return -1;
	if (out_handle)
		*out_handle = rx.handle;
	return 0;
}

int lib_am_check_service(int fd, const char *name, uint32_t *out_handle)
{
	uint8_t buf[256];
	size_t off = 0;

	off += put_interface_token(buf + off, "android.os.IServiceManager");
	off += put_str16(buf + off, name);

	/* Handle 0 is the real servicemanager on every process's /dev/binder,
	 * needing no lookup of its own. */
	return call_get_handle(fd, 0, LIB_AM_TXN_checkService, buf, off, NULL, 0,
			       out_handle);
}

int lib_am_get_content_provider_external(int fd, uint32_t am_handle,
					 const char *authority, int32_t user_id,
					 uint32_t *out_handle)
{
	uint8_t buf[512];
	size_t off = 0;

	off += put_interface_token(buf + off, "android.app.IActivityManager");
	off += put_str16(buf + off, authority);
	off += put_i32(buf + off, user_id);
	off += put_null_binder(buf + off);   /* IBinder token -- unused, null */
	off += put_str16(buf + off, "amclient");   /* dumpsys tag */

	/* No offsets table: the request carries no real Binder object, only
	 * the null argument's bare zero (see put_null_binder()). The reply
	 * does carry one (the provider handle), which call_get_handle() reads
	 * from the REPLY's own offsets table -- a separate, independent thing
	 * from this request's. */
	return call_get_handle(fd, am_handle, LIB_AM_TXN_getContentProviderExternal,
			       buf, off, NULL, 0, out_handle);
}

int lib_am_force_stop_package(int fd, uint32_t am_handle,
			      const char *package, int32_t user_id)
{
	uint8_t buf[256];
	uint8_t rbuf[256];
	size_t off = 0;
	struct lib_binder_rx rx;

	off += put_interface_token(buf + off, "android.app.IActivityManager");
	off += put_str16(buf + off, package);
	off += put_i32(buf + off, user_id);

	/* void return: a well-formed reply is an accepted call. The reply's
	 * leading int is readException()'s marker; a nonzero value there is an
	 * exception, but this reads only whether a transaction landed at all
	 * -- the header doc says why that is enough for this function. This is
	 * the call transact_until_reply()'s own doc names as the slow-server
	 * case: confirmed on hardware to need its retry, not just
	 * lib_binder_wait_reply()'s EAGAIN case alone -- a first read reliably
	 * caught only the completion acknowledgement, well before AMS finished
	 * actually tearing the target process down. */
	if (transact_until_reply(fd, am_handle, LIB_AM_TXN_forceStopPackage,
				 buf, off, NULL, 0, rbuf, sizeof(rbuf), &rx) != 0)
		return -1;
	return (rx.got_transaction && !rx.failed) ? 0 : -1;
}
