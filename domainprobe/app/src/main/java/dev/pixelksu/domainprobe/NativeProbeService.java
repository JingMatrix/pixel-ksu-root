package dev.pixelksu.domainprobe;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;

/**
 * Declared android:isolatedProcess + android:nativeService. On Android 17 the
 * framework loads libmain.so and calls ANativeService_onCreate (probe.c,
 * DOMAINPROBE_NATIVESVC), which registers its own binder from the native zygote
 * process — that native binder is what the app receives and calls run() on.
 *
 * This Java class is the declared component and a fallback: on a platform that
 * instantiates it as an ordinary isolated service, it still answers run() so the
 * app degrades to an isolated-domain result instead of failing to bind.
 */
public final class NativeProbeService extends Service {
    private final IShellProbe.Stub binder = new IShellProbe.Stub() {
        @Override public String run() { return Probe.run(""); }
        @Override public String content(String name) { return Probe.content("", name); }
        @Override public String contentChunk(String name, int offset, int len) { return Probe.contentChunk(name, offset, len); }
        @Override public void destroy() {}
    };
    @Override public IBinder onBind(Intent i) {
        return Process.isIsolated() ? binder : null;
    }
}
