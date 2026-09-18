package dev.pixelksu.domainprobe;

import android.content.Context;

/**
 * Runs inside the Shizuku (or Sui) service process — uid 2000, u:r:shell:s0 —
 * so the same native probe answers for the shell domain from within the app,
 * without the host script. Shizuku starts it via app_process with our APK on the
 * classpath, so it can load our native library and call {@link Probe}.
 */
public final class ShellProbeService extends IShellProbe.Stub {
    public ShellProbeService() {}
    public ShellProbeService(Context context) {}

    @Override public String run() {
        // /data/local/tmp is the shell-writable dir for the xattr round-trip.
        return Probe.run("/data/local/tmp");
    }

    @Override public String content(String name) {
        return Probe.content("/data/local/tmp", name);
    }

    @Override public String contentChunk(String name, int offset, int len) {
        return Probe.contentChunk(name, offset, len);
    }

    @Override public void destroy() { System.exit(0); }
}
