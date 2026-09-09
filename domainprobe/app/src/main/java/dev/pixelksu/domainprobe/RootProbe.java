package dev.pixelksu.domainprobe;

import android.content.Context;

import java.io.File;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;

/**
 * Runs the same native probe as root, when a manager (KernelSU/Magisk/APatch)
 * grants it. The probe binary already ships in the APK as libdomainprobe-cli.so;
 * su executes it, so the row set matches every other domain and the context line
 * shows whatever the root shell runs as (e.g. u:r:su:s0). Returns null when su is
 * absent or the request is denied.
 */
public final class RootProbe {
    private RootProbe() {}

    static String run(Context ctx) {
        return exec(ctx, cliPath(ctx) + " /data/local/tmp", "selinux context");
    }

    /** On-demand content for one INFO row, read in the root domain. */
    static String content(Context ctx, String name) {
        // single-quote the row name (it has spaces) for the su shell
        String out = exec(ctx, cliPath(ctx) + " --content '" + name.replace("'", "") + "' /data/local/tmp", null);
        return out != null ? out : "(root content unavailable)";
    }

    private static String cliPath(Context ctx) {
        return new File(ctx.getApplicationInfo().nativeLibraryDir, "libdomainprobe-cli.so").getAbsolutePath();
    }

    /** Root sees every process, so its content rows are the largest of any domain.
     *  Bound what crosses the pipe: read in blocks (not line by line, which built
     *  one String per line of a multi-MB blob), stop accumulating at the cap, and
     *  keep draining so the child still exits instead of blocking on a full pipe. */
    private static final int MAX = 4 << 20;

    /** Run one su -c command; return stdout, or null if no su path worked / marker absent. */
    private static String exec(Context ctx, String cmd, String marker) {
        for (String su : new String[]{"su", "/system/bin/su", "/system/xbin/su"}) {
            try {
                Process p = new ProcessBuilder(su, "-c", cmd).redirectErrorStream(true).start();
                StringBuilder sb = new StringBuilder();
                char[] buf = new char[1 << 16];
                boolean cut = false;
                try (Reader r = new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8)) {
                    int n;
                    while ((n = r.read(buf)) > 0) {
                        int room = MAX - sb.length();
                        if (room <= 0) { cut = true; continue; }
                        sb.append(buf, 0, Math.min(n, room));
                        if (n > room) cut = true;
                    }
                }
                if (cut) sb.append("\n(output truncated at ").append(MAX).append(" bytes)\n");
                boolean ok = p.waitFor() == 0 && (marker == null || sb.indexOf(marker) >= 0);
                if (ok) return sb.toString();
            } catch (Throwable ignored) { /* try the next su path */ }
        }
        return null;
    }
}
