package dev.pixelksu.domainprobe;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Where a probe's findings go. Every domain's section is logged under one tag so
 * `adb logcat -s domainprobe` shows all of them live -- including system_server,
 * which can only report that way. The domains that run in this app's own process
 * also write a file, to both the internal data dir (readable via run-as) and the
 * external files dir (readable by plain shell), so the host can pull a result
 * without logcat.
 */
final class Report {
    static final String TAG = "domainprobe";
    private Report() {}

    /** Log a section and append it to the on-device file. */
    static void section(Context ctx, StringBuilder acc, String header, String body) {
        Log.i(TAG, header);
        for (String line : body.split("\n")) Log.i(TAG, line);
        acc.append(header).append('\n').append(body).append('\n');
        write(ctx, acc.toString());
    }

    static void write(Context ctx, String text) {
        writeTo(new File(ctx.getFilesDir(), "domainprobe.txt"), text);
        File ext = ctx.getExternalFilesDir(null);
        if (ext != null) writeTo(new File(ext, "domainprobe.txt"), text);
    }

    private static void writeTo(File f, String text) {
        try (FileOutputStream s = new FileOutputStream(f)) {
            s.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.w(TAG, "write " + f + " failed: " + e);
        }
    }
}
