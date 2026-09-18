package dev.pixelksu.domainprobe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * The shell side of the channel.
 *
 * A probe app is only useful if the host can drive it, and the host lives in
 * u:r:shell:s0 while the app lives in untrusted_app. Shell cannot enter the
 * app's process, but it can send it a broadcast, and the app can write where
 * shell can read. That pair is a request/response channel with no binder service
 * and no special permission:
 *
 *   adb shell am broadcast -a dev.pixelksu.domainprobe.RUN     -p dev.pixelksu.domainprobe
 *   adb shell am broadcast -a dev.pixelksu.domainprobe.TELECOM -p dev.pixelksu.domainprobe
 *   adb shell run-as dev.pixelksu.domainprobe cat files/domainprobe.txt
 *   adb logcat -s domainprobe        # system_server section lands here
 *
 * Same idea as Shizuku, minus the binder: the privileged side asks, the
 * in-domain side answers, and the app-domain measurement (slabinfo, sockets,
 * tracepoint arming) runs in the domain a real delivery would use.
 */
public final class ProbeReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context ctx, Intent intent) {
        String action = intent != null ? intent.getAction() : null;
        String pkg = ctx.getPackageName();
        if ((pkg + ".TELECOM").equals(action)) {
            Telecom.fire(ctx);
            return;
        }
        // default and .RUN: probe this (untrusted_app) domain.
        StringBuilder acc = new StringBuilder();
        Report.section(ctx, acc, "=== app domain (broadcast) ===",
                       Probe.run(ctx.getFilesDir().getAbsolutePath()));
        Log.i(Report.TAG, "app domain written to files/domainprobe.txt");
    }
}
