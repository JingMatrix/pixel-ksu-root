package dev.pixelksu.domainprobe;

import android.telecom.InCallService;

/** Bait. Its manifest entry carries android.telecom.CLASS_EXISTENCE_CHECK, which
 *  is what makes InCallController call serviceClassExists() and load this app
 *  into system_server. The class does nothing itself. */
public final class BaitInCallService extends InCallService {}
