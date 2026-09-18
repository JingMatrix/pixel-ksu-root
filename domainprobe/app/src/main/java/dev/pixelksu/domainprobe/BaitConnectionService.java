package dev.pixelksu.domainprobe;

import android.telecom.Connection;
import android.telecom.ConnectionRequest;
import android.telecom.ConnectionService;
import android.telecom.DisconnectCause;
import android.telecom.PhoneAccountHandle;

/** Returns a live self-managed Connection so Telecom takes the call to RINGING
 *  and binds InCallServices — the point at which InCallController enumerates
 *  them and runs serviceClassExists(). A null return (the empty-subclass
 *  default) fails the call before that enumeration. */
public final class BaitConnectionService extends ConnectionService {
    static final class Call extends Connection {
        @Override public void onShowIncomingCallUi() { setActive(); }
        @Override public void onAnswer()  { setActive(); }
        @Override public void onReject()  { setDisconnected(new DisconnectCause(DisconnectCause.REJECTED)); destroy(); }
        @Override public void onDisconnect() { setDisconnected(new DisconnectCause(DisconnectCause.LOCAL)); destroy(); }
    }
    private static Connection make() {
        Call c = new Call();
        c.setConnectionProperties(Connection.PROPERTY_SELF_MANAGED);
        c.setActive();
        return c;
    }
    @Override public Connection onCreateIncomingConnection(PhoneAccountHandle h, ConnectionRequest r) { return make(); }
    @Override public Connection onCreateOutgoingConnection(PhoneAccountHandle h, ConnectionRequest r) { return make(); }
}
