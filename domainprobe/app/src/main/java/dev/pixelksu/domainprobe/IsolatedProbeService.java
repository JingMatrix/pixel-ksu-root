package dev.pixelksu.domainprobe;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

/** Declared android:isolatedProcess="true", so this runs as u:r:isolated_app:s0
 *  with no app data dir -- the probe is told so and skips the xattr test. */
public class IsolatedProbeService extends Service {
    private static final int TX_RUN = 1;
    private static final int TX_CONTENT = 2;
    private static final int TX_CONTENT_CHUNK = 3;

    @Override public IBinder onBind(Intent i) {
        return new Binder() {
            @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                    throws RemoteException {
                if (code == TX_RUN) {
                    reply.writeString(Probe.run(""));
                    return true;
                }
                if (code == TX_CONTENT) {
                    reply.writeString(Probe.content("", data.readString()));
                    return true;
                }
                if (code == TX_CONTENT_CHUNK) {
                    String nm = data.readString(); int off = data.readInt(); int len = data.readInt();
                    reply.writeString(Probe.contentChunk(nm, off, len));
                    return true;
                }
                return super.onTransact(code, data, reply, flags);
            }
        };
    }

    static String readResult(IBinder svc) {
        Parcel in = Parcel.obtain(), out = Parcel.obtain();
        try {
            svc.transact(TX_RUN, in, out, 0);
            return out.readString();
        } catch (RemoteException e) {
            return "isolated transact failed: " + e;
        } finally {
            in.recycle();
            out.recycle();
        }
    }

    /** One content chunk for a row, read in u:r:isolated_app:s0 (paged over binder). */
    static String readContentChunk(IBinder svc, String name, int offset, int len) {
        Parcel in = Parcel.obtain(), out = Parcel.obtain();
        try {
            in.writeString(name); in.writeInt(offset); in.writeInt(len);
            svc.transact(TX_CONTENT_CHUNK, in, out, 0);
            return out.readString();
        } catch (RemoteException e) {
            return "isolated content failed: " + e;
        } finally {
            in.recycle();
            out.recycle();
        }
    }
}
