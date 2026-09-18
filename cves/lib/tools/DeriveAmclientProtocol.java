// DeriveAmclientProtocol.java -- re-derive the constants lib/trigger/amclient.h
// hardcodes, on a device other than the one they were read from.
//
// amclient.h talks to two of IActivityManager's internal methods
// (getContentProviderExternal, forceStopPackage) by hand-rolled AIDL
// transaction, because they are hidden platform API with no public NDK
// wrapper -- android/binder_manager.h's AServiceManager_* calls do not cover
// them at all. Two things about that protocol are NOT stable across Android
// versions and must be read off the device the exploit actually targets,
// never assumed from AOSP source of a possibly different one:
//
//   1. Transaction codes. AIDL numbers a Stub's TRANSACTION_* constants by
//      declaration order in the .aidl file, so a method added or reordered
//      between releases renumbers everything after it.
//   2. Parcel.writeInterfaceToken()'s exact bytes. Android 17 writes a
//      12-byte strict-mode/work-source header before the interface name
//      string; older write-ups of this technique that predate that header
//      will send a malformed request that fails exactly like a permission
//      denial, not like a parse error -- this tool exists as a reusable
//      derivation for exactly this reason, rather than a one-off read.
//
// Run entirely as plain shell -- no root, no app install -- via app_process,
// which runs Java/Dalvik bytecode as an ordinary shell process:
//
//   javac --release 17 -d . DeriveAmclientProtocol.java
//   <build-tools>/d8 --output . DeriveAmclientProtocol.class
//   adb push classes.dex /data/local/tmp/derive.dex
//   adb shell CLASSPATH=/data/local/tmp/derive.dex app_process /system/bin \
//       DeriveAmclientProtocol
//
// Update amclient.h's LIB_AM_TXN_* defines and its INTERFACE_TOKEN_HEADER
// bytes in amclient.c from this tool's output before trusting amclient on a
// build other than the one its constants were last read from.
import java.lang.reflect.*;

public class DeriveAmclientProtocol {
    static void dumpTransactionCodes(String stubClass, String... fields) {
        try {
            Class<?> stub = Class.forName(stubClass);
            System.out.println("=== " + stubClass + " ===");
            for (String f : fields) {
                try {
                    Field fld = stub.getDeclaredField(f);
                    fld.setAccessible(true);
                    System.out.println("  " + f + " = " + fld.get(null));
                } catch (Throwable t) {
                    System.out.println("  " + f + ": " + t);
                }
            }
        } catch (Throwable t) {
            System.out.println(stubClass + ": " + t);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x ", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("--- transaction codes (-> amclient.h LIB_AM_TXN_*) ---");
        dumpTransactionCodes("android.os.IServiceManager$Stub",
                "TRANSACTION_checkService");
        dumpTransactionCodes("android.app.IActivityManager$Stub",
                "TRANSACTION_getContentProviderExternal",
                "TRANSACTION_forceStopPackage");

        System.out.println("\n--- writeInterfaceToken byte header "
                + "(-> amclient.c INTERFACE_TOKEN_HEADER) ---");
        Class<?> parcelCls = Class.forName("android.os.Parcel");
        Object p = parcelCls.getMethod("obtain").invoke(null);
        parcelCls.getMethod("writeInterfaceToken", String.class)
                .invoke(p, "x");   // a 1-char probe descriptor keeps the dump short
        byte[] raw = (byte[]) parcelCls.getMethod("marshall").invoke(p);
        // The header precedes the 4-byte string length; "x" as UTF-16LE plus
        // its null terminator is 4 bytes, so the length prefix sits at the
        // last 4 bytes before that -- i.e. raw.length - 8 marks the header end.
        int headerLen = raw.length - 8;
        byte[] header = new byte[headerLen];
        System.arraycopy(raw, 0, header, 0, headerLen);
        System.out.println("  " + hex(header));
        System.out.println("  (bytes before the 4-byte string-length prefix; "
                + "compare against amclient.c's INTERFACE_TOKEN_HEADER)");

        System.out.println("\n--- confirm the live call still resolves as expected ---");
        Object activityBinder = Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class).invoke(null, "activity");
        System.out.println("  ServiceManager.getService(\"activity\") = " + activityBinder);
    }
}
