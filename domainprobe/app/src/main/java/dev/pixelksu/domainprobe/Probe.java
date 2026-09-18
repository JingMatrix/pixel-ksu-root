package dev.pixelksu.domainprobe;

/** The native probe. Loaded into whichever process calls it, so the answer is
 *  that process's SELinux domain -- which is the whole point. */
public final class Probe {
    static { System.loadLibrary("domainprobe"); }
    public static native String run(String filesDir);
    /** Content for one INFO row, read on demand (tap), not during run(). */
    public static native String content(String filesDir, String name);
    /** One [offset,offset+len) slice of a row's content, for paging over binder. */
    public static native String contentChunk(String name, int offset, int len);
    private Probe() {}
}
