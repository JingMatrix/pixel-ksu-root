package dev.pixelksu.domainprobe;

interface IShellProbe {
    String run() = 1;
    String content(String name) = 2;
    String contentChunk(String name, int offset, int len) = 3;
    void destroy() = 16777114;   // Shizuku calls this on unbind
}
