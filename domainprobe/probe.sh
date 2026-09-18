#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# probe.sh -- run the same probe table in every domain we can reach, and print
# them side by side. Four domains, one source (app/src/main/cpp/probe.c):
#
#   u:r:shell:s0        a pushed binary over adb
#   u:r:runas_app:s0    the same binary under run-as (needs a debuggable app)
#   u:r:untrusted_app*  the JNI library, triggered by broadcast
#   u:r:isolated_app:s0 the same library in an isolatedProcess service
#
# The app half answers by writing its own files dir, which shell can read --
# that is the whole channel, no binder service required.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PKG=dev.pixelksu.domainprobe
BIN=${DOMAINPROBE_BIN:-/tmp/domainprobe-bin}

[ -x "$BIN" ] || ${CC_AARCH64:-aarch64-linux-gnu-gcc} -static -O1 -DDOMAINPROBE_MAIN \
    -o "$BIN" "$HERE/app/src/main/cpp/probe.c"

echo "=== u:r:shell:s0 ==="
adb push "$BIN" /data/local/tmp/domainprobe-bin >/dev/null
adb shell chmod 755 /data/local/tmp/domainprobe-bin
adb shell /data/local/tmp/domainprobe-bin /data/local/tmp

if adb shell "pm path $PKG" >/dev/null 2>&1; then
    echo
    echo "=== u:r:runas_app:s0 ==="
    adb shell "cat /data/local/tmp/domainprobe-bin > /data/local/tmp/dp2 && chmod 755 /data/local/tmp/dp2" || true
    adb shell "run-as $PKG sh -c 'cp /data/local/tmp/dp2 ./dp && chmod 755 ./dp && ./dp \$PWD; rm -f ./dp'" 2>&1 || \
        echo "(run-as exec refused; the binary must be copied into the app dir first)"

    echo
    echo "=== app + isolated domains (via broadcast) ==="
    adb logcat -c
    adb shell am broadcast -a $PKG.RUN -p $PKG >/dev/null
    adb shell am start -n $PKG/.MainActivity >/dev/null 2>&1 || true
    sleep 5
    adb logcat -d -s domainprobe | sed 's/^.*domainprobe: //'
else
    echo "(app not installed: gradle :app:assembleDebug && adb install -r ...)"
fi
