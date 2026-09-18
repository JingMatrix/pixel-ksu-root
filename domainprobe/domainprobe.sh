#!/usr/bin/env bash
#
# domainprobe.sh — run the probe in every domain and print one table.
#
# Five domains, from the least privileged the host can drive to the most:
#
#   shell          u:r:shell:s0          the pushed cli binary, run by adbd's shell
#   runas_app      u:r:runas_app:s0      the same binary, via run-as
#   untrusted_app  u:r:untrusted_app_3x  the app process (JNI)         } MainActivity
#   isolated_app   u:r:isolated_app:s0   an isolatedProcess service    } writes a file
#   system_server  u:r:system_server:s0  CVE-2026-49881 (Java, logcat-only)
#
# Usage: ./domainprobe.sh [serial]
set -uo pipefail
PKG=dev.pixelksu.domainprobe
APK=app/build/outputs/apk/debug/app-debug.apk
ADB=(adb); [ $# -ge 1 ] && ADB=(adb -s "$1")
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

[ -f "$APK" ] || { echo "build first: gradle :app:assembleDebug"; exit 1; }
"${ADB[@]}" install -r -g "$APK" >/dev/null 2>&1 || "${ADB[@]}" install -r "$APK" >/dev/null

# The cli binary ships in the APK as a lib*.so; extract it on the host so the
# domains that need a pushed binary do not depend on on-device lib extraction.
CLI_HOST="$(mktemp)"
unzip -p "$APK" lib/arm64-v8a/libdomainprobe-cli.so > "$CLI_HOST"

say "shell  (u:r:shell:s0)"
"${ADB[@]}" push "$CLI_HOST" /data/local/tmp/dp-cli >/dev/null
"${ADB[@]}" shell "chmod 755 /data/local/tmp/dp-cli && /data/local/tmp/dp-cli /data/local/tmp; rm -f /data/local/tmp/dp-cli"

say "runas_app  (u:r:runas_app:s0)"
# hand the binary to the app over stdin (runas_app cannot read /data/local/tmp),
# then run it as the app in its own data dir (writable, for the xattr probe).
"${ADB[@]}" shell "run-as $PKG sh -c 'cat > dp-cli && chmod 700 dp-cli'" < "$CLI_HOST"
"${ADB[@]}" shell "run-as $PKG sh -c './dp-cli \$PWD; rm -f dp-cli'"
rm -f "$CLI_HOST"

say "app + isolated + system_server  (MainActivity)"
"${ADB[@]}" logcat -c
"${ADB[@]}" shell am start -n $PKG/.MainActivity >/dev/null 2>&1
sleep 6
echo "--- app + isolated (pulled file) ---"
"${ADB[@]}" shell run-as $PKG cat files/domainprobe.txt 2>/dev/null
echo "--- system_server (logcat, pid=system_server) ---"
"${ADB[@]}" logcat -d -s domainprobe 2>&1 | sed -n '/system_server domain (via/,/system_server domain end/p' | sed -E 's/^.*domainprobe: //'
