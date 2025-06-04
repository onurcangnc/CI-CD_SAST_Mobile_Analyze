#!/usr/bin/env python3
import sys
import os
import json
import re

FEATURE_PATTERNS = {
    # strings commonly used when checking for root status
    "root_detection": [
        r"isrooted", r"checkroot", r"rootbeer", r"/system/bin/su", r"test-keys",
        r"magisk", r"ro\.secure", r"ro\.debuggable", r"supersu", r"busybox",
        r"superuser", r"isroot", r"/su/bin/su", r"xposed", r"rootcloak",
        r"/system/xbin/su", r"/sbin/su", r"/system/app/Superuser\.apk",
        r"/system/app/Magisk\.apk", r"com\.noshufou\.android\.su",
        r"com\.koushikdutta\.superuser", r"eu\.chainfire\.supersu",
        r"kinguser", r"kingroot", r"magiskmanager", r"rootaccess",
    ],
    # attempts to determine if the app is running on an emulator
    "emulator_detection": [
        r"generic", r"goldfish", r"ranchu", r"google_sdk", r"emulator",
        r"genymotion", r"bluestacks", r"nox", r"vbox", r"qemu", r"sdk_gphone",
        r"vbox86", r"virtualbox", r"memu", r"ldplayer", r"android sdk built for",
        r"x86", r"ro\.kernel\.qemu", r"droid4x",
    ],
    # checks whether a debugger is attached
    "debug_checks": [
        r"isdebuggerconnected", r"Debug\.isDebuggerConnected", r"adb",
        r"tracerpid", r"android\.os\.Debug", r"debugger",
        r"Debug\.waitForDebugger", r"waitfordebugger", r"debuggerd",
        r"gdbserver", r"lldb", r"android\.ddm", r"ptrace",
    ],
    # attempts to detect Frida instrumentation
    "frida_detection": [
        r"frida", r"frida-server", r"libfrida", r"fridaserver", r"gadget",
        r"gum-js-loop", r"re\.frida\.server", r"frida-gadget",
        r"libfrida-gadget", r"frida_agent", r"frida-java", r"frida-hooks",
    ],
    # certificate pinning or other SSL protection implementations
    "ssl_pinning": [
        r"certificatepinner", r"pinningtrustmanager", r"okhttp3",
        r"trustmanager", r"sslpinning", r"networksecurityconfig",
        r"trustkit", r"publickeypin", r"sslcontext", r"x509trustmanager",
        r"hostnameverifier", r"sslsocketfactory", r"okhttpclient",
    ],
}

# pre-compile regex patterns for efficiency
COMPILED_PATTERNS = {
    feature: [re.compile(pat, re.I) for pat in pats]
    for feature, pats in FEATURE_PATTERNS.items()
}

def _matches_patterns(content: str, patterns) -> bool:
    """Return True if at least two patterns match to reduce false positives."""
    matches = sum(1 for pat in patterns if pat.search(content))
    return matches >= 2


def scan_features(directory):
    features = {key: False for key in FEATURE_PATTERNS}
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(('.smali', '.java', '.kt', '.xml')):
                try:
                    with open(os.path.join(root, f), 'r', errors='ignore') as fh:
                        content = fh.read()
                        for key, patterns in COMPILED_PATTERNS.items():
                            if not features[key] and _matches_patterns(content, patterns):
                                features[key] = True
                except Exception:
                    continue
    return features

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: security_check.py <source_dir>")
        sys.exit(1)
    result = scan_features(sys.argv[1])
    print(json.dumps(result, indent=2))
