#!/usr/bin/env python3
import sys
import os
import json
import re

FEATURE_PATTERNS = {
    # strings commonly used when checking for root status
    "root_detection": [
        r"isrooted", r"checkroot", r"rootbeer", r"/system/bin/su", r"test-keys",
        r"magisk", r"ro\.secure", r"ro\.debuggable",
    ],
    # attempts to determine if the app is running on an emulator
    "emulator_detection": [
        r"generic", r"goldfish", r"ranchu", r"google_sdk", r"emulator",
    ],
    # checks whether a debugger is attached
    "debug_checks": [r"isdebuggerconnected", r"Debug\.isDebuggerConnected"],
    # attempts to detect Frida instrumentation
    "frida_detection": [r"frida", r"frida-server", r"libfrida"],
    # certificate pinning or other SSL protection implementations
    "ssl_pinning": [r"certificatepinner", r"pinningtrustmanager", r"okhttp3"],
}

def _matches_patterns(content: str, patterns) -> bool:
    """Return True if at least two patterns match to reduce false positives."""
    matches = sum(1 for pat in patterns if re.search(pat, content, re.I))
    return matches >= 2


def scan_features(directory):
    features = {key: False for key in FEATURE_PATTERNS}
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(('.smali', '.java', '.kt', '.xml')):
                try:
                    with open(os.path.join(root, f), 'r', errors='ignore') as fh:
                        content = fh.read()
                        for key, patterns in FEATURE_PATTERNS.items():
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
