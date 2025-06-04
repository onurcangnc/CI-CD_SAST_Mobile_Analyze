#!/usr/bin/env python3
import sys
import os
import json

FEATURE_KEYWORDS = {
    "root_detection": ["isrooted", "checkroot", "rootbeer"],
    "debug_checks": ["isdebuggerconnected", "debuggable"],
    "cert_pinning": ["certificatepinner", "okhttp3"],
}

def scan_features(directory):
    features = {key: False for key in FEATURE_KEYWORDS}
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(('.smali', '.java', '.kt')):
                try:
                    with open(os.path.join(root, f), 'r', errors='ignore') as fh:
                        content = fh.read().lower()
                        for key, keywords in FEATURE_KEYWORDS.items():
                            if any(k in content for k in keywords):
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
