#!/usr/bin/env python3
import json
import sys
import os

if len(sys.argv) != 3:
    print("Usage: baseline_to_html.py <baseline_json> <output_html>")
    sys.exit(1)

baseline_path, html_path = sys.argv[1:3]

with open(baseline_path) as f:
    data = json.load(f)

results = data.get("results", {})
rows = []
for file, secrets in results.items():
    for item in secrets:
        rows.append(
            (
                file,
                item.get("type", ""),
                str(item.get("line_number", "")),
            )
        )

dir_name = os.path.dirname(html_path)
if dir_name:
    os.makedirs(dir_name, exist_ok=True)
rows_html = "\n".join(
    f"<tr><td>{file}</td><td>{stype}</td><td>{line}</td></tr>" for file, stype, line in rows
)
html = (
    "<html><head><meta charset='UTF-8'>"
    "<title>detect-secrets Report</title></head><body>"
    "<h1>detect-secrets Findings</h1>"
    "<table border='1'><tr><th>File</th><th>Type</th><th>Line</th></tr>"
    f"{rows_html}</table></body></html>"
)
with open(html_path, "w") as f:
    f.write(html)
