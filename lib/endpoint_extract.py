#!/usr/bin/env python3
"""
endpoint_extract.py <js_dir> <out_json>

Walks every downloaded JS file and pulls out candidate endpoints:
absolute URLs, absolute/relative paths, API-looking routes, and
fetch/axios/XHR call targets. Regex set is the common, battle-tested
pattern family used by tools like LinkFinder / JSFinder.
"""
import json
import os
import re
import sys

ENDPOINT_REGEX = re.compile(
    r"""
    (?:"|')
    (
        (?:/[a-zA-Z0-9_?&=\-\#\.%\+/]*)                     # relative path starting with /
        |
        (?:[a-zA-Z0-9_\-]+\.(?:php|json|action|aspx|jsp)(?:[\?][a-zA-Z0-9_&=\-\.%]*)?)  # file-style endpoints
        |
        (?:https?://[a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_?&=\-\#\.%\+/]*)?)                   # absolute URLs
    )
    (?:"|')
    """,
    re.VERBOSE,
)

CALL_CONTEXT_REGEX = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\$\.(?:get|post|ajax)|XMLHttpRequest|open)\s*\(\s*(?:["']([^"']+)["'])""",
    re.IGNORECASE,
)

NOISE_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|woff2?|ttf|eot|css|ico)(\?|$)", re.IGNORECASE)
MIN_LEN = 4


def extract_from_text(text):
    found = set()
    for m in ENDPOINT_REGEX.finditer(text):
        val = m.group(1)
        if val and len(val) >= MIN_LEN and not NOISE_EXT.search(val):
            found.add(val)
    for m in CALL_CONTEXT_REGEX.finditer(text):
        val = m.group(1)
        if val and len(val) >= MIN_LEN and not NOISE_EXT.search(val):
            found.add(val)
    return found


def main():
    if len(sys.argv) != 3:
        print("usage: endpoint_extract.py <js_dir> <out_json>", file=sys.stderr)
        sys.exit(1)

    js_dir, out_json = sys.argv[1], sys.argv[2]
    results = []

    for root, _, files in os.walk(js_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue

            endpoints = extract_from_text(text)
            for ep in sorted(endpoints):
                results.append({
                    "source_file": os.path.relpath(fpath, js_dir),
                    "endpoint": ep,
                })

    with open(out_json, "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
