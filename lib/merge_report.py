#!/usr/bin/env python3
"""
merge_report.py --endpoints endpoints.json --secrets secrets.json --outdir DIR --format json|csv|both

Combines the endpoint-extraction output and gitleaks secret-detection output
into one clean report (grouped by source JS file), written as report.json
and/or report.csv, plus a readable console summary.
"""
import argparse
import csv
import json
import os
from collections import defaultdict


def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def normalize_secrets(raw_secrets, js_dir_hint="js"):
    """Normalize gitleaks report entries to a common shape."""
    out = []
    for s in raw_secrets:
        file_path = s.get("File", "")
        # gitleaks gives a path like <outdir>/js/sub/file.js -> keep relative to js dir
        rel = file_path
        if js_dir_hint in file_path:
            rel = file_path.split(js_dir_hint, 1)[-1].lstrip("/\\")
        out.append({
            "source_file": rel,
            "rule": s.get("RuleID", "unknown"),
            "secret": s.get("Secret", s.get("Match", "")),
            "line": s.get("StartLine", ""),
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoints", required=True)
    ap.add_argument("--secrets", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--format", default="both", choices=["json", "csv", "both"])
    args = ap.parse_args()

    endpoints = load_json(args.endpoints)
    raw_secrets = load_json(args.secrets)
    secrets = normalize_secrets(raw_secrets)

    by_file = defaultdict(lambda: {"endpoints": [], "secrets": []})
    for e in endpoints:
        by_file[e["source_file"]]["endpoints"].append(e["endpoint"])
    for s in secrets:
        by_file[s["source_file"]]["secrets"].append({
            "rule": s["rule"], "secret": s["secret"], "line": s["line"]
        })

    report = {
        "summary": {
            "files_with_findings": len(by_file),
            "total_endpoints": len(endpoints),
            "total_secrets": len(secrets),
        },
        "findings": [
            {
                "source_file": fname,
                "endpoints": sorted(set(data["endpoints"])),
                "secrets": data["secrets"],
            }
            for fname, data in sorted(by_file.items())
        ],
    }

    if args.format in ("json", "both"):
        out_path = os.path.join(args.outdir, "report.json")
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)

    if args.format in ("csv", "both"):
        out_path = os.path.join(args.outdir, "report.csv")
        with open(out_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["type", "source_file", "value", "rule_or_context", "line"])
            for fname, data in sorted(by_file.items()):
                for ep in sorted(set(data["endpoints"])):
                    writer.writerow(["endpoint", fname, ep, "", ""])
                for sec in data["secrets"]:
                    writer.writerow(["secret", fname, sec["secret"], sec["rule"], sec["line"]])

    # Console summary
    print("")
    print("=" * 60)
    print(f" Files with findings : {report['summary']['files_with_findings']}")
    print(f" Total endpoints     : {report['summary']['total_endpoints']}")
    print(f" Total secrets       : {report['summary']['total_secrets']}")
    print("=" * 60)
    if secrets:
        print(" Secrets found:")
        for s in secrets[:20]:
            print(f"   [{s['rule']}] {s['source_file']}:{s['line']}")
        if len(secrets) > 20:
            print(f"   ... and {len(secrets) - 20} more (see report.json / report.csv)")


if __name__ == "__main__":
    main()
