#!/usr/bin/env python3
"""
sigma_parser.py — Export a Sigma rules directory to a CSV index.

Usage:
    python3 sigma_parser.py [--rules-dir PATH] [--output PATH]

Defaults:
    --rules-dir  ./sigma/rules
    --output     ./Sigma_rules.csv

Columns in output CSV:
    sl no | Detection Name | Category | TTP | Severity

Dependencies:
    pip install pyyaml
"""

import argparse
import csv
import os
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: install PyYAML with  pip install pyyaml")


TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def parse_rule(fpath: str, rules_dir: str) -> dict | None:
    """Parse a single Sigma YAML file and return a row dict, or None on failure."""
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            doc = yaml.safe_load(f)
    except Exception:
        return None

    if not isinstance(doc, dict):
        return None

    # Category = first path component under rules_dir
    rel = os.path.relpath(os.path.dirname(fpath), rules_dir)
    parts = rel.split(os.sep)
    category = parts[0] if parts and parts[0] != "." else "unknown"

    # MITRE technique IDs from tags
    tags = doc.get("tags") or []
    techniques = [
        m.group(1).upper()
        for tag in tags
        if (m := TECHNIQUE_RE.match(str(tag)))
    ]

    return {
        "Detection Name": (doc.get("title") or "").strip(),
        "Category": category,
        "TTP": ", ".join(techniques),
        "Severity": (doc.get("level") or "").strip(),
    }


def main():
    parser = argparse.ArgumentParser(description="Export Sigma rules directory to CSV.")
    parser.add_argument("--rules-dir", default="./sigma/rules",
                        help="Root directory containing Sigma rule YAML files")
    parser.add_argument("--output", default="./Sigma_rules.csv",
                        help="Output CSV file path")
    args = parser.parse_args()

    rules_dir = os.path.abspath(args.rules_dir)
    if not os.path.isdir(rules_dir):
        sys.exit(f"Rules directory not found: {rules_dir}")

    rows = []
    skipped = 0

    for root, _, files in os.walk(rules_dir):
        for fname in sorted(files):
            if not fname.endswith(".yml"):
                continue
            result = parse_rule(os.path.join(root, fname), rules_dir)
            if result is None:
                skipped += 1
                continue
            rows.append(result)

    # Sort by category then detection name for a stable, readable order
    rows.sort(key=lambda r: (r["Category"], r["Detection Name"].lower()))

    output_path = os.path.abspath(args.output)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sl no", "Detection Name", "Category", "TTP", "Severity"])
        for sl, row in enumerate(rows, start=1):
            writer.writerow([sl, row["Detection Name"], row["Category"],
                             row["TTP"], row["Severity"]])

    print(f"Wrote {len(rows)} rules to {output_path}")
    if skipped:
        print(f"Skipped {skipped} files (parse errors or non-rule YAML)")


if __name__ == "__main__":
    main()
