#!/usr/bin/env python3
"""Validate a Sigma rule file against detection engineering standards."""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print(json.dumps({"error": "PyYAML not installed — run: pip install pyyaml"}))
    sys.exit(2)

VALID_LEVELS = {"low", "medium", "high", "critical"}
ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
FILENAME_RE = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*\.ya?ml$")


def check_attack_tags(rule: dict) -> list[str]:
    issues = []
    tags = rule.get("tags", [])
    if not tags:
        issues.append("No 'tags' field found — at least one attack.tXXXX tag is required")
        return issues
    technique_tags = [t for t in tags if ATTACK_TECHNIQUE_RE.match(str(t))]
    if not technique_tags:
        tactic_only = [t for t in tags if str(t).startswith("attack.")]
        if tactic_only:
            issues.append(
                f"Only tactic-level tags found ({tactic_only}) — a specific technique "
                "tag (attack.tXXXX or attack.tXXXX.YYY) is required"
            )
        else:
            issues.append("No attack.tXXXX technique tag found in 'tags'")
    return issues


def check_level(rule: dict) -> list[str]:
    issues = []
    level = rule.get("level")
    if level is None:
        issues.append("Missing 'level' field — must be one of: low, medium, high, critical")
    elif str(level).lower() not in VALID_LEVELS:
        issues.append(
            f"Invalid level '{level}' — must be one of: {', '.join(sorted(VALID_LEVELS))}"
        )
    return issues


def check_falsepositives(rule: dict) -> list[str]:
    issues = []
    fp = rule.get("falsepositives")
    if fp is None:
        issues.append("Missing 'falsepositives' field")
        return issues
    if not isinstance(fp, list) or len(fp) == 0:
        issues.append("'falsepositives' must be a non-empty list")
        return issues
    # Reject placeholder-only entries
    placeholder = {"unknown"}
    entries = [str(e).strip().lower() for e in fp]
    if all(e in placeholder for e in entries):
        issues.append(
            "'falsepositives' contains only 'Unknown' — document at least one concrete "
            "scenario or explicitly state no false positives are expected with reasoning"
        )
    return issues


def check_tests(rule: dict, raw_text: str) -> list[str]:
    issues = []
    # Inline tests block (non-standard but supported in this KB)
    inline_tests = rule.get("tests")
    if inline_tests and isinstance(inline_tests, list) and len(inline_tests) > 0:
        return issues  # at least one inline test present

    # Fall back to checking for a 'tests:' key anywhere in the raw YAML text,
    # covering multi-document files or partial parses
    if re.search(r"^\s*tests\s*:", raw_text, re.MULTILINE):
        return issues

    issues.append(
        "No test cases found — add an inline 'tests:' block with at least one "
        "'expected: match' entry, or create a companion <rule_name>.test.yml file"
    )
    return issues


def check_filename(path: Path) -> list[str]:
    issues = []
    name = path.name
    if not FILENAME_RE.match(name):
        issues.append(
            f"Filename '{name}' does not follow the required pattern: "
            "all lowercase letters, digits, and underscores only (e.g. proc_access_win_lsass.yml)"
        )
    return issues


def check_level_justification(raw_text: str, rule: dict) -> list[str]:
    """Warn (not fail) when no comment appears immediately above the level field."""
    issues = []
    level = rule.get("level")
    if level is None:
        return issues  # already flagged by check_level
    # Look for a comment line directly before 'level:'
    pattern = re.compile(r"#[^\n]+\n\s*level\s*:", re.MULTILINE)
    if not pattern.search(raw_text):
        issues.append(
            "No inline justification comment found above 'level:' — "
            "add a # comment explaining why this severity was chosen"
        )
    return issues


def validate(path: Path) -> dict:
    result = {
        "file": str(path),
        "valid": False,
        "checks": {
            "attack_technique_tag": {"passed": False, "issues": []},
            "severity_level":       {"passed": False, "issues": []},
            "false_positives":      {"passed": False, "issues": []},
            "test_cases":           {"passed": False, "issues": []},
            "filename":             {"passed": False, "issues": []},
        },
        "warnings": [],
        "summary": [],
    }

    if not path.exists():
        result["summary"].append(f"File not found: {path}")
        return result

    raw_text = path.read_text(encoding="utf-8")

    try:
        rule = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        result["summary"].append(f"YAML parse error: {exc}")
        return result

    if not isinstance(rule, dict):
        result["summary"].append("Rule file did not parse to a YAML mapping")
        return result

    checks = result["checks"]

    issues = check_attack_tags(rule)
    checks["attack_technique_tag"]["issues"] = issues
    checks["attack_technique_tag"]["passed"] = len(issues) == 0

    issues = check_level(rule)
    checks["severity_level"]["issues"] = issues
    checks["severity_level"]["passed"] = len(issues) == 0

    issues = check_falsepositives(rule)
    checks["false_positives"]["issues"] = issues
    checks["false_positives"]["passed"] = len(issues) == 0

    issues = check_tests(rule, raw_text)
    checks["test_cases"]["issues"] = issues
    checks["test_cases"]["passed"] = len(issues) == 0

    issues = check_filename(path)
    checks["filename"]["issues"] = issues
    checks["filename"]["passed"] = len(issues) == 0

    # Warnings (non-blocking)
    result["warnings"].extend(check_level_justification(raw_text, rule))

    passed = sum(1 for c in checks.values() if c["passed"])
    total = len(checks)
    result["valid"] = passed == total
    result["summary"].append(f"{passed}/{total} checks passed")

    failed = [name for name, c in checks.items() if not c["passed"]]
    if failed:
        result["summary"].append(f"Failed checks: {', '.join(failed)}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a Sigma rule against detection engineering standards"
    )
    parser.add_argument("rule_file", help="Path to the Sigma rule YAML file")
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if validation fails (useful in CI)",
    )
    args = parser.parse_args()

    result = validate(Path(args.rule_file))
    print(json.dumps(result, indent=2))

    if args.exit_code and not result["valid"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
