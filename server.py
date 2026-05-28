#!/usr/bin/env python3
"""MCP server exposing Sigma detection rules as browsable resources."""

import asyncio
import json
import re
from pathlib import Path

import yaml
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource
from pydantic import AnyUrl

RULES_DIR    = Path(__file__).parent / "rules"
MAPPINGS_DIR = Path(__file__).parent / "mappings"
ATTACK_FILE  = MAPPINGS_DIR / "attack_techniques.json"

server = Server("detection-kb")


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def _load_rules() -> dict[str, dict]:
    """Return {stem: rule_dict} for every parseable YAML in rules/."""
    rules: dict[str, dict] = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text())
            if isinstance(data, dict):
                rules[path.stem] = data
        except Exception:
            pass
    return rules


def _load_attack() -> dict[str, dict]:
    """Return the cached ATT&CK technique index {T1234.001: {name, description, tactics, url}}."""
    if not ATTACK_FILE.exists():
        return {}
    return json.loads(ATTACK_FILE.read_text())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _techniques(rule: dict) -> list[str]:
    """Extract uppercase ATT&CK technique IDs from a rule's tags."""
    results = []
    for tag in rule.get("tags") or []:
        m = re.search(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag), re.IGNORECASE)
        if m:
            results.append(m.group(1).upper())
    return results


def _summary(name: str, rule: dict) -> dict:
    return {
        "name":        name,
        "title":       rule.get("title", ""),
        "status":      rule.get("status", ""),
        "level":       rule.get("level", ""),
        "techniques":  _techniques(rule),
        "description": (rule.get("description") or "")[:120],
    }


def _coverage_assessment(rules_for_tech: list[dict]) -> str:
    """
    Rate detection coverage for a technique given the matching rules.

    covered  – ≥2 rules, OR one stable rule at high/critical severity
    partial  – rules exist but don't meet the covered bar
    gap      – no rules at all
    """
    if not rules_for_tech:
        return "gap"
    if len(rules_for_tech) >= 2:
        return "covered"
    rule = rules_for_tech[0]
    if rule.get("status") == "stable" and rule.get("level") in ("high", "critical"):
        return "covered"
    return "partial"


def _technique_index(rules: dict[str, dict]) -> dict[str, list[str]]:
    """Return {technique_id: [rule_stem, ...]} built from parsed rules."""
    index: dict[str, list[str]] = {}
    for name, rule in rules.items():
        for tech in _techniques(rule):
            index.setdefault(tech, []).append(name)
    return index


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@server.list_resources()
async def list_resources() -> list[Resource]:
    rules  = _load_rules()
    attack = _load_attack()
    tech_index = _technique_index(rules)

    resources: list[Resource] = [
        Resource(
            uri=AnyUrl("detection://rules"),
            name="All Detection Rules",
            description=f"Index of {len(rules)} available Sigma detection rules",
            mimeType="application/json",
        )
    ]

    # One resource per rule file
    for name, rule in rules.items():
        techs    = _techniques(rule)
        tech_str = ", ".join(techs) if techs else "untagged"
        resources.append(Resource(
            uri=AnyUrl(f"detection://rules/{name}"),
            name=rule.get("title", name),
            description=f"[{rule.get('level', '?')}] {tech_str}",
            mimeType="text/yaml",
        ))

    # One detection://rules/by-technique resource per unique technique
    for tech_id in sorted(tech_index):
        count = len(tech_index[tech_id])
        resources.append(Resource(
            uri=AnyUrl(f"detection://rules/by-technique/{tech_id}"),
            name=f"Rules for {tech_id}",
            description=f"{count} rule{'s' if count != 1 else ''} covering {tech_id}",
            mimeType="application/json",
        ))

    # One detection://attack/techniques resource per technique that has any coverage
    for tech_id in sorted(tech_index):
        tech_meta = attack.get(tech_id, {})
        rules_for = [rules[n] for n in tech_index[tech_id] if n in rules]
        assessment = _coverage_assessment(rules_for)
        tech_name  = tech_meta.get("name", tech_id)
        resources.append(Resource(
            uri=AnyUrl(f"detection://attack/techniques/{tech_id}"),
            name=f"{tech_id}: {tech_name}",
            description=f"Coverage: {assessment} | {len(rules_for)} rule{'s' if len(rules_for) != 1 else ''}",
            mimeType="application/json",
        ))

    return resources


@server.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    uri_str = str(uri)
    rules   = _load_rules()
    attack  = _load_attack()

    # --- detection://rules -----------------------------------------------
    if uri_str == "detection://rules":
        return json.dumps([_summary(n, r) for n, r in rules.items()], indent=2)

    # --- detection://rules/by-technique/{technique_id} -------------------
    m = re.fullmatch(r"detection://rules/by-technique/([A-Z0-9.]+)", uri_str)
    if m:
        tech_id = m.group(1)
        matched = [_summary(n, r) for n, r in rules.items() if tech_id in _techniques(r)]
        if not matched:
            raise ValueError(f"No rules found for technique: {tech_id}")
        return json.dumps({"technique": tech_id, "count": len(matched), "rules": matched}, indent=2)

    # --- detection://attack/techniques/{technique_id} --------------------
    m = re.fullmatch(r"detection://attack/techniques/([A-Z0-9.]+)", uri_str)
    if m:
        tech_id   = m.group(1)
        tech_meta = attack.get(tech_id)
        if not tech_meta:
            raise ValueError(f"Technique {tech_id} not found in ATT&CK index")

        matching_rules = {
            name: rule
            for name, rule in rules.items()
            if tech_id in _techniques(rule)
        }
        rules_for      = list(matching_rules.values())
        assessment     = _coverage_assessment(rules_for)

        return json.dumps({
            "technique_id": tech_id,
            "name":         tech_meta["name"],
            "description":  tech_meta["description"],
            "tactics":      tech_meta["tactics"],
            "url":          tech_meta["url"],
            "coverage": {
                "assessment": assessment,
                "rule_count": len(matching_rules),
                "rules": [_summary(n, r) for n, r in matching_rules.items()],
            },
        }, indent=2)

    # --- detection://rules/{rule_name} -----------------------------------
    m = re.fullmatch(r"detection://rules/([^/]+)", uri_str)
    if m:
        rule_name  = m.group(1)
        rule_path  = RULES_DIR / f"{rule_name}.yml"
        if not rule_path.exists():
            raise ValueError(f"Rule not found: {rule_name}")
        return rule_path.read_text()

    raise ValueError(f"Unknown resource URI: {uri_str}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
