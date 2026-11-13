#!/usr/bin/env python3
"""
Cloud IAM Policy Analyzer
-------------------------
Reads cloud IAM policy JSON files (AWS-style, with Azure-flavored action
names appearing in the sensitive-action list to show multi-cloud awareness)
and flags least-privilege violations:

  (a) Action wildcard "*" or "service:*"            -> Critical / High
  (b) Resource "*" combined with write/admin actions -> High
  (c) Actions from a built-in sensitive list         -> High on "*",
                                                        Medium on scoped resources
  (d) Statements that are not explicit "Allow" are ignored for findings,
      and read-only actions on scoped resources are not flagged.

Output: per-policy findings on stdout plus a combined Markdown summary
written to summary.md in the project root (or --out PATH).

Usage:
    python3 src/analyze_policy.py [--policies data/policies] [--out summary.md]

Standard library only.
"""

import argparse
import json
import sys
from pathlib import Path

# Actions that are dangerous in almost any context: privilege escalation,
# identity creation, key access, destructive data-plane operations, and
# network exposure. Includes Azure-style action names for multi-cloud
# awareness.
SENSITIVE_ACTIONS = {
    "iam:passrole",
    "iam:createuser",
    "iam:createaccesskey",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "kms:decrypt",
    "kms:createdatakey",
    "s3:deletebucket",
    "s3:putbucketpolicy",
    "ec2:authorizesecuritygroupingress",
    "ec2:runinstances",
    "rds:deletesdbinstance",
    # Azure-style equivalents
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roleassignments/delete",
}

# Action-name suffixes that indicate a read-only operation.
READONLY_HINTS = ("get", "list", "describe", "read", "head")

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def as_list(value):
    """Normalize a JSON field that may be a string or a list into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def is_write_action(action: str) -> bool:
    """Heuristic: an action is a write/admin action unless it looks read-only."""
    name = action.split(":", 1)[-1].split("/")[-1].lower()
    if name == "*":
        return True
    return not any(name.startswith(h) or f"/{h}" in name for h in READONLY_HINTS)


def analyze_statement(stmt, policy_name, stmt_idx):
    """Return a list of finding dicts for one policy statement."""
    findings = []

    def add(severity, rule, detail, action=None, resource=None):
        findings.append({
            "policy": policy_name,
            "statement": stmt_idx,
            "severity": severity,
            "rule": rule,
            "action": action,
            "resource": resource,
            "detail": detail,
        })

    if str(stmt.get("Effect", "Allow")).lower() != "allow":
        return findings  # Only Allow statements grant access.

    actions = as_list(stmt.get("Action"))
    resources = as_list(stmt.get("Resource"))
    resource_is_wildcard = any(r == "*" for r in resources) or not resources

    for action in actions:
        lowered = action.lower()

        # (a) Full wildcard action
        if action == "*":
            add("Critical", "full-wildcard-action",
                "Statement allows every action in every service ('*').",
                action=action, resource=", ".join(resources) or "*")
            continue

        # (a) Service-level wildcard, e.g. "s3:*"
        if lowered.endswith(":*") or lowered.endswith("/*"):
            sev = "High"
            add(sev, "service-wildcard-action",
                f"Statement allows all actions of a service ('{action}').",
                action=action, resource=", ".join(resources) or "*")

        # (c) Sensitive actions
        if lowered in SENSITIVE_ACTIONS:
            if resource_is_wildcard:
                add("High", "sensitive-action-on-wildcard-resource",
                    f"Sensitive action '{action}' is allowed on resource '*'.",
                    action=action, resource="*")
            else:
                add("Medium", "sensitive-action",
                    f"Sensitive action '{action}' is allowed (resource-scoped).",
                    action=action, resource=", ".join(resources))

    # (b) Wildcard resource combined with any write/admin action
    if resource_is_wildcard:
        write_actions = [a for a in actions
                         if a != "*" and is_write_action(a)
                         and not a.lower().endswith(":*")]
        for action in write_actions:
            # Skip actions already reported as sensitive-on-wildcard to
            # avoid double-counting the same underlying problem.
            if action.lower() in SENSITIVE_ACTIONS:
                continue
            add("High", "write-action-on-wildcard-resource",
                f"Write/admin action '{action}' is allowed on resource '*'.",
                action=action, resource="*")

    return findings


def analyze_policy(path: Path):
    """Analyze one policy file; return (findings, error_or_None)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"could not parse {path.name}: {exc}"

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    findings = []
    for idx, stmt in enumerate(statements):
        findings.extend(analyze_statement(stmt, path.name, idx))
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings, None


def summarize(results):
    """Build a Markdown summary from {policy_name: findings}."""
    total = sum(len(f) for f in results.values())
    by_sev = {}
    for findings in results.values():
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    lines = ["# IAM Policy Analysis Summary", ""]
    lines.append(f"Policies analyzed: {len(results)}")
    lines.append(f"Total findings: {total}")
    for sev in ("Critical", "High", "Medium", "Low"):
        if sev in by_sev:
            lines.append(f"- {sev}: {by_sev[sev]}")
    lines.append("")
    lines.append("| Policy | Critical | High | Medium | Total |")
    lines.append("|---|---|---|---|---|")
    for name in sorted(results):
        counts = {s: 0 for s in ("Critical", "High", "Medium")}
        for f in results[name]:
            if f["severity"] in counts:
                counts[f["severity"]] += 1
        lines.append(
            f"| {name} | {counts['Critical']} | {counts['High']} | "
            f"{counts['Medium']} | {len(results[name])} |")
    lines.append("")
    for name in sorted(results):
        lines.append(f"## {name}")
        if not results[name]:
            lines.append("No findings.")
        for f in results[name]:
            lines.append(
                f"- **{f['severity']}** ({f['rule']}) statement "
                f"#{f['statement']}: {f['detail']}")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze cloud IAM policies "
                                                 "for least-privilege violations.")
    parser.add_argument("--policies", default=str(Path(__file__).resolve().parent.parent
                                                  / "data" / "policies"),
                        help="Directory containing policy JSON files.")
    parser.add_argument("--out", default=None,
                        help="Where to write the Markdown summary "
                             "(default: two levels above the policies "
                             "directory, i.e. the project root).")
    args = parser.parse_args(argv)

    policy_dir = Path(args.policies)
    files = sorted(policy_dir.glob("*.json"))
    if not files:
        print(f"No .json policy files found in {policy_dir}", file=sys.stderr)
        return 1

    results = {}
    for path in files:
        findings, error = analyze_policy(path)
        if error:
            print(f"ERROR: {error}", file=sys.stderr)
            continue
        results[path.name] = findings
        print(f"== {path.name}: {len(findings)} finding(s)")
        for f in findings:
            print(f"   [{f['severity']:>8}] {f['rule']}: {f['detail']}")

    out_path = Path(args.out) if args.out else policy_dir.parent.parent / "summary.md"
    out_path.write_text(summarize(results), encoding="utf-8")
    print(f"\nMarkdown summary written to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
