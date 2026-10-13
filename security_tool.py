"""Shared validation, findings, suppressions and reporting for defensive tools."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return result.astimezone(timezone.utc)


def object_value(value, label="input"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(data, key, required=()):
    object_value(data)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be an array")
    for index, row in enumerate(rows):
        object_value(row, f"{key}[{index}]")
        if any(field not in row for field in required):
            raise ValueError(f"{key}[{index}] is missing required fields: {', '.join(required)}")
    return rows


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def number(value, label, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside the permitted range")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return value


def setting(policy, key, default, minimum=0, maximum=None):
    return number(policy.get(key, default), f"policy.{key}", minimum, maximum)


def finding(rule, severity, resource, title, evidence, remediation, **extra):
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity")
    resource = str(resource)
    stable = json.dumps([TOOL, rule, resource, extra.get("subject", "")], ensure_ascii=False)
    result = {"rule": rule, "severity": severity, "resource": resource,
              "title": title, "evidence": evidence, "remediation": remediation,
              "fingerprint": hashlib.sha256(stable.encode()).hexdigest()[:24]}
    result.update(extra)
    return result


def unique_rows(rows, key):
    result = {}
    for row in rows:
        identifier = text(row[key], key)
        if identifier in result:
            raise ValueError(f"duplicate {key} in inventory")
        result[identifier] = row
    return result


def decode_json(content):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains a duplicate key")
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def load_json(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 10 MiB limit")
    return decode_json(path.read_text(encoding="utf-8-sig"))


def build_report(findings, suppressions=(), now=None):
    now = now or datetime.now(timezone.utc)
    active, suppressed = [], []
    fingerprints = set()
    for suppression in suppressions:
        object_value(suppression, "suppression")
        text(suppression.get("fingerprint"), "suppression fingerprint")
        text(suppression.get("reason"), "suppression reason")
        timestamp(suppression.get("expires"))
        if suppression["fingerprint"] in fingerprints:
            raise ValueError("duplicate suppression fingerprint")
        fingerprints.add(suppression["fingerprint"])
    known = {item["fingerprint"]: item for item in suppressions
             if timestamp(item["expires"]) > now}
    for item in findings:
        if item["fingerprint"] in known:
            suppressed.append({**item, "suppression_reason": known[item["fingerprint"]]["reason"]})
        else:
            active.append(item)
    active.sort(key=lambda item: (-SEVERITIES[item["severity"]], item["resource"], item["rule"], item["fingerprint"]))
    return {"tool": TOOL, "version": VERSION, "generated_at": now.isoformat(),
            "summary": dict(Counter(item["severity"] for item in active)),
            "findings": active, "suppressed": suppressed}


def sarif(report):
    rules = {item["rule"]: item["title"] for item in report["findings"]}
    results = []
    for item in report["findings"]:
        results.append({"ruleId": item["rule"],
                        "level": "error" if SEVERITIES[item["severity"]] >= 3 else "warning" if SEVERITIES[item["severity"]] >= 1 else "note",
                        "message": {"text": item["title"] + ". " + item["remediation"]},
                        "locations": [{"logicalLocations": [{"name": item["resource"]}]}],
                        "partialFingerprints": {"securityToolFingerprint/v1": item["fingerprint"]},
                        "properties": {"severity": item["severity"], "evidence": item["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION,
                       "rules": [{"id": key, "shortDescription": {"text": title}} for key, title in sorted(rules.items())]}},
                       "results": results}]}


def markdown(report):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = [f"# {TOOL} report", "", f"Version: {VERSION}. Findings: {len(report['findings'])}.", "",
             "| Severity | Resource | Finding | Recommended action |", "|---|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(escape(item[key]) for key in ("severity", "resource", "title", "remediation")) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("input", nargs="?", type=Path, help="JSON inventory, event export or tool configuration")
    parser.add_argument("--demo", action="store_true", help="run the embedded synthetic example")
    parser.add_argument("--policy", type=Path, help="JSON object overriding documented defaults")
    parser.add_argument("--suppressions", type=Path, help="JSON array: fingerprint, reason, expires")
    parser.add_argument("--format", choices=["json", "sarif", "markdown"], default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=list(SEVERITIES), default="high")
    parser.add_argument("--now", help="timezone-aware ISO timestamp for reproducible reviews")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.demo == bool(args.input):
        parser.error("provide exactly one of input or --demo")
    try:
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        data = object_value(json.loads(json.dumps(DEMO)) if args.demo else load_json(args.input))
        policy = object_value(load_json(args.policy), "policy") if args.policy else {}
        suppressions = load_json(args.suppressions) if args.suppressions else []
        if not isinstance(suppressions, list):
            raise ValueError("suppressions must be an array")
        report = build_report(audit(data, policy, now), suppressions, now)
        content = markdown(report) if args.format == "markdown" else json.dumps(sarif(report) if args.format == "sarif" else report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            # Exclusive creation keeps earlier evidence from being overwritten.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return int(any(SEVERITIES[item["severity"]] >= SEVERITIES[args.fail_on] for item in report["findings"]))
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {type(exc).__name__}: {exc}\n")
TOOL = "cloud-iam-policy-auditor"
DESCRIPTION = "Statically review AWS-style IAM policy documents for broad grants and risky delegation."
DEMO = {"policies": [{"id": "synthetic-deployment-role", "document": {"Version": "2012-10-17", "Statement": [
    {"Sid": "WideAdmin", "Effect": "Allow", "Action": "*", "Resource": "*"},
    {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example/*"}]}}]}


def values(value, label):
    return [value] if isinstance(value, str) and value else string_list(value, label)


def audit(data, policy, now):
    result = []
    risky = string_list(policy.get("delegation_actions", ["iam:PassRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "sts:AssumeRole"]), "delegation_actions")
    policies = unique_rows(records(data, "policies", ("id", "document")), "id")
    for identifier, row in policies.items():
        document = object_value(row["document"], "policy.document")
        statements = document.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            raise ValueError("Statement must be an object or array")
        for index, statement in enumerate(statements):
            object_value(statement, "Statement")
            effect = statement.get("Effect")
            if effect not in {"Allow", "Deny"}:
                raise ValueError("Statement requires Allow or Deny Effect")
            if ("Action" in statement) == ("NotAction" in statement):
                raise ValueError("provide exactly one of Action or NotAction")
            actions = values(statement.get("Action", statement.get("NotAction")), "Action")
            if ("Resource" in statement) == ("NotResource" in statement):
                raise ValueError("provide exactly one of Resource or NotResource")
            resources = values(statement.get("Resource", statement.get("NotResource")), "Resource")
            conditions = object_value(statement.get("Condition", {}), "Condition")
            if effect == "Deny":
                continue
            resource = identifier + ":" + str(statement.get("Sid", index))
            conditional = bool(conditions)
            evidence = {"actions": actions, "resource_patterns": resources, "conditional": conditional}
            unrestricted = "*" in resources or "NotResource" in statement
            if "NotAction" in statement:
                result.append(finding("IAM-NOTACTION-ALLOW", "high", resource, "Allow statement uses action exclusions",
                                      evidence, "Replace broad exclusions with reviewed, explicit allowed actions."))
            elif "*" in actions and unrestricted:
                result.append(finding("IAM-ADMIN-WILDCARD", "high" if conditional else "critical", resource,
                                      "All-action grant over broad resources", evidence,
                                      "Narrow actions and resources; review conditions and applicable denies."))
            elif any("*" in action or "?" in action for action in actions):
                result.append(finding("IAM-ACTION-WILDCARD", "medium", resource, "Wildcard action grant",
                                      evidence, "Review wildcard expansion and constrain actions to the required operations."))
            delegated = sorted({risk for risk in risky if any(fnmatch.fnmatchcase(risk.lower(), action.lower()) for action in actions)})
            if delegated and unrestricted:
                result.append(finding("IAM-BROAD-DELEGATION", "high", resource, "Broad role or policy delegation",
                                      {"matched_actions": delegated, "conditional": conditional},
                                      "Scope delegated roles and policy changes to reviewed resources and conditions."))
            principal = statement.get("Principal", {})
            public = principal == "*" or (isinstance(principal, dict) and any("*" in values(value, "Principal") for value in principal.values()))
            if public:
                result.append(finding("IAM-PUBLIC-PRINCIPAL", "high" if conditional else "critical", resource,
                                      "Policy grants access to a wildcard principal", {"conditional": conditional},
                                      "Review the public grant and constrain principals and contextual conditions."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
