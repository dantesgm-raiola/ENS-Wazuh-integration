#!/usr/bin/env python3
"""Validate the ENS SCA policies against what the Wazuh 5.x agent accepts.

Checks:
  - YAML parses; policy/requirements/checks present; policy id matches file name
  - check ids are integers, unique within and across all policies given
  - every check has name/description/condition/rules, and no 4.x `title`
  - compliance is an object using only the keys the 5.x agent keeps
    (sca_policy_parser.cpp ALLOWED_COMPLIANCE_KEYS); anything else is dropped
    by the agent with a warning, and a 4.x list-style block is dropped whole
  - ENS tagging convention in references: >=1 `ens:<control>`, exactly one
    `ens-level:<basico|medio|alto>`, and the same controls/level in the name
  - rule syntax: known type prefix, `n:<regex> compare <op> <number>` shape,
    and every regex compiles (Python `re`, close enough to PCRE2 for this set)

Usage: python3 tests/validate_sca.py [sca/*.yml ...]   (default: sca/*.yml)
Exit code 1 on any error.
"""
import glob
import os
import re
import sys
import warnings as _warnings

# [[:space:]]-style classes are valid PCRE2 but make Python's re emit FutureWarning.
_warnings.simplefilter("ignore", FutureWarning)

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

ALLOWED_COMPLIANCE_KEYS = {
    "cmmc", "fedramp", "gdpr", "hipaa", "iso_27001",
    "nis2", "nist_800_171", "nist_800_53", "pci_dss", "tsc",
}
REQUIRED_CHECK_FIELDS = ("id", "name", "description", "condition", "rules")
CONDITIONS = {"all", "any", "none"}
RULE_TYPES = ("f:", "d:", "p:", "c:", "r:")
LEVELS = {"basico": "Básico", "medio": "Medio", "alto": "Alto"}
CTRL = r"(?:op|mp|org)\.[a-z]+\.\d+"
NAME_CTRLS_RE = re.compile(rf"\[({CTRL}(?:\s*,\s*{CTRL})*)\]")
NAME_LEVEL_RE = re.compile(r"\[(Básico|Medio|Alto)\]")
N_RE = re.compile(r"^n:(.+) compare (<=|>=|==|!=|<|>) (-?\d+)$")


def compile_regex(expr, where, errors):
    try:
        re.compile(expr, re.I | re.M)
    except re.error as exc:
        errors.append(f"{where}: regex does not compile ({exc}): {expr!r}")


def check_pattern(pattern, where, errors):
    """Validate the part after the first '->' of a rule."""
    for part in [p.strip() for p in pattern.split(" -> ")]:
        for piece in [x.strip() for x in part.split("&&")]:
            piece = piece[4:].strip() if piece.startswith("not ") else piece
            if piece.startswith("r:"):
                compile_regex(piece[2:], where, errors)
            elif piece.startswith("n:"):
                m = N_RE.match(piece)
                if not m:
                    errors.append(f"{where}: bad numeric rule, expected 'n:<regex> compare <op> <int>': {piece!r}")
                else:
                    compile_regex(m.group(1), where, errors)
                    if re.compile(m.group(1)).groups != 1:
                        errors.append(f"{where}: numeric rule regex must have exactly one group: {piece!r}")


def strip_not(rule):
    return rule[4:].lstrip() if rule.startswith("not ") else rule


def check_rule(rule, where, errors):
    body = strip_not(rule)
    if not body.startswith(RULE_TYPES):
        errors.append(f"{where}: unknown rule type: {rule!r}")
        return
    if " -> " in body:
        check_pattern(body.split(" -> ", 1)[1], where, errors)


def validate(path, data, seen_ids, errors, warnings):
    if not isinstance(data, dict):
        errors.append(f"{path}: not a YAML mapping")
        return
    policy = data.get("policy") or {}
    for field in ("id", "file", "name", "description"):
        if not policy.get(field):
            errors.append(f"{path}: policy.{field} missing")
    if policy.get("file") and policy["file"] != os.path.basename(path):
        errors.append(f"{path}: policy.file is {policy['file']!r}, expected {os.path.basename(path)!r}")
    req = data.get("requirements") or {}
    if "title" in req:
        warnings.append(f"{path}: requirements.title is the 4.x name; 5.x uses requirements.name")
    for i, rule in enumerate(req.get("rules") or []):
        check_rule(rule, f"{path}: requirements rule {i}", errors)

    checks = data.get("checks") or []
    if not checks:
        errors.append(f"{path}: no checks")
    for check in checks:
        cid = check.get("id")
        where = f"{path}: check {cid}"
        if not isinstance(cid, int):
            errors.append(f"{where}: id must be an integer")
        elif cid in seen_ids:
            errors.append(f"{where}: duplicate id (also in {seen_ids[cid]})")
        else:
            seen_ids[cid] = path
        if "title" in check:
            errors.append(f"{where}: uses 4.x 'title'; use 'name'")
        for field in REQUIRED_CHECK_FIELDS:
            if field not in check:
                errors.append(f"{where}: missing '{field}'")
        if check.get("condition") not in CONDITIONS:
            errors.append(f"{where}: condition must be one of {sorted(CONDITIONS)}")

        comp = check.get("compliance")
        if comp is not None:
            if not isinstance(comp, dict):
                errors.append(f"{where}: compliance must be a mapping (4.x list format is dropped by the 5.x agent)")
            else:
                bad = set(comp) - ALLOWED_COMPLIANCE_KEYS
                if bad:
                    errors.append(f"{where}: compliance keys {sorted(bad)} are dropped by the 5.x agent")
                for key, val in comp.items():
                    if not (isinstance(val, list) and all(isinstance(v, str) for v in val)):
                        errors.append(f"{where}: compliance.{key} must be a list of strings")

        refs = check.get("references") or []
        ens = sorted(r[4:] for r in refs if isinstance(r, str) and r.startswith("ens:"))
        lvls = [r[10:] for r in refs if isinstance(r, str) and r.startswith("ens-level:")]
        if not ens:
            errors.append(f"{where}: no 'ens:<control>' reference")
        if len(lvls) != 1 or lvls[0] not in LEVELS:
            errors.append(f"{where}: needs exactly one 'ens-level:' reference in {sorted(LEVELS)}")
        name = check.get("name", "")
        m_ctrl, m_lvl = NAME_CTRLS_RE.search(name), NAME_LEVEL_RE.search(name)
        name_ctrls = sorted(c.strip() for c in m_ctrl.group(1).split(",")) if m_ctrl else []
        if name_ctrls != ens:
            errors.append(f"{where}: controls in name {name_ctrls} differ from references {ens}")
        if not m_lvl or (len(lvls) == 1 and LEVELS.get(lvls[0]) != m_lvl.group(1)):
            errors.append(f"{where}: level in name does not match the ens-level reference")

        rules = check.get("rules") or []
        if not rules:
            errors.append(f"{where}: no rules")
        for i, rule in enumerate(rules):
            if not isinstance(rule, str):
                errors.append(f"{where}: rule {i} is not a string")
                continue
            check_rule(rule, f"{where} rule {i}", errors)


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = argv or sorted(glob.glob(os.path.join(root, "sca", "*.yml")))
    errors, warnings, seen = [], [], {}
    stats = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            try:
                data = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                errors.append(f"{path}: YAML error: {exc}")
                continue
        validate(path, data, seen, errors, warnings)
        checks = (data or {}).get("checks") or []
        cmd = sum(1 for c in checks if any(strip_not(r).startswith("c:") for r in c.get("rules", [])))
        stats.append(f"{os.path.basename(path)}: {len(checks)} checks, {cmd} use command rules")
    for line in stats:
        print(line)
    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")
    print("OK" if not errors else f"{len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
