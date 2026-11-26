#!/usr/bin/env python3
"""Deploy the ENS detection rules (rules/ens-*.yml) to a Wazuh 5.0 indexer.

Wazuh 5.0 keeps detection rules as Sigma-style documents in the Indexer's content-manager
plugin. This tool does, in order:

  1. create the custom integration "ens-compliance" (category system-activity) if needed;
  2. create each rule (POST) or update it (PUT) in the draft space;
  3. promote integration, rules and draft policy draft -> test -> custom;
  4. optionally (--detectors) create or update one Security Analytics detector per
     events data stream the rules read (detector_index in each rule file);
  5. write the assigned IDs back into the five state lines at the top of each rule file.

Three modes:
  --dry-run   offline: prints the requests it would send, opens no connection.
  (default)   plan: read-only queries against the indexer (existence + content diff),
              prints what would change, writes nothing.
  --apply     performs the writes.

The content-manager API has no GET endpoint. Reads go to the backing indices
(wazuh-threatintel-{rules,integrations,policies}) and the Security Analytics config index,
so the account used needs read access to them as well as content-manager write access.

Only dependency outside the standard library: PyYAML (apt install python3-yaml).
"""

import argparse
import base64
import difflib
import getpass
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: apt install python3-yaml  (or: pip install pyyaml)")

INTEGRATION_TITLE = "ens-compliance"
CM = "/_plugins/_content_manager"
SA = "/_plugins/_security_analytics"
STATE_KEYS = ("document_id", "integration_id", "space", "detector", "sa_native_id")
LOCAL_KEYS = STATE_KEYS + ("detector_index",)
RESOURCE_TYPES = ("policy", "integrations", "kvdbs", "decoders", "filters", "rules")


class DeployError(Exception):
    pass


# ── HTTP ─────────────────────────────────────────────────────────────────────

class Indexer:
    """Minimal JSON client. In dry-run mode every call is printed and nothing is sent."""

    def __init__(self, base, *, dry_run, user=None, password=None, cacert=None,
                 insecure=False, cert=None, key=None):
        self.base = base.rstrip("/")
        self.dry_run = dry_run
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if user:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.headers["Authorization"] = "Basic " + token
        if dry_run:
            self.ctx = None
            return
        if insecure:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        else:
            self.ctx = ssl.create_default_context(cafile=cacert)
        if cert:
            self.ctx.load_cert_chain(cert, key)

    def request(self, method, path, body=None, *, write=True):
        if self.dry_run:
            if write:
                print(f"  -> {method} {path}")
                if body is not None:
                    print("     " + json.dumps(body, ensure_ascii=False, indent=2).replace("\n", "\n     "))
            return None
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=self.headers)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=60) as resp:
                raw = resp.read().decode() or "{}"
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:2000]
            raise DeployError(f"{method} {path} -> HTTP {e.code}: {detail}") from None
        except urllib.error.URLError as e:
            raise DeployError(f"{method} {path} -> {e.reason}") from None
        return json.loads(raw)

    def search(self, index, query, size=10):
        res = self.request("POST", f"/{index}/_search", {"size": size, "query": query}, write=False)
        return [] if res is None else res.get("hits", {}).get("hits", [])


def created_id(res, what):
    """Content-manager create calls answer {"message": "<uuid>", "status": 201}."""
    if res is None:
        return f"<new-{what}-id>"
    msg = res.get("message")
    if res.get("status") not in (200, 201) or not isinstance(msg, str):
        raise DeployError(f"unexpected response creating {what}: {res}")
    return msg


# ── Rule files ───────────────────────────────────────────────────────────────

class RuleFile:
    def __init__(self, path):
        self.path = path
        self.text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(self.text)
        missing = [k for k in LOCAL_KEYS if k not in data]
        if missing:
            raise DeployError(f"{path.name}: missing state keys {missing}")
        self.state = {k: (data.get(k) or "") for k in STATE_KEYS}
        self.detector_index = data["detector_index"]
        self.resource = {k: v for k, v in data.items() if k not in LOCAL_KEYS}
        self.title = self.resource["metadata"]["title"]
        self.enabled = bool(self.resource.get("enabled", True))
        product = self.resource.get("logsource", {}).get("product")
        if product != INTEGRATION_TITLE:
            raise DeployError(f"{path.name}: logsource.product must be '{INTEGRATION_TITLE}'"
                              f" (the content manager checks it against the integration title)")

    def save_state(self, **changes):
        self.state.update({k: v for k, v in changes.items() if v is not None})
        text = self.text
        for key in STATE_KEYS:
            text, n = re.subn(rf'^{key}: ".*"$', f'{key}: "{self.state[key]}"', text, count=1,
                              flags=re.MULTILINE)
            if n != 1:
                raise DeployError(f"{self.path.name}: state line '{key}' not found")
        if text != self.text:
            self.path.write_text(text, encoding="utf-8")
            self.text = text


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=1).splitlines()


def project(live, local):
    """The live value restricted to the keys `local` defines, at every dict level. The server
    adds fields on its own (e.g. metadata.supports: []), which must not count as drift."""
    if isinstance(local, dict) and isinstance(live, dict):
        return {k: project(live.get(k), v) for k, v in local.items()}
    return live


def drift(local, live):
    """Diff only the keys the local file defines (the live copy carries extra server fields)."""
    live_view = project(live, local)
    return list(difflib.unified_diff(canonical(live_view), canonical(local), "live(draft)", "file",
                                     lineterm="", n=1))


# ── Steps ────────────────────────────────────────────────────────────────────

def draft_copy(ix, index, doc_id):
    hits = ix.search(index, {"bool": {"filter": [{"term": {"document.id": doc_id}},
                                                 {"term": {"space.name": "draft"}}]}}, size=1)
    return hits[0]["_source"]["document"] if hits else None


def find_by_title(ix, index, field, title):
    hits = ix.search(index, {"bool": {"filter": [{"term": {field: title}},
                                                 {"term": {"space.name": "draft"}}]}}, size=5)
    return [h["_source"]["document"]["id"] for h in hits]


def draft_policy_id(ix):
    """The draft policy's document.id, needed to promote the policy along with the integration."""
    if ix.dry_run:
        return "<draft-policy-id>"
    hits = ix.search("wazuh-threatintel-policies", {"term": {"space.name": "draft"}}, size=2)
    if len(hits) != 1:
        raise DeployError(f"expected exactly one draft policy, found {len(hits)}")
    return hits[0]["_source"]["document"]["id"]


def ensure_integration(ix, rules, args):
    ids = {r.state["integration_id"] for r in rules if r.state["integration_id"]}
    if args.integration_id:
        ids.add(args.integration_id)
    if len(ids) > 1:
        raise DeployError(f"rule files disagree on integration_id: {sorted(ids)}")
    if ids:
        return ids.pop(), False
    existing = [] if ix.dry_run else find_by_title(
        ix, "wazuh-threatintel-integrations", "document.metadata.title", INTEGRATION_TITLE)
    if existing:
        raise DeployError(f"integration '{INTEGRATION_TITLE}' already exists in draft as {existing}; "
                          f"rerun with --integration-id {existing[0]}")
    print(f"integration '{INTEGRATION_TITLE}': create")
    if not args.apply and not ix.dry_run:
        return "<new-integration-id>", True
    res = ix.request("POST", f"{CM}/integrations", {"resource": {
        "metadata": {"title": INTEGRATION_TITLE,
                     "description": "ENS (Esquema Nacional de Seguridad, RD 311/2022) detections",
                     "author": "ENS-Wazuh-integration"},
        "category": "system-activity", "enabled": True, "decoders": [], "kvdbs": []}})
    return created_id(res, "integration"), True


def upsert_rules(ix, rules, integration_id, args):
    """Returns (added_ids, updated_ids)."""
    added, updated = [], []
    for r in rules:
        body = {"integration": integration_id, "resource": r.resource}
        doc_id = r.state["document_id"]
        if not doc_id and not ix.dry_run:
            existing = find_by_title(ix, "wazuh-threatintel-rules", "document.metadata.title", r.title)
            if existing and not args.adopt:
                raise DeployError(f"{r.path.name}: a draft rule titled '{r.title}' already exists "
                                  f"({existing}); rerun with --adopt to record and update it")
            if existing:
                doc_id = existing[0]
                print(f"{r.path.name}: adopting existing draft rule {doc_id}")
                if args.apply:
                    r.save_state(document_id=doc_id, integration_id=integration_id)
        if doc_id:
            if not ix.dry_run:
                live = draft_copy(ix, "wazuh-threatintel-rules", doc_id)
                if live is None:
                    raise DeployError(f"{r.path.name}: no draft copy of {doc_id}; the content manager "
                                      f"only updates draft, recreate or fix document_id by hand")
                diff = drift(r.resource, live)
                if not diff:
                    print(f"{r.path.name}: unchanged")
                    continue
                print(f"{r.path.name}: update {doc_id}")
                print("\n".join("    " + line for line in diff))
            else:
                print(f"{r.path.name}: update {doc_id}")
            if args.apply or ix.dry_run:
                ix.request("PUT", f"{CM}/rules/{doc_id}", body)
            updated.append(doc_id)
        else:
            print(f"{r.path.name}: create")
            if not args.apply and not ix.dry_run:
                added.append(f"<new:{r.path.name}>")
                continue
            new_id = created_id(ix.request("POST", f"{CM}/rules", body), f"rule:{r.path.name}")
            if args.apply:
                r.save_state(document_id=new_id, integration_id=integration_id, space="draft")
            added.append(new_id)
    return added, updated


def promote(ix, *, integration_id, integration_new, added, updated, policy_id):
    """Promote draft -> test -> custom, one resource type per call (the confirmed path)."""
    batches = []
    if integration_new:
        batches.append(("integrations", [{"operation": "add", "id": integration_id}]))
    elif added:  # the integration's rules list changed
        batches.append(("integrations", [{"operation": "update", "id": integration_id}]))
    rule_ops = [{"operation": "add", "id": i} for i in added] + \
               [{"operation": "update", "id": i} for i in updated]
    if rule_ops:
        batches.append(("rules", rule_ops))
    if integration_new:
        batches.append(("policy", [{"operation": "update", "id": policy_id}]))
    for source in ("draft", "test"):
        for kind, ops in batches:
            changes = {t: [] for t in RESOURCE_TYPES}
            changes[kind] = ops
            print(f"promote {kind} {source} -> {'test' if source == 'draft' else 'custom'}")
            ix.request("POST", f"{CM}/promote", {"space": source, "changes": changes})


def sa_native_id(ix, doc_id):
    if ix.dry_run:
        return None
    hits = ix.search(".opensearch-sap-custom-rules-config",
                     {"bool": {"filter": [{"term": {"rule.document.id": doc_id}},
                                          {"term": {"rule.space": "custom"}}]}}, size=1)
    return hits[0]["_id"] if hits else None


def sync_detectors(ix, all_rules, args):
    by_index = {}
    for r in all_rules:
        deployed = r.state["document_id"] and r.state["space"] == "custom"
        if r.enabled and (deployed or ix.dry_run):
            by_index.setdefault(r.detector_index, []).append(r)
    for index, rules in sorted(by_index.items()):
        name = f"{INTEGRATION_TITLE}-{index.removeprefix('wazuh-events-v5-')}-detector"
        body = {
            "type": "detector", "detector_type": INTEGRATION_TITLE, "name": name, "enabled": True,
            "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
            "inputs": [{"detector_input": {
                "description": f"ENS detections over {index}",
                "indices": [index],
                "custom_rules": [{"id": r.state["document_id"] or f"<new-rule-id:{r.path.name}>"}
                                 for r in rules],
                "pre_packaged_rules": []}}],
            "triggers": [{"name": f"{name}-trigger", "severity": "3", "types": [INTEGRATION_TITLE],
                          "ids": [], "tags": [], "sev_levels": [], "actions": []}],
        }
        existing = None
        if not ix.dry_run:
            # match_phrase on detector.name returns nothing on 5.0.0 (seen 2026-11-25, which made a
            # re-run create duplicates), so list every detector and match the name here.
            res = ix.request("POST", f"{SA}/detectors/_search",
                             {"size": 1000, "query": {"match_all": {}}}, write=False)
            hits = [h for h in res.get("hits", {}).get("hits", [])
                    if h["_source"].get("name", h["_source"].get("detector", {}).get("name")) == name]
            existing = hits[0]["_id"] if hits else None
        print(f"detector {name} on {index}: {'update ' + existing if existing else 'create'} "
              f"({len(rules)} rules)")
        if not (args.apply or ix.dry_run):
            continue
        if existing:
            ix.request("PUT", f"{SA}/detectors/{existing}", body)
            det_id = existing
        else:
            res = ix.request("POST", f"{SA}/detectors", body)
            det_id = (res or {}).get("_id")
        if args.apply and det_id:
            for r in rules:
                r.save_state(detector=det_id)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--indexer", default="https://localhost:9200", help="indexer URL")
    p.add_argument("--user", help="basic-auth user (password from $ENS_INDEXER_PASSWORD or a prompt)")
    p.add_argument("--cert", help="client certificate (PEM) instead of a password")
    p.add_argument("--key", help="client certificate key (PEM)")
    p.add_argument("--cacert", help="CA bundle used to verify the indexer certificate")
    p.add_argument("--insecure", action="store_true", help="do not verify the indexer certificate")
    p.add_argument("--rules-dir", default=str(Path(__file__).resolve().parent.parent / "rules"))
    p.add_argument("--only", action="append", default=[], metavar="FILE",
                   help="deploy only this rule file (repeatable); detectors still list every deployed rule")
    p.add_argument("--include-disabled", action="store_true", help="also deploy rules with enabled: false")
    p.add_argument("--integration-id", help="use this existing ens-compliance integration")
    p.add_argument("--adopt", action="store_true",
                   help="record and update draft rules that already exist with the same title")
    p.add_argument("--detectors", action="store_true", help="create/update Security Analytics detectors")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="offline: print requests, no connection")
    mode.add_argument("--apply", action="store_true", help="perform the writes")
    args = p.parse_args()

    rules_dir = Path(args.rules_dir)
    all_rules = [RuleFile(f) for f in sorted(rules_dir.glob("ens-*.yml"))]
    if not all_rules:
        sys.exit(f"no ens-*.yml rule files in {rules_dir}")
    selected = all_rules
    if args.only:
        wanted = {Path(o).name for o in args.only}
        selected = [r for r in all_rules if r.path.name in wanted]
        unknown = wanted - {r.path.name for r in selected}
        if unknown:
            sys.exit(f"unknown rule files: {sorted(unknown)}")
    skipped = [r for r in selected if not r.enabled and not args.include_disabled]
    selected = [r for r in selected if r not in skipped]
    for r in skipped:
        print(f"{r.path.name}: skipped (enabled: false; use --include-disabled)")

    password = None
    if args.user and not args.dry_run:
        password = os.environ.get("ENS_INDEXER_PASSWORD") or getpass.getpass(f"Password for {args.user}: ")
    elif not args.cert and not args.dry_run:
        sys.exit("give --user (basic auth) or --cert/--key (client certificate)")
    if args.cert and not args.key:
        sys.exit("--cert needs --key")

    ix = Indexer(args.indexer, dry_run=args.dry_run, user=args.user, password=password,
                 cacert=args.cacert, insecure=args.insecure, cert=args.cert, key=args.key)
    print(f"mode: {'dry-run (offline)' if args.dry_run else 'APPLY' if args.apply else 'plan (read-only)'}")

    try:
        integration_id, integration_new = ensure_integration(ix, all_rules, args)
        added, updated = upsert_rules(ix, selected, integration_id, args)
        if added or updated or integration_new:
            policy_id = draft_policy_id(ix) if integration_new else None
            if args.apply or args.dry_run:
                promote(ix, integration_id=integration_id, integration_new=integration_new,
                        added=added, updated=updated, policy_id=policy_id)
            else:
                print(f"would promote: integration={'add' if integration_new else '-'} "
                      f"rules add={len(added)} update={len(updated)}")
        if args.apply:
            for r in selected:
                if r.state["document_id"] in added + updated:
                    r.save_state(space="custom", sa_native_id=sa_native_id(ix, r.state["document_id"]))
        if args.detectors:
            sync_detectors(ix, all_rules, args)
    except DeployError as e:
        sys.exit(f"error: {e}")
    if not args.apply:
        print("nothing written" + ("" if args.dry_run else "; rerun with --apply to deploy"))


if __name__ == "__main__":
    main()
