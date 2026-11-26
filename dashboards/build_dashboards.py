#!/usr/bin/env python3
"""
Generate the Wazuh 5.x ENS dashboards as OpenSearch Dashboards saved objects (ndjson).

    python3 dashboards/build_dashboards.py          # writes both ndjson files next to this script
    python3 dashboards/build_dashboards.py --check  # regenerate in memory, validate, fail if files differ

Stdlib only. Everything is generated from the tables below, so a change to a panel
is a reviewable diff here, not a hand-edited JSON blob.

Data sources (Wazuh 5.0):
  * wazuh-states-sca*    SCA state, one document per (agent, policy, check). No time field.
                         check.result is exactly "Passed" | "Failed" | "Not applicable".
  * wazuh-findings-v5-*  Detection findings from Security Analytics detectors.

ENS tagging conventions these dashboards depend on (set by sca/*.yml and rules/*.yml):
  * SCA checks:  check.references contains  "ens:<control>"        e.g. "ens:op.acc.6"
                                            "ens-level:<level>"    basico | medio | alto
                                            "iso27001-2022:<ctrl>" e.g. "iso27001-2022:8.5"
  * Rules:       wazuh.rule.tags contains   "ens.<control>"        e.g. "ens.op.acc.6"
                                            "iso27001-2022.<ctrl>"
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

SCA_PATTERN_ID = "ens-5x-states-sca"
FINDINGS_PATTERN_ID = "ens-5x-findings"

ENS_POLICY_QUERY = "policy.id: (ens_linux or ens_windows)"
ENS_FINDINGS_QUERY = "wazuh.rule.tags: ens.*"
# Compliance % excludes checks that could not be evaluated.
EVALUATED_QUERY = ENS_POLICY_QUERY + ' and check.result: ("Passed" or "Failed")'


# ── saved-object builders ────────────────────────────────────────────────────

def _js(obj):
    return json.dumps(obj, ensure_ascii=False)


def index_pattern(obj_id, title, time_field=None):
    attrs = {"title": title, "fields": "[]"}
    if time_field:
        attrs["timeFieldName"] = time_field
    return {"type": "index-pattern", "id": obj_id, "attributes": attrs, "references": []}


def _search_source(query, index_id=None):
    src = {"query": {"query": query, "language": "kuery"}, "filter": []}
    refs = []
    if index_id:
        src["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
        refs.append({"name": src["indexRefName"], "type": "index-pattern", "id": index_id})
    return {"searchSourceJSON": _js(src)}, refs


def visualization(obj_id, title, description, vis_type, params, aggs, index_id, query=""):
    meta, refs = _search_source(query, index_id)
    vis_state = {"title": title, "type": vis_type, "params": params, "aggs": aggs}
    return {
        "type": "visualization",
        "id": obj_id,
        "attributes": {
            "title": title,
            "description": description,
            "visState": _js(vis_state),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": meta,
        },
        "references": refs,
    }


def saved_search(obj_id, title, description, columns, index_id, query, sort):
    meta, refs = _search_source(query, index_id)
    return {
        "type": "search",
        "id": obj_id,
        "attributes": {
            "title": title,
            "description": description,
            "hits": 0,
            "columns": columns,
            "sort": sort,
            "version": 1,
            "kibanaSavedObjectMeta": meta,
        },
        "references": refs,
    }


def policy_control(obj_id, title, index_id, field="policy.id", label="SCA policy"):
    params = {
        "controls": [{
            "id": "1",
            "fieldName": field,
            "parent": "",
            "label": label,
            "type": "list",
            "options": {"type": "terms", "multiselect": True, "dynamicOptions": True,
                        "size": 10, "order": "desc"},
            "indexPatternRefName": "control_0_index_pattern",
        }],
        "updateFiltersOnChange": True,
        "useTimeFilter": False,
        "pinFilters": False,
    }
    vis_state = {"title": title, "type": "input_control_vis", "params": params, "aggs": []}
    meta, _ = _search_source("")
    return {
        "type": "visualization",
        "id": obj_id,
        "attributes": {
            "title": title,
            "description": "Filter the whole dashboard by " + field,
            "visState": _js(vis_state),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": meta,
        },
        "references": [{"name": "control_0_index_pattern", "type": "index-pattern", "id": index_id}],
    }


def dashboard(obj_id, title, description, panels, query=""):
    """panels: list of (object, x, y, w, h)."""
    panels_json, refs = [], []
    for n, (obj, x, y, w, h) in enumerate(panels, start=1):
        ref_name = "panel_%d" % n
        panels_json.append({
            "version": "2.0.0",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(n)},
            "panelIndex": str(n),
            "embeddableConfig": {},
            "panelRefName": ref_name,
        })
        refs.append({"name": ref_name, "type": obj["type"], "id": obj["id"]})
    meta, _ = _search_source(query)
    return {
        "type": "dashboard",
        "id": obj_id,
        "attributes": {
            "title": title,
            "description": description,
            "panelsJSON": _js(panels_json),
            "optionsJSON": _js({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": meta,
        },
        "references": refs,
    }


# ── vis param presets ────────────────────────────────────────────────────────

def count(agg_id="1", label=None):
    return {"id": agg_id, "enabled": True, "type": "count", "schema": "metric",
            "params": {"customLabel": label} if label else {}}


def unique(field, agg_id, label):
    return {"id": agg_id, "enabled": True, "type": "cardinality", "schema": "metric",
            "params": {"field": field, "customLabel": label}}


def terms(field, agg_id, schema, size, label, include=None, order_by="1", order="desc"):
    params = {"field": field, "size": size, "order": order, "orderBy": order_by,
              "otherBucket": False, "missingBucket": False, "customLabel": label}
    if include:
        params["include"] = include
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema, "params": params}


PIE = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
       "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}

TABLE = {"perPage": 25, "showPartialRows": False, "showMetricsAtAllLevels": False,
         "sort": {"columnIndex": None, "direction": None}, "showTotal": False, "totalFunc": "sum"}


def metric_params(font=48):
    return {"addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                       "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                       "labels": {"show": True}, "invertColors": False,
                       "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                 "subText": "", "fontSize": font}}}


def hbar_percent(value_title):
    return {"type": "histogram", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                              "show": True, "scale": {"type": "linear"},
                              "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 150},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1", "type": "value",
                           "position": "bottom", "show": True,
                           "scale": {"type": "linear", "mode": "percentage"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": value_title}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Checks", "id": "1"}, "valueAxis": "ValueAxis-1"}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
            "addTimeMarker": False, "orderBucketsBySum": False}


def hbar_count(value_title):
    p = hbar_percent(value_title)
    p["valueAxes"][0]["scale"]["mode"] = "normal"
    return p


def line_params(value_title):
    return {"type": "line", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                              "show": True, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                           "position": "left", "show": True,
                           "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": value_title}}],
            "seriesParams": [{"show": True, "type": "line", "mode": "normal",
                              "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "lineWidth": 2,
                              "interpolate": "linear", "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
            "addTimeMarker": False,
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}


RESULT_FILTERS = {"id": "2", "enabled": True, "type": "filters", "schema": "group",
                  "params": {"filters": [
                      {"input": {"query": 'check.result: "Passed"', "language": "kuery"}, "label": "Passed"},
                      {"input": {"query": 'check.result: "Failed"', "language": "kuery"}, "label": "Failed"},
                      {"input": {"query": 'check.result: "Not applicable"', "language": "kuery"},
                       "label": "Not applicable"}]}}


# ── SCA compliance dashboard ─────────────────────────────────────────────────

def build_sca():
    ip = index_pattern(SCA_PATTERN_ID, "wazuh-states-sca*")
    P = SCA_PATTERN_ID

    control = policy_control("ens-5x-sca-policy-control", "ENS SCA — Policy filter", P)

    totals = visualization(
        "ens-5x-sca-result-counts", "ENS SCA — Check results",
        "Number of ENS check results (one per agent and check) by outcome.",
        "metric", metric_params(40), [count("1", "Checks"), RESULT_FILTERS], P, ENS_POLICY_QUERY)

    donut = visualization(
        "ens-5x-sca-result-donut", "ENS SCA — Result distribution",
        "Passed / Failed / Not applicable across all ENS checks on all agents.",
        "pie", PIE, [count(), terms("check.result", "2", "segment", 5, "Result")], P, ENS_POLICY_QUERY)

    pct_policy = visualization(
        "ens-5x-sca-compliance-pct", "ENS SCA — Compliance % by policy",
        "Share of evaluated checks that passed, per ENS policy. Not applicable results are excluded.",
        "horizontal_bar", hbar_percent("Compliance (%)"),
        [count("1", "Checks"), terms("policy.id", "2", "segment", 5, "Policy", order_by="_key", order="asc"),
         terms("check.result", "3", "group", 2, "Result")], P, EVALUATED_QUERY)

    agents = visualization(
        "ens-5x-sca-agent-count", "ENS SCA — Agents assessed",
        "Distinct agents that reported ENS SCA results, and when results last changed.",
        "metric", metric_params(40),
        [unique("wazuh.agent.id", "1", "Agents"),
         {"id": "2", "enabled": True, "type": "max", "schema": "metric",
          "params": {"field": "state.modified_at", "customLabel": "Last result change"}}],
        P, ENS_POLICY_QUERY)

    pct_level = visualization(
        "ens-5x-sca-compliance-by-level", "ENS SCA — Compliance % by ENS level",
        "Share of evaluated checks passing per ENS level (Básico / Medio / Alto), from the "
        "'ens-level:*' entries in check.references.",
        "horizontal_bar", hbar_percent("Compliance (%)"),
        [count("1", "Checks"),
         terms("check.references", "2", "segment", 5, "ENS level", include="ens-level:.*",
               order_by="_key", order="asc"),
         terms("check.result", "3", "group", 2, "Result")], P, EVALUATED_QUERY)

    pct_control = visualization(
        "ens-5x-sca-compliance-by-control", "ENS SCA — Compliance % by ENS control",
        "Share of evaluated checks passing per ENS control, from the 'ens:*' entries in check.references.",
        "horizontal_bar", hbar_percent("Compliance (%)"),
        [count("1", "Checks"),
         terms("check.references", "2", "segment", 50, "ENS control", include="ens:.*",
               order_by="_key", order="asc"),
         terms("check.result", "3", "group", 2, "Result")], P, EVALUATED_QUERY)

    control_table = visualization(
        "ens-5x-sca-control-table", "ENS SCA — Results by ENS control",
        "ENS control × result: number of check results and distinct agents affected.",
        "table", TABLE,
        [count("1", "Checks"), unique("wazuh.agent.id", "2", "Agents"),
         terms("check.references", "3", "bucket", 50, "ENS control", include="ens:.*",
               order_by="_key", order="asc"),
         terms("check.result", "4", "bucket", 3, "Result")], P, ENS_POLICY_QUERY)

    agent_pct = visualization(
        "ens-5x-sca-compliance-by-agent", "ENS SCA — Compliance % by agent",
        "Share of evaluated checks passing per agent (agents ordered by number of results).",
        "horizontal_bar", hbar_percent("Compliance (%)"),
        [count("1", "Checks"), terms("wazuh.agent.name", "2", "segment", 50, "Agent"),
         terms("check.result", "3", "group", 2, "Result")], P, EVALUATED_QUERY)

    agent_table = visualization(
        "ens-5x-sca-agent-table", "ENS SCA — Results by agent",
        "Agent × policy × result counts.",
        "table", TABLE,
        [count("1", "Checks"),
         terms("wazuh.agent.name", "2", "bucket", 100, "Agent", order_by="_key", order="asc"),
         terms("policy.id", "3", "bucket", 5, "Policy"),
         terms("check.result", "4", "bucket", 3, "Result")], P, ENS_POLICY_QUERY)

    agent_control_table = visualization(
        "ens-5x-sca-agent-control-failed", "ENS SCA — Failed checks by agent and ENS control",
        "Where each agent fails: agent × ENS control, failed results only.",
        "table", TABLE,
        [count("1", "Failed checks"),
         terms("wazuh.agent.name", "2", "bucket", 100, "Agent"),
         terms("check.references", "3", "bucket", 50, "ENS control", include="ens:.*",
               order_by="_key", order="asc")],
        P, ENS_POLICY_QUERY + ' and check.result: "Failed"')

    top_failing = visualization(
        "ens-5x-sca-top-failing", "ENS SCA — Most failed checks",
        "Checks failing on the most agents.",
        "table", TABLE,
        [unique("wazuh.agent.id", "1", "Agents failing"),
         terms("check.id", "2", "bucket", 30, "Check ID"),
         terms("check.name", "3", "bucket", 1, "Check")],
        P, ENS_POLICY_QUERY + ' and check.result: "Failed"')

    failed_search = saved_search(
        "ens-5x-sca-failed-search", "ENS SCA — Failed checks",
        "Every failed ENS check result, with the reason the agent reported.",
        ["wazuh.agent.name", "policy.id", "check.id", "check.name", "check.reason"],
        P, ENS_POLICY_QUERY + ' and check.result: "Failed"', [])

    na_search = saved_search(
        "ens-5x-sca-na-search", "ENS SCA — Not applicable checks",
        "Checks the agent could not evaluate. 'Remote commands are disabled for this policy' "
        "means sca.remote_commands=1 is missing on that agent.",
        ["wazuh.agent.name", "policy.id", "check.id", "check.name", "check.reason"],
        P, ENS_POLICY_QUERY + ' and check.result: "Not applicable"', [])

    dash = dashboard(
        "ens-5x-sca-dashboard", "ENS — SCA compliance (Wazuh 5.x)",
        "ENS (RD 311/2022) configuration compliance from the ens_linux and ens_windows SCA policies, "
        "read from wazuh-states-sca. Per-control and per-level panels rely on the 'ens:' and "
        "'ens-level:' entries in check.references. State index: the time picker has no effect.",
        [
            (control, 0, 0, 12, 6),
            (totals, 12, 0, 24, 6),
            (agents, 36, 0, 12, 6),
            (donut, 0, 6, 16, 12),
            (pct_policy, 16, 6, 16, 12),
            (pct_level, 32, 6, 16, 12),
            (pct_control, 0, 18, 24, 20),
            (control_table, 24, 18, 24, 20),
            (agent_pct, 0, 38, 24, 16),
            (agent_table, 24, 38, 24, 16),
            (agent_control_table, 0, 54, 24, 16),
            (top_failing, 24, 54, 24, 16),
            (failed_search, 0, 70, 48, 16),
            (na_search, 0, 86, 48, 12),
        ],
        ENS_POLICY_QUERY,
    )
    return [ip, control, totals, donut, pct_policy, agents, pct_level, pct_control, control_table,
            agent_pct, agent_table, agent_control_table, top_failing, failed_search, na_search, dash]


# ── detections (findings) dashboard ──────────────────────────────────────────

def build_findings():
    ip = index_pattern(FINDINGS_PATTERN_ID, "wazuh-findings-v5-*", "@timestamp")
    P = FINDINGS_PATTERN_ID
    Q = ENS_FINDINGS_QUERY

    total = visualization(
        "ens-5x-det-total", "ENS detections — Findings",
        "Findings from ENS-tagged rules in the selected time range, and distinct agents.",
        "metric", metric_params(40), [count("1", "Findings"), unique("wazuh.agent.id", "2", "Agents")], P, Q)

    over_time = visualization(
        "ens-5x-det-over-time", "ENS detections — Findings over time",
        "ENS findings per interval, split by rule level.",
        "line", line_params("Findings"),
        [count(),
         {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
          "params": {"field": "@timestamp", "useNormalizedOpenSearchInterval": True, "interval": "auto",
                     "drop_partials": False, "min_doc_count": 1, "extended_bounds": {},
                     "customLabel": "Time"}},
         terms("wazuh.rule.level", "3", "group", 5, "Level")], P, Q)

    by_level = visualization(
        "ens-5x-det-by-level", "ENS detections — By level",
        "ENS findings by rule level.",
        "pie", PIE, [count(), terms("wazuh.rule.level", "2", "segment", 5, "Level")], P, Q)

    by_control = visualization(
        "ens-5x-det-by-control", "ENS detections — By ENS control",
        "ENS findings per ENS control, from the 'ens.*' entries in wazuh.rule.tags.",
        "horizontal_bar", hbar_count("Findings"),
        [count("1", "Findings"),
         terms("wazuh.rule.tags", "2", "segment", 40, "ENS control", include="ens\\..*")], P, Q)

    by_agent = visualization(
        "ens-5x-det-by-agent", "ENS detections — By agent",
        "Agents with the most ENS findings, and which ENS controls they hit.",
        "table", TABLE,
        [count("1", "Findings"),
         terms("wazuh.agent.name", "2", "bucket", 30, "Agent"),
         terms("wazuh.rule.tags", "3", "bucket", 10, "ENS control", include="ens\\..*")], P, Q)

    top_rules = visualization(
        "ens-5x-det-top-rules", "ENS detections — Top rules",
        "ENS rules producing the most findings.",
        "table", TABLE,
        [count("1", "Findings"), unique("wazuh.agent.id", "2", "Agents"),
         terms("wazuh.rule.title", "3", "bucket", 30, "Rule"),
         terms("wazuh.rule.level", "4", "bucket", 1, "Level")], P, Q)

    recent = saved_search(
        "ens-5x-det-recent-search", "ENS detections — Recent findings",
        "Most recent ENS findings.",
        ["wazuh.agent.name", "wazuh.rule.title", "wazuh.rule.level", "wazuh.rule.tags"],
        P, Q, [["@timestamp", "desc"]])

    dash = dashboard(
        "ens-5x-detections-dashboard", "ENS — Detections (Wazuh 5.x)",
        "Findings from ENS-tagged detection rules (wazuh.rule.tags: ens.*) in wazuh-findings-v5-*. "
        "Empty until the ENS rules are deployed and wired into a detector.",
        [
            (total, 0, 0, 12, 10),
            (over_time, 12, 0, 36, 10),
            (by_level, 0, 10, 16, 14),
            (by_control, 16, 10, 32, 14),
            (by_agent, 0, 24, 24, 16),
            (top_rules, 24, 24, 24, 16),
            (recent, 0, 40, 48, 16),
        ],
        Q,
    )
    return [ip, total, over_time, by_level, by_control, by_agent, top_rules, recent, dash]


# ── validation and output ────────────────────────────────────────────────────

def validate(objects):
    errors = []
    ids = [(o["type"], o["id"]) for o in objects]
    if len(ids) != len(set(ids)):
        errors.append("duplicate saved-object ids")
    known = set(ids)
    for o in objects:
        a = o["attributes"]
        for key in ("visState", "uiStateJSON", "panelsJSON", "optionsJSON", "fields"):
            if key in a:
                try:
                    json.loads(a[key])
                except ValueError as exc:
                    errors.append("%s: %s is not valid JSON (%s)" % (o["id"], key, exc))
        meta = a.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON")
        if meta is not None:
            src = json.loads(meta)
            names = {r["name"] for r in o["references"]}
            if "indexRefName" in src and src["indexRefName"] not in names:
                errors.append("%s: indexRefName has no matching reference" % o["id"])
        for r in o["references"]:
            if (r["type"], r["id"]) not in known:
                errors.append("%s: reference %s/%s not in file" % (o["id"], r["type"], r["id"]))
        if o["type"] == "dashboard":
            seen = set()
            refnames = {r["name"] for r in o["references"]}
            for p in json.loads(a["panelsJSON"]):
                g = p["gridData"]
                if g["x"] < 0 or g["x"] + g["w"] > 48:
                    errors.append("%s: panel %s exceeds 48 columns" % (o["id"], p["panelIndex"]))
                if p["panelIndex"] in seen:
                    errors.append("%s: duplicate panelIndex %s" % (o["id"], p["panelIndex"]))
                seen.add(p["panelIndex"])
                if p["panelRefName"] not in refnames:
                    errors.append("%s: panelRefName %s unresolved" % (o["id"], p["panelRefName"]))
    return errors


def render(objects):
    return "".join(json.dumps(o, ensure_ascii=False, sort_keys=True) + "\n" for o in objects)


OUTPUTS = {
    "ens_sca_compliance_5x.ndjson": build_sca,
    "ens_detections_5x.ndjson": build_findings,
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="validate and compare with the files on disk without writing")
    args = ap.parse_args()

    status = 0
    for name, builder in OUTPUTS.items():
        objects = builder()
        errors = validate(objects)
        for e in errors:
            print("ERROR %s: %s" % (name, e), file=sys.stderr)
        if errors:
            status = 1
            continue
        text = render(objects)
        path = os.path.join(HERE, name)
        if args.check:
            current = open(path, encoding="utf-8").read() if os.path.exists(path) else None
            if current != text:
                print("%s is out of date; run without --check" % name, file=sys.stderr)
                status = 1
            else:
                print("ok  %s (%d objects)" % (name, len(objects)))
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            print("wrote %s (%d objects)" % (name, len(objects)))
    return status


if __name__ == "__main__":
    sys.exit(main())
