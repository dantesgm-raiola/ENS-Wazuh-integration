# ENS detection rules on Wazuh 5.0

Wazuh 5.0 dropped the XML ruleset. Detection rules are now Sigma-style YAML documents stored in
the Indexer's content-manager plugin. Security Analytics *detectors* evaluate them against events
that are already indexed, and every match is written to `wazuh-findings-v5-<category>` as a
*finding*. Rules can't chain (`if_sid`), can't count events over time (`frequency`/`timeframe`),
and can only use fields from the Wazuh Common Schema (WCS).

`rules/ens_detection_rules.xml` (25 rules) is replaced by 15 files `rules/ens-*.yml`. Each one was
rebuilt from the real fields its events carry, not from the 4.x parent rule IDs. Most of those parent
IDs were wrong (see the last column).

> **Status: deployed on a production Wazuh 5.0.0 indexer on 2026-11-25** with
> `deploy_rules.py --apply --detectors`. The content manager accepted all 14 enabled rules on the
> first run (no validation errors), and they were promoted draft → test → custom. Both
> detectors were created. The `PUT /rules/{id}` + promote `update` path was also exercised and works with the
> `{"integration", "resource"}` body. The field values below come from read-only queries against
> that indexer (90-day window, 2026-08-27 → 2026-11-25). `ens-op-acc-6-authentication-failure`
> is still `enabled: false` and was not deployed.

## Conventions

| Item | Value |
|---|---|
| Integration | `ens-compliance` (custom, category `system-activity`, no decoders) |
| `logsource.product` | `ens-compliance`. The content manager rejects a rule whose product doesn't match its integration's title. |
| ENS control | tag `ens.<control>`, e.g. `ens.op.acc.6`; also the prefix of `metadata.title` (`ENS op.acc.6: …`) |
| ISO/IEC 27001:2022 | tag `iso27001-2022.<control>`, e.g. `iso27001-2022.8.5` (from [iso27001_mapping.md](iso27001_mapping.md)) |
| `compliance` | Only the 10 keys the 5.0 schema allows. Only `nis2` (Art. 21.2 letters) is used. ISO 2022 numbers are **not** put in `iso_27001`, because Wazuh's own content fills that key with 2013 numbering (`A.9.2.1`). |
| Titles | Static, no `{{ field }}` placeholders, so dashboards can aggregate by `wazuh.rule.title` |
| State header | The first 5 keys (`document_id`, `integration_id`, `space`, `detector`, `sa_native_id`) record what is deployed, written back by `deploy_rules.py`. `detector_index` picks the detector. Neither is sent to the API. |

## Old rule → new rule

Counts are matching events in the 90-day window on the reference deployment.

| 4.x rule | 4.x said | 4.x actually hooked | 5.0 | Matches (90 d) |
|---|---|---|---|---|
| 100200 | SSH auth failure | 5501 PAM session opened (and cron sessions via 5521) | [`ens-op-acc-6-authentication-failure.yml`](../rules/ens-op-acc-6-authentication-failure.yml): sshd failures + Windows 4625. **`enabled: false`** (volume) | 581,047 / 24 agents |
| 100201 | SSH auth success | 5715 ✓ | [`ens-op-acc-1-ssh-session-opened.yml`](../rules/ens-op-acc-1-ssh-session-opened.yml) | 2,408 / 3 |
| 100202 | SSH reverse mapping failed | 5712 brute force | dropped: correlation, and reverse-mapping lines aren't decoded | — |
| 100203 | SSH insecure connection | 5710 non-existent user | dropped: covered by the auth-failure rule | — |
| 100210 | password change | 5551–5553 PAM | [`ens-op-acc-2-password-changed-or-reset.yml`](../rules/ens-op-acc-2-password-changed-or-reset.yml): Windows 4723/4724 | 20 / 8 |
| 100220 | sudo success | 5401, which is the **failure** rule | [`ens-op-acc-3-sudo-command-executed.yml`](../rules/ens-op-acc-3-sudo-command-executed.yml) | 519 / 7 |
| 100221 | sudo failure | 5402, which is the **success** rule | [`ens-op-acc-3-sudo-authentication-failure.yml`](../rules/ens-op-acc-3-sudo-authentication-failure.yml) | 17 / 3 |
| 100230 | user created | 5901 new group | [`ens-op-acc-4-user-account-created.yml`](../rules/ens-op-acc-4-user-account-created.yml) | 15 / 3 |
| 100231 | user deleted | 5902 new user | [`ens-op-acc-4-user-account-deleted.yml`](../rules/ens-op-acc-4-user-account-deleted.yml) | 14 / 3 |
| 100232 | user modified | 5903 user deleted | [`ens-op-acc-4-user-account-modified.yml`](../rules/ens-op-acc-4-user-account-modified.yml) | 466 / 14 |
| 100233 | added to privileged group | 5905 useradd failed (level 0 → 9) | [`ens-op-acc-4-user-added-to-privileged-group.yml`](../rules/ens-op-acc-4-user-added-to-privileged-group.yml) | 194 / 5 |
| 100300 | FIM checksum changed | 550 ✓ | dropped: every FIM change (~140k/30 d) would become a finding. FIM events are already indexed. | — |
| 100301 | FIM file added | 554 ✓ | dropped, same reason | — |
| 100302 | critical file modified | 550 + match ✓ | [`ens-op-exp-3-critical-system-file-changed.yml`](../rules/ens-op-exp-3-critical-system-file-changed.yml) | 2 / 1 |
| 100310 | rootkit/malware | 510 = every rootcheck event | [`ens-op-exp-6-rootkit-hidden-process-or-port.yml`](../rules/ens-op-exp-6-rootkit-hidden-process-or-port.yml) | 1,213 / 19 |
| 100320 | brute force | 40101 system user logged in | gap (correlation). Partial: [`ens-op-acc-6-account-locked-out.yml`](../rules/ens-op-acc-6-account-locked-out.yml), Windows 4740 | 73 / 12 |
| 100321 | failures from many sources | 40111 | gap (correlation) | — |
| 100330 | audit event recorded | 80700–80703 (lowered daemon-end 10 → 3) | dropped: generic, and was harmful | — |
| 100331 | auditd stopped | 80711 | [`ens-op-exp-8-audit-daemon-stopped.yml`](../rules/ens-op-exp-8-audit-daemon-stopped.yml) | 1 / 1 |
| 100340 | log file deleted | 591/592 + `/var/log` | [`ens-op-exp-10-windows-event-log-cleared.yml`](../rules/ens-op-exp-10-windows-event-log-cleared.yml): Windows 1102/104. FIM doesn't watch `/var/log` (0 events) | 0 (value unconfirmed) |
| 100400 | port scan | 40501 attack + new user (15 → 10) | gap: no scan events exist; needs IDS or correlation | — |
| 100401 | new remote connection | 5104 promiscuous mode | dropped: kernel lines land undecoded in `unclassified` | — |
| 100500 | weak SSH cipher | 5716 = every SSH auth failure | dropped: not visible in logs; covered by the SCA `sshd -T` cipher check | — |
| 100600 | service started | 502 Wazuh started | [`ens-op-exp-5-windows-service-installed.yml`](../rules/ens-op-exp-5-windows-service-installed.yml): Windows 7045 | 1,592 / 23 |
| 100601 | service stopped | 503 Wazuh stopped | merged into the line above; agent liveness belongs to agent status, not a rule | — |

## Fields each rule relies on

All values below were seen in real documents, unless marked *unconfirmed*.

| Rule | Index | Match |
|---|---|---|
| authentication-failure | system-activity | `wazuh.integration.name: linux`, `process.name: sshd`, `event.category: authentication`, `event.outcome: failure` (covers both `Failed password` with `event.action: authentication-failure` and `pam_unix(sshd:auth)` lines that have no action); or `windows` + `event.action: authentication-failure` |
| ssh-session-opened | system-activity | `linux`, `sshd`, `event.action: logged-in` |
| password-changed-or-reset | system-activity | `windows`, `event.action: password-changed\|password-reset`; excludes `user.target.name` `lenovo_tmp_*` |
| sudo-command-executed | system-activity | `linux`, `process.name: sudo`, `event.action: sudo` (the `COMMAND=` line; `process.command_line` holds the command) |
| sudo-authentication-failure | system-activity | `linux`, `sudo`, `event.outcome: failure` (`pam_unix(sudo:auth)`) |
| user-account-created / deleted | system-activity | `linux` + `process.name: useradd\|userdel` + `event.type: creation\|deletion` (`event.category: iam`); `windows` + `event.action: user-created\|user-deleted` |
| user-account-modified | system-activity | `linux` + `usermod`; `windows` + `user-modified\|user-enabled\|user-disabled` |
| user-added-to-privileged-group | system-activity | Linux: `usermod\|gpasswd` and `message` contains `group 'sudo'\|'wheel'\|'adm'\|'root'` (`gpasswd` *unconfirmed*). Windows: `event.action: user-added-to-group` and `group.id` `S-1-5-32-544`/`-551` or ending in `-512`/`-518`/`-519` |
| critical-system-file-changed | system-activity | `wazuh.integration.name: wazuh-fim`, `event.action: created\|modified\|deleted`, `file.path` in a fixed list, or under `sudoers.d/` or `sshd_config.d/`, or `*/.ssh/authorized_keys` |
| rootkit-hidden-process-or-port | **security** | `wazuh-rootcheck`, `event.action: malware-detected`, `threat.indicator.type: process\|port` |
| audit-daemon-stopped | system-activity | `wazuh.integration.name: auditd`, `event.code: DAEMON_END\|DAEMON_ABORT` (`DAEMON_ABORT` *unconfirmed*) |
| windows-event-log-cleared | system-activity | `windows`, `event.code: 1102\|104` (*unconfirmed*: no log clears happened in the window; `event.code` carries the EventID for every other code seen) |
| account-locked-out | system-activity | `windows`, `event.action: account-locked` (4740) |
| windows-service-installed | system-activity | `windows`, `event.code: 7045` |

Things learned from the data that shaped the rules:
- **`event.original` isn't indexed** (`index: false`), so a rule can't match on it. This rules out
  telling rootcheck's "trojaned binary" reports apart from its `check_files` link-count noise
  (about 520k `file`-type events in 90 days). That's why only `process`/`port` indicators are used.
- **`message` is a keyword field.** `|contains` works, but only on the complete normalized message.
- **Modern OpenSSH logs as `sshd-session`** (Debian 13). The standard decoders don't parse it, so
  those events land in `wazuh-events-v5-unclassified` under `wazuh-core`, with no
  `event.action`/`outcome`. They are not covered. Adding `wazuh-events-v5-unclassified` to a
  detector plus a `message|contains` rule would cover them, at the cost of evaluating ~1M
  events/day.
- **Lenovo Vantage creates, promotes and deletes `lenovo_tmp_*` local admin accounts.** The
  account rules filter them out by `user.target.name`. The privileged-group rule can't, because
  4732 events don't resolve the member SID (`user.target.name: "-"`).
- Linux `passwd`/`chpasswd` and rsyslog/journald log-deletion events don't appear in the
  indexed data, so password changes and log tampering are covered on Windows only.

## Gaps and replacements

| Need | Why a rule can't do it | 5.0 replacement |
|---|---|---|
| Brute force (100320/100321), many failures per source/user | Sigma rules match single events | OpenSearch Alerting **bucket-level monitor** on `wazuh-events-v5-system-activity`, grouped by `source.ip`/`user.name` over `event.outcome: failure` with a count threshold |
| Port scan (100400) | No scan telemetry is collected | Network IDS (Suricata/Zeek) feeding an integration, or a firewall-log bucket monitor |
| Weak SSH algorithms (100500) | Not logged at default `LogLevel` | SCA check on `sshd -T` (see `sca/ens_linux.yml`) |
| Service stopped / agent down (100601) | Inventory deltas are per process restart, too noisy | Agent connection status (`wazuh-states-*` / server API) |

## Deploy

`tools/deploy_rules.py` needs Python 3.9+ and PyYAML. It talks to the **indexer** (port 9200), not
the server API.

```bash
# 1. See exactly which requests it would send (offline, no connection opened):
python3 tools/deploy_rules.py --dry-run --detectors

# 2. Plan against the real indexer (read-only: existence + content diff, writes nothing):
python3 tools/deploy_rules.py --indexer https://indexer:9200 --user admin --cacert root-ca.pem

#    or with the admin client certificate, run on the indexer host:
python3 tools/deploy_rules.py --cert admin.pem --key admin-key.pem --cacert root-ca.pem

# 3. Apply (creates integration + rules, promotes draft -> test -> custom, writes IDs back):
python3 tools/deploy_rules.py --indexer https://indexer:9200 --user admin --cacert root-ca.pem --apply

# 4. Wire the rules into detectors (separate, explicit step: starts continuous evaluation):
python3 tools/deploy_rules.py ... --apply --detectors
```

- Password: from `$ENS_INDEXER_PASSWORD`, otherwise prompted. It's never printed. TLS is
  verified unless you pass `--insecure`.
- `--only rules/<file>.yml` deploys a single rule. Detectors are still rebuilt from every deployed
  rule for that index, so a partial run doesn't drop the others.
- `--include-disabled` also deploys `enabled: false` rules (the authentication-failure rule).
- Safety: the content manager has no read API. The tool reads the backing indices
  (`wazuh-threatintel-rules`, `-integrations`, `-policies`) instead:
  - It refuses to `POST` a rule whose title already exists in draft (`--adopt` records the
    existing ID and updates it instead).
  - It shows a diff before any `PUT`.
  - It finds the draft policy ID with `term space.name: draft` on `wazuh-threatintel-policies`.
- Promotion follows the confirmed path: one call per resource type per hop, with `space` set to
  the **source** space and all six change lists present. The integration is promoted with `add`
  (new) or `update` (new rules attached). The draft policy is promoted with `update` only when
  the integration is new.
- Two detectors are created, because a detector's `indices` must be one concrete data stream:
  `ens-compliance-system-activity-detector` (13 enabled rules) and `ens-compliance-security-detector`
  (rootkit rule). Both run every minute.
- Updating a live rule means `PUT /rules/{id}` on its **draft** copy, then promoting `update`
  draft→test→custom. The tool sends the same `{"integration", "resource"}` wrapper as `POST`,
  and that body was accepted on 5.0.0. The content diff ignores fields the server adds on its own
  (e.g. `metadata.supports: []`), so an unchanged rule is not re-sent.
- Existing detectors are found by listing all of them and matching the name, because
  `match_phrase` on `detector.name` returns nothing on 5.0.0. Re-running `--detectors` updates
  the two detectors in place instead of duplicating them.

## Remove

`deploy_rules.py` has no delete mode. To take the rules out (not verified end-to-end):

1. Delete the detectors: `DELETE _plugins/_security_analytics/detectors/<id>` (the `detector`
   value in each rule file). This stops evaluation immediately.
2. For each rule, `DELETE _plugins/_content_manager/rules/<document_id>`. The content manager
   only deletes the **draft** copy, so then promote the removal, `space` = source space:
   `POST _plugins/_content_manager/promote` with
   `{"space": "draft", "changes": {"rules": [{"operation": "remove", "id": "<document_id>"}], "policy": [], "integrations": [], "kvdbs": [], "decoders": [], "filters": []}}`,
   and the same with `"space": "test"`.
3. Delete the `ens-compliance` integration the same way (`DELETE .../integrations/<id>` + promote
   `remove`), and blank the state lines in the rule files.

## Verify

Findings carry the rule's tags, so the ENS ones can be selected without knowing any ID:

```
GET wazuh-findings-v5-*/_search
{ "query": { "prefix": { "wazuh.rule.tags": "ens." } },
  "aggs": { "rule": { "terms": { "field": "wazuh.rule.title" } } } }
```

`wazuh.rule.id` on a finding is the Security Analytics **per-space** ID (`sa_native_id` in the rule
file), not the content-manager `document_id`. To test a detector without waiting for a real event,
run `POST _plugins/_alerting/monitors/<monitor_id>/_execute` (dry run; the monitor ID is in
`.opensearch-sap-detectors-config`).
