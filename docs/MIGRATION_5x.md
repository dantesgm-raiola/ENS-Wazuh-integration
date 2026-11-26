# Migrating ENS-Wazuh-integration from Wazuh 4.x to 5.x

Wazuh 5.0 replaced most of what the 4.x version of this project relied on. This document lists
what changed for each component, why, and how to move an existing 4.x installation over.

Sources: the Wazuh v5.0.0 source (`src/wazuh_modules/sca/sca_impl/`, `framework/scripts/agent_groups.py`,
`docs/guide/migration/rules-4x-to-5x.md`), the stock 5.0 SCA policies in `ruleset/sca/`, and the
mapping of a live 5.0 `wazuh-states-sca` index.

## What changed in Wazuh 5.0

| Area | Wazuh 4.x | Wazuh 5.x |
|---|---|---|
| Manager directory | `/var/ossec` | `/var/wazuh-manager` (agents stay in `/var/ossec`) |
| Manager config | `ossec.conf` | `wazuh-manager.conf` |
| Custom rules | XML in `etc/rules/`, `analysisd` | Sigma YAML in the Indexer content manager; Security Analytics detectors produce findings |
| Alerts | `wazuh-alerts-*` | `wazuh-events-v5-*` (events) and `wazuh-findings-v5-*` (matches) |
| SCA results | Alerts with `data.sca.*` + `/sca` API endpoints | Agent writes every check to the `wazuh-states-sca` index; no `/sca` API |
| SCA regex engine | OS_Regex / OS_Match by default | PCRE2, case-insensitive, multi-line |
| SCA check fields | `title` | `name` (`title` is still read and renamed) |
| SCA `compliance` | Any key, list-of-maps format | Mapping; only `cmmc, fedramp, gdpr, hipaa, iso_27001, nis2, nist_800_171, nist_800_53, pci_dss, tsc` are kept |

## Component by component

### SCA policies (`sca/`)

**ENS tags.** The 5.x agent's policy parser (`sca_policy_parser.cpp`, `ValidateComplianceKeys`)
removes every compliance key outside the list above and logs `Invalid compliance key '<key>' in
check <id>, ignoring`. A compliance block in the 4.x list format (`- ens: "op.acc.1"`) isn't a
mapping, so the parser drops all of it (`Unexpected compliance format`). The check itself still
runs and is indexed, but without ENS tags. Since `wazuh-states-sca` is `dynamic: strict`, adding
fields isn't an option either. ENS metadata therefore moved to `references` (`ens:<control>`,
`ens-level:<level>`, `iso27001-2022:<control>`), which the schema stores as `check.references`.
The name keeps its `[control] [level]` suffix. `compliance` now carries only a family-level
`nis2` mapping.

> An earlier review of this project concluded that 5.x discards whole ENS check results because
> of the unknown keys. That's wrong for v5.0.0: the parser strips the keys before the schema
> validator sees the event, so results are indexed without ENS tags. Live data agrees: a custom
> policy with non-standard compliance keys (`cis`, `cis_csc`) is indexed with no `compliance`
> field at all.

**`title` → `name`**, `requirements.title` → `requirements.name`, and the requirements rule
`f:/proc/sys/kernel/ostype -> Linux` became `-> r:Linux` (5.x expects typed patterns).

**Directory rules read file names, not contents.** In both 4.x and 5.x, `d:/dir -> r:X` matches
file *names* under `/dir`; only `d:/dir -> r:<name> -> r:<content>` reads files. Four 4.x checks
used the two-part form expecting content, so they never inspected file contents: 30021 (sudoers.d
NOPASSWD), 30022 (profile.d umask), 30131 (rsyslog.d forwarding) and 30400 (profile.d TMOUT).
All four now use the three-part form.

**Fewer command checks.** Kernel parameters are read from `/proc/sys/...`, binaries and daemons are
checked with `f:` and `p:` rules. Command rules dropped from 56 to 28 of the 60 Linux checks, so
more of the policy works on agents without `sca.remote_commands=1`.

**Check fixes (Linux)**

| Check | 4.x problem | 5.x version |
|---|---|---|
| 30001, 30030–30035, 30040–30042, 30300, 30301 | Read only `/etc/ssh/sshd_config`, missing `sshd_config.d/` drop-ins (Debian 12/13) and defaults | Read the effective config with `sshd -T` |
| 30035, 30300, 30301 | "Strong KEX/ciphers/MACs" passed if the directive existed with *any* value, and failed on secure defaults | Fail only if a weak algorithm is offered |
| 30031 | `ClientAliveCountMax 0` accepted, which disables the timeout on current OpenSSH | Interval 1–900, count max 1–3 |
| 30010, 30011, 30013, 30014 | Range regexes | `n:` numeric compares; 30014 also reads `pwquality.conf.d/` |
| 30021 | NOPASSWD in comments counted; sudoers.d contents never read | Ignores comments, reads the files sudo actually includes |
| 30022 | profile.d contents never read; accepted only literal 027/077 | Reads `*.sh` files; any umask with group-write and other-all masked |
| 30103 | Passed if SELinux was merely enabled (permissive) | SELinux enforcing, or AppArmor with ≥1 enforced profile |
| 30110 | "Antimalware installed" passed whenever `wazuh-agent` was running | ESET, ClamAV, Sophos, CrowdStrike or Defender for Endpoint present |
| 30124 | Only `/var/log/lastlog` (absent on Debian 13) | Also `/var/log/wtmp` and `/var/lib/wtmpdb` |
| 30126 | `chronyd` unit name only | Also `chrony`, `ntpsec`, and `timedatectl NTPSynchronized` |
| 30130 | Required rsyslog, which Debian 13 doesn't install | rsyslog, syslog-ng, or persistent journald |
| 30131 | Only `@@` in rsyslog.conf; contents of rsyslog.d never read | rsyslog `@`/`@@`/omfwd, journal-upload, or the Wazuh agent |
| 30400 | Any `TMOUT=` passed, including huge values | TMOUT 1–900; also `/etc/bash.bashrc` |
| 30510 | "Backup solution" meant rsync is installed | A real backup client (restic, borg, PBS client, Bacula, ...) |
| 30700 | `unattended-upgrades` service state | APT periodic config or dnf-automatic timers |

**Check fixes (Windows)**

| Check | 4.x problem | 5.x version |
|---|---|---|
| 31010, 31011, 31030 | Read `Netlogon\Parameters`, where account policy isn't stored: length/lockout always failed, max age read the *machine account* password age | `secedit` export with `n:` compares, as the stock 5.0 CIS policies do |
| 31100, 31101 | Defender-only; fail on hosts protected by ESET (Defender is off there) | One check: Defender real-time on, or ESET/MDE/CrowdStrike/Sophos running. 31101 removed |
| 31120 | `EventLog\Security` has no `Start` value | `EventLog` service start type is automatic |
| 31400 | Read `HKCU`, which is the SYSTEM account's hive when the agent scans | Machine inactivity limit (`InactivityTimeoutSecs` ≤ 900, not 0) |
| 31700 | Legacy `Auto Update\AUOptions`, absent on Windows 10+ | Fails only if updates are disabled by policy or service |
| 31033, 31102 | Failed when the value was absent (the secure default) | Absent or 0 passes (stock 5.0 CIS semantics) |
| 31035 | Only `RunAsPPL=1` | 1 or 2 (Windows 11 22H2+ without UEFI lock) |
| 31036 | Only the runtime key | Runtime key or the Device Guard policy key |

**Removed: `sca/ens_windows_remote.yml` and `tools/collect_registry.py`.** The agentless mode worked
around a 4.14 manager bug ([wazuh/wazuh#28979](https://github.com/wazuh/wazuh/issues/28979)) by
collecting registry values over WinRM with domain-admin credentials. On 5.x the Windows policy goes
to Windows agents through the `ens-windows` group, so neither is needed. The remote policy also
reused the IDs of `ens_windows.yml`, so the two could never load together.

### Detection rules (`rules/`)

`rules/ens_detection_rules.xml` can't be installed on 5.x: there is no `etc/rules/` and no
`analysisd`. Each rule was rewritten as a self-contained Sigma rule on Wazuh Common Schema fields
and is deployed through the content-manager API. Most 4.x rules also hooked the wrong parent rule
(for example sudo success and failure were swapped, and "weak SSH cipher" fired on every SSH
authentication failure); the rewrite fixes the intent, not just the format. Rule-by-rule notes,
dropped rules and the deploy procedure are in [detection_rules_5x.md](detection_rules_5x.md).

### Installer and agent groups

`install.sh` no longer edits `ossec.conf` or copies files into `ruleset/sca/`. It registers the
`ens-linux` and `ens-windows` groups with `agent_groups`, places the policies in the groups'
shared directories, and writes one `agent.conf` per group. `deploy_sca_agents.sh` is folded into
it (`--linux-agents`, `--windows-agents`), and it no longer needs API credentials.

### Sync tool and dashboards

`tools/sync_sca_to_opensearch.py`, `install_sync.sh` and `uninstall_sync.sh` are removed. They
polled `/sca` API endpoints that 5.x doesn't have, and 5.x already indexes every check in
`wazuh-states-sca`. The dashboards were rebuilt on `wazuh-states-sca*` and
`wazuh-findings-v5-*` (see [../dashboards/README.md](../dashboards/README.md)).

## Moving an existing 4.x installation

Wazuh 4.x → 5.0 is a platform migration in its own right; follow Wazuh's upgrade guide for the
manager, indexer and agents first. Then:

1. On the 4.x manager (before upgrading, if it's still running), remove the old content:
   `ruleset/sca/ens_*.yml`, the `<policy>` lines in `ossec.conf`, `etc/rules/ens_detection_rules.xml`,
   the sync cron job (`/etc/cron.d/ens-sca-sync`), its log `/var/log/ens-sca-sync.log` (it
   contains the first characters of the API and indexer passwords, so delete it rather than
   archive it, and consider rotating those passwords), and the `ens-sca-checks` index.
2. On the 5.x manager run `sudo ./install.sh`, add the agents to the groups, and enable
   `sca.remote_commands` on them.
3. Deploy the detection rules with `tools/deploy_rules.py`.
4. Delete the old `ens-*` saved objects from the dashboard and import the two `*_5x.ndjson` bundles.

Check IDs are unchanged (except removed 31101), so results for the same check line up before and
after. Names changed for checks whose meaning changed (listed above).

## Not verified

- The policies were validated statically (`tests/validate_sca.py`) and against the 5.0 parser and
  evaluator source, but haven't been run on a live 5.x agent yet. Run them on a test agent first
  and look at `check.reason` for any `Not applicable` result.
- The Windows checks follow the stock 5.0 CIS policy syntax but haven't been tested on Windows.
