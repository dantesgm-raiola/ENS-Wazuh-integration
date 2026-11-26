# ENS Wazuh Integration

[![Wazuh](https://img.shields.io/badge/Wazuh-5.x-blue)](https://wazuh.com)
[![License](https://img.shields.io/badge/License-GPL--2.0-green)](LICENSE)
[![ENS](https://img.shields.io/badge/ENS-RD%20311%2F2022-red)](https://www.boe.es/boe/dias/2022/05/03/pdfs/BOE-A-2022-7191.pdf)

Community integration of the **Spanish National Security Framework (Esquema Nacional de Seguridad — ENS, Real Decreto 311/2022)** for [Wazuh](https://wazuh.com).

> [!NOTE]
> This is a community project maintained by a [Wazuh Ambassador](https://wazuh.com/community/ambassador-program/). It is not officially supported by Wazuh, Inc.

---
<p align="center">
  <img width="900" alt="ENS Dashboard" src="https://github.com/user-attachments/assets/6a98315f-da6b-4e54-a4aa-c07e9fd6672b" />
  <img width="900" alt="SCA-ENS Dashboard" src="https://github.com/user-attachments/assets/6ea25533-2c2f-49e0-bac5-eda1cb3d2fad" />
</p>



## What is ENS?

The **Esquema Nacional de Seguridad (ENS)** is the Spanish national cybersecurity framework, mandatory for public administrations and their technology providers. It is defined in **Real Decreto 311/2022** and structured in three compliance levels:

| Level | Description |
|-------|-------------|
| **Básico** | Baseline security measures |
| **Medio** | Intermediate controls, adds to Básico |
| **Alto** | Strictest controls, adds to Medio |

ENS covers three control families: **[org]** Organizational, **[op]** Operational, and **[mp]** Protection Measures.

---

## What this integration provides

| Component | Description |
|-----------|-------------|
| **SCA policies** | `sca/ens_linux.yml` (60 checks) and `sca/ens_windows.yml` (17 checks), pushed to agents through two agent groups |
| **Detection rules** | Sigma rules for the Wazuh 5.x content manager (`rules/`), tagged with ENS controls, deployed by `tools/deploy_rules.py` |
| **Dashboards** | SCA compliance and ENS detections dashboards built on the indices Wazuh 5.x writes natively (`dashboards/`) |
| **Control mapping** | ENS ↔ Wazuh checks/rules ([docs/controls_mapping.md](docs/controls_mapping.md)) and ENS ↔ ISO/IEC 27001:2022 ([docs/iso27001_mapping.md](docs/iso27001_mapping.md)) |

There is no sync tool any more: on Wazuh 5.x the agent writes every SCA check result to the
`wazuh-states-sca` index, and detection rules produce findings in `wazuh-findings-v5-*`.

---

## Supported versions

- **Wazuh 5.x** (manager in `/var/wazuh-manager`, rules in the Indexer content manager). Built
  against the v5.0.0 SCA module and the live `wazuh-states-sca` index schema.
- **Agents**: Linux (Debian/Ubuntu/RHEL family) and Windows 10/11/Server 2016+, version 5.x.
- **Wazuh 4.x**: use the `main` branch / 4.x releases. Nothing on this branch installs on 4.x.

Upgrading from the 4.x version of this project: read [docs/MIGRATION_5x.md](docs/MIGRATION_5x.md).

---

## How ENS data is stored on Wazuh 5.x

The `wazuh-states-sca` index has a strict mapping, and the 5.x agent keeps only these
`compliance` keys: `cmmc, fedramp, gdpr, hipaa, iso_27001, nis2, nist_800_171, nist_800_53,
pci_dss, tsc`. Any other key, such as the `ens`/`ens_nivel` keys the 4.x policies used, is
dropped with an `Invalid compliance key` warning. So ENS tagging lives in fields the schema
does accept:

| Where | Value | Example |
|---|---|---|
| Check name | `[<control>] [<level>]` suffix | `Ensure SSH root login is disabled [op.acc.1] [Básico]` |
| `check.references` | `ens:<control>` (one per control) | `ens:op.acc.1` |
| `check.references` | `ens-level:<basico\|medio\|alto>` | `ens-level:basico` |
| `check.references` | `iso27001-2022:<control>` | `iso27001-2022:5.16` |
| `check.compliance.nis2` | NIS2 Art. 21.2 letter, mapped per ENS family | `21.2.i` |
| Detection rules | `wazuh.rule.tags`: `ens.<control>`, `iso27001-2022.<control>` | `ens.op.acc.6` |

ISO/IEC 27001:2022 numbers are deliberately **not** put in `check.compliance.iso_27001`: Wazuh's
own policies fill that field with 2013-style numbers (`A.12.1.1`), and mixing both numbering
schemes in one field would make it unusable. The NIS2 values are an approximate, family-level
mapping (see [docs/controls_mapping.md](docs/controls_mapping.md)).

Example queries:

```
GET wazuh-states-sca/_search?q=policy.id:ens_linux AND check.result:Failed
GET wazuh-states-sca/_search?q=check.references:"ens:op.acc.6"
GET wazuh-findings-v5-*/_search?q=wazuh.rule.tags:ens.*
```

---

## Installation

| Step | Where | What |
|---|---|---|
| 1. SCA policies | Manager, as root | `sudo ./install.sh` |
| 2. Command checks | Each agent, as root/admin | `tools/agent_enable_sca_commands.sh` / `.ps1` |
| 3. Detection rules | Anywhere that reaches the Indexer | `python3 tools/deploy_rules.py` |
| 4. Dashboards | Wazuh dashboard | import `dashboards/*.ndjson` |

### 1. SCA policies (manager)

```bash
git clone -b wazuh-5.0-migration https://github.com/fredycibersec/ENS-Wazuh-integration.git
cd ENS-Wazuh-integration
sudo ./install.sh --dry-run          # preview
sudo ./install.sh --linux-agents 001,002 --windows-agents 010
sudo ./install.sh --groups servers,proxmox   # every member of these groups, placed by OS
```

`--groups` takes existing Wazuh groups and adds each current member to `ens-linux` or
`ens-windows` according to the OS recorded by the manager. It skips macOS agents and agents that
have not reported their OS yet. The OS family comes from `os_type`, falling back to
`os_platform` (some 5.0 Windows agents leave `os_platform` empty). It reads membership from the manager's agent database
(`queue/db/global.db`, read-only) and never touches the source groups' own files, so a group
`agent.conf` managed by other tooling (Ansible, etc.) stays intact. It is a snapshot: agents
that join those groups later are not added until you run the same command again. Every step is
idempotent, so a cron job or your config-management run can repeat it safely.

The installer registers the `ens-linux` and `ens-windows` groups with the manager's
`agent_groups` tool, copies the policy into each group's directory, and writes a dedicated `agent.conf` per
group. The group directories are where the manager reads them: `/etc/wazuh-manager/shared/` on
5.0.0-1 builds published from late October 2026 on, `/var/wazuh-manager/etc/shared/` on earlier
5.0 builds. The installer picks the right one (it checks for `/etc/wazuh-manager/wazuh-manager.conf`)
and warns if a stale `/var/wazuh-manager/etc/shared/` is left from an upgrade; set
`WAZUH_CONF_DIR` to override. The manager
pushes the files to agents on its own; no restart is needed. Adding an agent to an ENS group
keeps its other groups. It never edits a group `agent.conf` it didn't write unless you pass
`--force` (a backup is kept in `<config dir>/ens-install-backups/`, outside the group
directory, because every file in a group directory is pushed to its agents). The manager host isn't scanned: install an agent on it and add
that agent to `ens-linux` if you need it.

Add more agents later by re-running the installer with `--linux-agents`, `--windows-agents`
or `--groups`, or directly:

```bash
sudo /var/wazuh-manager/bin/agent_groups -a -i <agent_id> -g ens-linux -q
```

<details>
<summary>Manual installation</summary>

```bash
G=ens-linux; P=ens_linux.yml; OS=Linux      # or ens-windows / ens_windows.yml / Windows
AGENT_SHARED=etc/shared                       # Windows agents: shared (no etc/)
SHARED=/etc/wazuh-manager/shared              # /var/wazuh-manager/etc/shared on builds before late Oct 2026
sudo /var/wazuh-manager/bin/agent_groups -a -g "$G" -q
sudo install -m 0660 -o root -g wazuh-manager "sca/$P" "$SHARED/$G/$P"
sudo tee "$SHARED/$G/agent.conf" >/dev/null <<EOF
<agent_config os="$OS">
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <policies>
      <policy>$AGENT_SHARED/$P</policy>
    </policies>
  </sca>
</agent_config>
EOF
```

The policy path is relative to the agent's install directory, where group files land:
`etc/shared/` on Linux and macOS, `shared\` on Windows. A Windows agent given `etc/shared/...`
logs "File not found" and skips the policy without any other error.
</details>

### 2. Allow command checks on the agents

28 of the 60 Linux checks and 4 of the 17 Windows checks run a command (`sshd -T`, `auditctl`,
`systemctl`, `secedit`, `Get-MpComputerStatus`...). A Wazuh agent skips command rules in a
policy pushed from the manager unless `sca.remote_commands=1` is set in its
`local_internal_options.conf`. Those checks then show `Not applicable` with the reason
`Remote commands are disabled for this policy`.

```bash
sudo tools/agent_enable_sca_commands.sh            # Linux agent
```
```powershell
.\tools\agent_enable_sca_commands.ps1              # Windows agent, elevated
```

This lets policies pushed by the manager run commands as root/SYSTEM on the agent. Only enable
it where the manager is trusted to do that. The other checks (files, `/proc/sys`, processes,
registry) work without it.

### 3. Detection rules

On 5.x there is no `etc/rules` directory: rules are Sigma YAML documents in the Indexer content
manager, linked to a custom integration and evaluated by a Security Analytics detector. The
rules in `rules/` and how to deploy them are described in
[docs/detection_rules_5x.md](docs/detection_rules_5x.md):

```bash
python3 tools/deploy_rules.py --help
python3 tools/deploy_rules.py --dry-run --indexer https://<indexer>:9200 --user admin
```

### 4. Dashboards

See [dashboards/README.md](dashboards/README.md). Import `ens_sca_compliance_5x.ndjson` and
`ens_detections_5x.ndjson` from **Dashboards Management → Saved objects → Import**.

---

## Verifying

```bash
# On the manager: the group has the files
sudo /var/wazuh-manager/bin/agent_groups -c -g ens-linux
# Which agents are in the group
sudo /var/wazuh-manager/bin/agent_groups -l -g ens-linux
```

On an agent, `/var/ossec/etc/shared/ens_linux.yml` should exist after the next sync (about a
minute), and the agent log shows the scan. Results then appear in `wazuh-states-sca`:

```
GET wazuh-states-sca/_search
{ "size": 0, "query": { "terms": { "policy.id": ["ens_linux", "ens_windows"] } },
  "aggs": { "agent": { "terms": { "field": "wazuh.agent.name" },
            "aggs": { "result": { "terms": { "field": "check.result" } } } } } }
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Many checks `Not applicable`, reason `Remote commands are disabled for this policy` | `sca.remote_commands=1` is not set on that agent (step 2) |
| Agent log: `Invalid compliance key 'ens'` | The agent still has a 4.x policy. Re-run `install.sh` so the group copy is replaced |
| No ENS results for an agent | The agent isn't in `ens-linux`/`ens-windows` (`agent_groups -s -i <id>`), or the group isn't registered |
| sshd checks `Not applicable` | `sshd` isn't installed, or `sshd -T` failed (it needs root and readable host keys) |
| `ip_forward` fails on Docker hosts, hypervisors, VPN gateways | Expected: they route by design. Record the exception |
| Per-control dashboard panels empty | The checks don't carry `ens:` references: the policy on the agent is not the 5.x one |

---

## ENS Controls Coverage

Every row below is also tagged with its ISO/IEC 27001:2022 Annex A equivalent — see [docs/iso27001_mapping.md](docs/iso27001_mapping.md) for the full ENS ↔ ISO 27001 crosswalk, including the controls that require manual evidence.

### Automated (SCA + Rules)

| Family | Control | Description | Level | ISO 27001:2022 |
|--------|---------|-------------|-------|-----------------|
| op.acc | op.acc.1 | Identification | Básico | 5.16 |
| op.acc | op.acc.2 | Access requirements | Básico | 5.15 |
| op.acc | op.acc.3 | Segregation of duties | Básico | 5.3 |
| op.acc | op.acc.6 | Authentication (org users) | Básico | 8.5 |
| op.acc | op.acc.7 | Remote access | Medio | 6.7 |
| op.exp | op.exp.2 | Security configuration | Básico | 8.9 |
| op.exp | op.exp.6 | Malware protection | Básico | 8.7 |
| op.exp | op.exp.8 | User activity logging | Básico | 8.15 |
| op.exp | op.exp.10 | Log protection | Medio | 8.15 |
| op.mon | op.mon.1 | Intrusion detection | Básico | 8.16 |
| mp.com | mp.com.2 | Confidentiality | Medio | 8.24 |
| mp.com | mp.com.3 | Authenticity/integrity | Básico | 8.24 |
| mp.com | mp.com.4 | Network segregation | Básico | 8.22 |
| mp.eq | mp.eq.2 | Workstation lock | Básico | 8.1 |
| mp.info | mp.info.3 | Information encryption | Medio | 8.24 |
| mp.info | mp.info.9 | Backups | Básico | 8.13 |
| mp.s | mp.s.2 | Service protection | Básico | 8.26 |
| mp.s | mp.s.3 | DoS protection | Básico | 8.6 |
| mp.sw | mp.sw.2 | Software acceptance | Básico | 8.29 |

### Requires manual evidence

| Family | Control | Description |
|--------|---------|-------------|
| org.* | org.1–4 | Policies, procedures, authorizations |
| mp.if | mp.if.1–7 | Physical facilities |
| mp.per | mp.per.1–5 | Personnel management |
| mp.si | mp.si.1–5 | Physical media handling |

---

## Project structure

```
ENS-Wazuh-integration/
├── sca/
│   ├── ens_linux.yml                 # SCA policy for Linux agents (60 checks)
│   └── ens_windows.yml               # SCA policy for Windows agents (17 checks)
├── rules/                            # Sigma detection rules for the 5.x content manager
├── dashboards/
│   ├── build_dashboards.py           # generator for the two ndjson bundles
│   ├── ens_sca_compliance_5x.ndjson  # SCA posture (wazuh-states-sca*)
│   ├── ens_detections_5x.ndjson      # ENS findings (wazuh-findings-v5-*)
│   └── README.md
├── tools/
│   ├── deploy_rules.py               # create/update/promote rules + detectors
│   ├── agent_enable_sca_commands.sh  # sets sca.remote_commands=1 on a Linux agent
│   └── agent_enable_sca_commands.ps1 # same for Windows agents
├── docs/
│   ├── MIGRATION_5x.md               # what changed from the 4.x version, and why
│   ├── detection_rules_5x.md         # rule-by-rule port notes and deployment
│   ├── controls_mapping.md           # ENS ↔ Wazuh mapping
│   └── iso27001_mapping.md           # ENS ↔ ISO/IEC 27001:2022 crosswalk
├── tests/
│   └── validate_sca.py               # validates policies against 5.x agent rules
├── install.sh                        # manager-side installer (groups + policies)
└── uninstall.sh
```

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

Areas where help is especially needed:
- Windows SCA policy checks
- Additional op.exp and mp.com checks
- OpenSearch dashboard improvements
- Translations and documentation

---

## References

- [Real Decreto 311/2022 — BOE](https://www.boe.es/boe/dias/2022/05/03/pdfs/BOE-A-2022-7191.pdf)
- [CCN-CERT ENS Portal](https://ens.ccn.cni.es)
- [Wazuh SCA Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/)
- [Wazuh Groups Documentation](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)

---

## Security

Found a vulnerability (credential handling, a check/rule that could report
false compliance, etc.)? See [SECURITY.md](SECURITY.md) — please don't open
a public issue for it.

---

## License

This project is licensed under the **GNU General Public License v2.0** — see [LICENSE](LICENSE) for details.

---

## Author

Maintained by **Alfredo Ramírez**, Wazuh Ambassador.
https://wazuh.com/ambassadors/alfredo-ramirez/
