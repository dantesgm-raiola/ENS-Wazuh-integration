# Contributing to ENS Wazuh Integration

Thank you for your interest in contributing. This project maps the Spanish National Security Framework (ENS, Real Decreto 311/2022) to Wazuh checks and detection rules. Contributions that improve coverage, accuracy, or usability are very welcome.

---

## Table of contents

1. [Reporting issues](#reporting-issues)
2. [Development setup](#development-setup)
3. [Contributing SCA checks](#contributing-sca-checks)
4. [Contributing detection rules](#contributing-detection-rules)
5. [Contributing to the dashboard](#contributing-to-the-dashboard)
6. [Updating the controls mapping](#updating-the-controls-mapping)
7. [Pull request process](#pull-request-process)

---

## Reporting issues

Use [GitHub Issues](https://github.com/fredycibersec/ENS-Wazuh-integration/issues) to report bugs or suggest improvements. Please include:

- Wazuh version (`/var/ossec/bin/wazuh-control info`)
- OS and distribution of the affected agent
- The full error message or unexpected behaviour
- Steps to reproduce

---

## Development setup

No special tooling is required. To validate your changes locally before opening a PR:

```bash
# Install the YAML parser
pip install pyyaml

# Validate both SCA policies
python3 tests/validate_sca.py sca/ens_linux.yml sca/ens_windows.yml
```

The validator checks what the Wazuh 5.x agent accepts:
- YAML syntax, policy fields, and `policy.file` matching the file name
- Check fields (`id`, `name`, `description`, `condition`, `rules`); the 4.x `title` is rejected
- Check ID uniqueness across all policy files
- `compliance` is a mapping that uses only the keys the 5.x agent keeps
- ENS tagging: `ens:<control>` and `ens-level:<level>` in `references`, matching the name suffix
- Rule syntax: known rule types, `n:<regex> compare <op> <int>` shape, regexes compile

---

## Contributing SCA checks

### Check ID ranges

IDs are allocated by ENS control family. Use the next available ID within the correct range:

| ENS family | ID range      |
|------------|---------------|
| op.acc     | 30001 – 30099 |
| op.exp     | 30100 – 30199 |
| op.mon     | 30200 – 30299 |
| mp.com     | 30300 – 30399 |
| mp.eq      | 30400 – 30499 |
| mp.info    | 30500 – 30599 |
| mp.s       | 30600 – 30699 |
| mp.sw      | 30700 – 30799 |

New families not listed above: open an issue first to agree on a range.

### Required structure

ENS tagging goes in `references` (the 5.x SCA schema drops unknown `compliance` keys such as
`ens`). Example:

```yaml
- id: 30036
  name: "Ensure SSH MaxAuthTries is set to 4 or less [op.acc.6] [Básico]"
  description: "Limit the number of authentication attempts per connection."
  rationale: "Reduces exposure to brute-force attacks. Required by ENS op.acc.6."
  remediation: "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config and reload sshd."
  references:
    - "ens:op.acc.6"
    - "ens-level:basico"
    - "iso27001-2022:8.5"
  compliance:
    nis2: ["21.2.i"]
  condition: all
  rules:
    - 'c:sshd -T -> n:^maxauthtries\s+(\d+) compare <= 4'
```

**Name format:** `"<description> [<ens_control>] [<level>]"`, with the same controls and level
as the `ens:` / `ens-level:` references.

**Level values:** `Básico`, `Medio`, `Alto` in the name; `basico`, `medio`, `alto` in
`ens-level:`.

**Compliance keys:** only `cmmc, fedramp, gdpr, hipaa, iso_27001, nis2, nist_800_171,
nist_800_53, pci_dss, tsc`. Use the NIS2 table in `docs/controls_mapping.md`. Don't put
ISO 27001:2022 numbers in `iso_27001` (use the `iso27001-2022:` reference).

**Regexes** are PCRE2, case-insensitive and multi-line on 5.x. `d:/dir -> r:X` matches file
*names*; to match file contents use `d:/dir -> r:<file-name-regex> -> r:<content-regex>`.
Prefer `f:` reads (`/proc/sys/...`, config files) and `p:` process checks over `c:` commands:
command checks need `sca.remote_commands=1` on every agent.

### Guidelines

- One check per configuration item. Prefer narrow, actionable checks over broad ones.
- `rationale` must reference the ENS control explicitly.
- `remediation` must give a concrete, copy-pasteable fix.
- Test the check against a real agent before submitting. Include a brief note in the PR description on how it was tested.
- Windows checks go in `ens_windows.yml` (ID range same as Linux for the same control family).

---

## Contributing detection rules

Detection rules are Sigma YAML files in `rules/`, one per rule, for the Wazuh 5.x content
manager. See [docs/detection_rules_5x.md](docs/detection_rules_5x.md) for the format, the
deployment-state header that `tools/deploy_rules.py` fills in, and the deploy steps.

- `logsource.product` must be `ens-compliance` (the custom integration's title).
- Match on Wazuh Common Schema fields you have seen in real events (`wazuh-events-v5-*`); the
  content manager rejects unknown fields.
- `tags`: `ens.<control>` for each ENS control and `iso27001-2022.<control>`; the detections
  dashboard filters on `ens.*`.
- `compliance` accepts the same fixed keys as SCA. No `ens` key.
- Event correlation (frequency, timeframe) isn't available in 5.x rules: use an OpenSearch
  Alerting bucket-level monitor instead.

---

## Contributing to the dashboard

The dashboards are generated by `dashboards/build_dashboards.py`. Edit the script, regenerate,
and validate:

```bash
python3 dashboards/build_dashboards.py
python3 dashboards/build_dashboards.py --check
```

Keep object ids under the `ens-5x-` prefix, and check the panels on a live Wazuh 5.x dashboard
before submitting.

---

## Updating the controls mapping

`docs/controls_mapping.md` is the authoritative reference table. When you add checks or rules that cover a new ENS control, update the table accordingly:

- Add the SCA check IDs to the **SCA Check IDs** column.
- Add the rule IDs to the **Rule IDs** column.
- If a control was previously listed as manual-only, move it to the automated section.

---

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes following the conventions above.
3. Run `python3 tests/validate_sca.py sca/ens_linux.yml sca/ens_windows.yml` and fix any errors.
4. Update `docs/controls_mapping.md` if your change affects ENS control coverage.
5. Add a brief entry to `CHANGELOG.md` under `[Unreleased]`.
6. Open a PR with a clear description of:
   - Which ENS control(s) are affected
   - What was added or changed and why
   - How the change was tested

PRs that fail the SCA validator or that are missing compliance tags will be asked to fix those before merging.

---

## Security

Please do not open a public issue for a security vulnerability (credential
handling, a check/rule that could report false compliance, etc.) — see
[SECURITY.md](SECURITY.md).

## Questions

Open a [GitHub Discussion](https://github.com/fredycibersec/ENS-Wazuh-integration/discussions) for questions that are not bug reports or feature requests.
