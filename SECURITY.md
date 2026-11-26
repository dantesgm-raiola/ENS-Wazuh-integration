# Security Policy

## Reporting a vulnerability

If you find a security issue in this project (e.g. a credential-handling
problem in `tools/deploy_rules.py`, a way an SCA check or detection rule
could be manipulated to report false compliance, or an installer script
doing something unsafe on the manager), please **do not
open a public GitHub issue**. Instead, use GitHub's
[private vulnerability reporting](https://github.com/fredycibersec/ENS-Wazuh-integration/security/advisories/new)
for this repository, or contact the maintainer directly.

Please include:
- A description of the issue and its impact
- Steps to reproduce
- The affected file(s) and, if relevant, the Wazuh/OpenSearch version involved

## Credentials handling

Only `tools/deploy_rules.py` needs credentials: an Indexer user allowed to use the
content-manager and Security Analytics APIs. It takes the password from the
`ENS_INDEXER_PASSWORD` environment variable or an interactive prompt, or uses a client
certificate instead. It never prints or logs the password, verifies TLS unless you pass
`--insecure`, and talks only to the Indexer you name. `install.sh` and `uninstall.sh` use
the manager's local `agent_groups` tool and need no credentials.

The 4.x sync tool, which read every stack password from `wazuh-install-files.tar`, is not
part of the 5.x version.

When reporting a bug, always redact credentials and API responses before pasting them
anywhere public.

## Command checks on agents

Many ENS checks run commands, so agents need `sca.remote_commands=1`
(`tools/agent_enable_sca_commands.*`). That setting lets any SCA policy pushed from the
manager run commands as root/SYSTEM on the agent. Anyone who can write to the manager's
`etc/shared/` directory can then run code on every agent in the group. Enable it only where
that is acceptable, and protect the manager accordingly.

## Compliance content is not a substitute for review

The SCA policies and detection rules in this repository encode an
interpretation of ENS (RD 311/2022) and ISO/IEC 27001:2022 controls (see
[`docs/controls_mapping.md`](docs/controls_mapping.md) and
[`docs/iso27001_mapping.md`](docs/iso27001_mapping.md)). A bug in a check's
regex, or an incorrect control mapping, could cause a system to be reported
as compliant when it isn't. Treat this project as an aid to auditing, not
as a certification — always validate the actual checks against your own
environment and requirements before relying on the results.

## Scope

This is a community project, not officially supported by Wazuh, Inc. — the
scope of this policy is limited to the scripts, policies, and dashboards in
this repository, not the Wazuh platform itself (report those to
[wazuh/wazuh](https://github.com/wazuh/wazuh/security)).
