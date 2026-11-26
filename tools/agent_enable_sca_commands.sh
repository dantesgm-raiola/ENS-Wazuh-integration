#!/bin/bash
# Enable command checks (c:) for SCA policies pushed from the manager.
#
# Run as root on each Linux agent that is in the ens-linux group. Wazuh agents
# skip c: rules in group-pushed (remote) policies unless sca.remote_commands=1 is
# set locally; the ENS Linux policy relies on them for sshd -T, auditctl,
# systemctl and similar. Only enable this on agents whose manager you trust to
# push policies: it lets group policies run commands as root on the agent.
#
# Usage: sudo ./agent_enable_sca_commands.sh [--dry-run]

set -euo pipefail
OPTS="${WAZUH_AGENT_DIR:-/var/ossec}/etc/local_internal_options.conf"
DRY_RUN=false; [[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

[[ $EUID -eq 0 ]] || $DRY_RUN || { echo "Run as root." >&2; exit 1; }
[[ -f "$OPTS" ]] || { echo "Not found: $OPTS (is the Wazuh agent installed? set WAZUH_AGENT_DIR)" >&2; exit 1; }

if grep -Eq '^\s*sca\.remote_commands\s*=\s*1\s*$' "$OPTS"; then
  echo "sca.remote_commands=1 already set in $OPTS"
  exit 0
fi
if $DRY_RUN; then
  echo "[DRY-RUN] would set sca.remote_commands=1 in $OPTS and restart wazuh-agent"
  exit 0
fi
cp -p "$OPTS" "${OPTS}.bak-$(date +%Y%m%d%H%M%S)"
sed -i -E '/^\s*sca\.remote_commands\s*=/d' "$OPTS"
printf '\n# ENS-Wazuh-integration: allow command checks in group-pushed SCA policies\nsca.remote_commands=1\n' >> "$OPTS"
systemctl restart wazuh-agent
echo "sca.remote_commands=1 set in $OPTS; wazuh-agent restarted"
