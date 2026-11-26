#!/bin/bash
# ENS Wazuh Integration — uninstaller for Wazuh 5.x
# https://github.com/fredycibersec/ENS-Wazuh-integration
#
# Removes the ENS policy and the installer-managed agent.conf from the ENS agent
# groups. With --remove-groups it also deletes the groups themselves (agents that
# belong to other groups keep those).
#
# Usage: sudo ./uninstall.sh [--dry-run] [--remove-groups]
#
# Detection rules and detectors: see "Remove" in docs/detection_rules_5x.md;
# dashboards from Dashboards Management > Saved objects (ids start with ens-5x-).

set -euo pipefail

WAZUH_DIR="${WAZUH_DIR:-/var/wazuh-manager}"
AGENT_GROUPS="${WAZUH_DIR}/bin/agent_groups"
# Same detection as install.sh: newer 5.0.0-1 builds read /etc/wazuh-manager, older ones
# ${WAZUH_DIR}/etc. WAZUH_CONF_DIR overrides.
if [[ -n "${WAZUH_CONF_DIR:-}" ]]; then
  CONF_DIR="$WAZUH_CONF_DIR"
elif [[ -f /etc/wazuh-manager/wazuh-manager.conf ]]; then
  CONF_DIR=/etc/wazuh-manager
else
  CONF_DIR="${WAZUH_DIR}/etc"
fi
SHARED_DIR="${CONF_DIR}/shared"
GROUPS_TO_CLEAN=("${ENS_GROUP_LINUX:-ens-linux}:ens_linux.yml" "${ENS_GROUP_WINDOWS:-ens-windows}:ens_windows.yml")
MARKER="Managed by ENS-Wazuh-integration install.sh"
DRY_RUN=false
REMOVE_GROUPS=false

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
run()   { if $DRY_RUN; then echo -e "  ${YELLOW}[DRY-RUN]${NC} $*"; else "$@"; fi; }

for arg in "$@"; do
  case "$arg" in
    --dry-run)       DRY_RUN=true ;;
    --remove-groups) REMOVE_GROUPS=true ;;
    -h|--help)       sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) error "Unknown option: $arg" ;;
  esac
done

[[ $EUID -eq 0 ]] || $DRY_RUN || error "Run as root on the Wazuh manager."
[[ -d "$SHARED_DIR" ]] || error "Shared group directory not found at ${SHARED_DIR} (set WAZUH_CONF_DIR to override)."

for entry in "${GROUPS_TO_CLEAN[@]}"; do
  group="${entry%%:*}"; policy="${entry##*:}"; dir="${SHARED_DIR}/${group}"
  [[ -d "$dir" ]] || { info "Group directory ${dir} not present, skipping"; continue; }
  if [[ -f "${dir}/${policy}" ]]; then
    run rm -f "${dir}/${policy}"; info "Removed ${dir}/${policy}"
  fi
  if [[ -f "${dir}/agent.conf" ]]; then
    if grep -q "$MARKER" "${dir}/agent.conf"; then
      run rm -f "${dir}/agent.conf"; info "Removed ${dir}/agent.conf"
    else
      warn "${dir}/agent.conf was not written by install.sh; left in place"
    fi
  fi
  if $REMOVE_GROUPS; then
    # Only delete groups that hold nothing but our files (and remoted's merged.mg).
    others="$(find "$dir" -mindepth 1 -maxdepth 1 ! -name merged.mg ! -name "$policy" \
              ! -name agent.conf -printf '%f ' 2>/dev/null)"
    if [[ -f "${dir}/agent.conf" ]] && ! grep -q "$MARKER" "${dir}/agent.conf"; then
      others+="agent.conf"
    fi
    if [[ -n "$others" ]]; then
      warn "Group '${group}' also holds: ${others}; not removing the group"
    else
      run "$AGENT_GROUPS" -r -g "$group" -q
      info "Removed group '${group}'"
    fi
  fi
done

info "ENS SCA content removed. Agents drop the policy on their next group sync."
