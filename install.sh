#!/bin/bash
# ENS Wazuh Integration — installer for Wazuh 5.x
# https://github.com/fredycibersec/ENS-Wazuh-integration
#
# Run as root on the Wazuh 5.x manager. It:
#   1. registers two agent groups (ens-linux, ens-windows) with the manager's own
#      agent_groups tool,
#   2. copies the ENS SCA policy into each group's shared directory,
#   3. writes a dedicated agent.conf for each group that enables that policy,
#   4. optionally adds agents to the groups (an agent keeps its other groups), either
#      by ID or by taking every member of existing Wazuh groups and placing each one
#      in ens-linux or ens-windows according to its OS.
#
# The manager pushes group files to agents by itself (remoted re-reads the shared
# directory), so no manager restart is needed. Results land in the
# wazuh-states-sca index; there is nothing to sync.
#
# Detection rules and dashboards are installed separately:
#   tools/deploy_rules.py   (Indexer content-manager API)
#   dashboards/README.md    (saved-object import)
#
# Usage:
#   sudo ./install.sh [--dry-run] [--force]
#                     [--linux-agents 001,002] [--windows-agents 010,011]
#                     [--groups servers,proxmox]
#
#   --dry-run          show what would change, change nothing
#   --force            overwrite a group agent.conf that this script did not write
#   --linux-agents     comma-separated agent IDs to add to ens-linux
#   --windows-agents   comma-separated agent IDs to add to ens-windows
#   --groups           comma-separated existing Wazuh groups: every current member goes
#                      to ens-linux or ens-windows by its OS (macOS agents and agents
#                      that never connected are skipped). The groups' own files are
#                      not touched. This is a snapshot of membership: re-run the same
#                      command to pick up agents that joined those groups later.
#
# Environment overrides: WAZUH_DIR (default /var/wazuh-manager),
# WAZUH_CONF_DIR (detected, see below), ENS_GROUP_LINUX (ens-linux),
# ENS_GROUP_WINDOWS (ens-windows), ENS_SCA_INTERVAL (12h).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="${WAZUH_DIR:-/var/wazuh-manager}"
AGENT_GROUPS="${WAZUH_DIR}/bin/agent_groups"

# Where the manager reads its configuration, group directories included. Builds published
# from late October 2026 on (still versioned 5.0.0-1) read /etc/wazuh-manager and ignore
# ${WAZUH_DIR}/etc; earlier 5.0 builds read ${WAZUH_DIR}/etc. A host upgraded from one to the
# other keeps a stale ${WAZUH_DIR}/etc/shared, so the newer layout is checked first: files
# written to the directory the manager does not read are never pushed to agents.
detect_conf_dir() {
  if [[ -n "${WAZUH_CONF_DIR:-}" ]]; then
    echo "$WAZUH_CONF_DIR"
  elif [[ -f /etc/wazuh-manager/wazuh-manager.conf ]]; then
    echo /etc/wazuh-manager
  else
    echo "${WAZUH_DIR}/etc"
  fi
}
CONF_DIR="$(detect_conf_dir)"
SHARED_DIR="${CONF_DIR}/shared"
GROUP_LINUX="${ENS_GROUP_LINUX:-ens-linux}"
GROUP_WINDOWS="${ENS_GROUP_WINDOWS:-ens-windows}"
SCA_INTERVAL="${ENS_SCA_INTERVAL:-12h}"
MARKER="Managed by ENS-Wazuh-integration install.sh"

DRY_RUN=false
FORCE=false
LINUX_AGENTS=""
WINDOWS_AGENTS=""
SOURCE_GROUPS=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
run()   { if $DRY_RUN; then echo -e "  ${YELLOW}[DRY-RUN]${NC} $*"; else "$@"; fi; }

usage() { sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)        DRY_RUN=true ;;
    --force)          FORCE=true ;;
    --linux-agents)   LINUX_AGENTS="${2:-}"; shift ;;
    --windows-agents) WINDOWS_AGENTS="${2:-}"; shift ;;
    --groups)         SOURCE_GROUPS="${2:-}"; shift ;;
    -h|--help)        usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
  shift
done

echo ""
echo "  ENS Wazuh Integration — installer (Wazuh 5.x)"
$DRY_RUN && echo -e "  ${YELLOW}DRY-RUN: nothing will be changed${NC}"
echo ""

# ── Checks ────────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || $DRY_RUN || error "Run as root on the Wazuh manager."
if [[ ! -d "$WAZUH_DIR" ]]; then
  if [[ -d /var/ossec/etc/rules ]]; then
    error "Found a Wazuh 4.x layout (/var/ossec). This branch targets Wazuh 5.x; use the 4.x release of this project instead."
  fi
  error "Wazuh 5.x manager directory not found at ${WAZUH_DIR} (set WAZUH_DIR to override)."
fi
[[ -x "$AGENT_GROUPS" ]] || error "agent_groups not found at ${AGENT_GROUPS}."
[[ -d "$SHARED_DIR" ]] || error "Shared group directory not found at ${SHARED_DIR} (set WAZUH_CONF_DIR to override)."
for f in ens_linux.yml ens_windows.yml; do
  [[ -f "${SCRIPT_DIR}/sca/${f}" ]] || error "Missing sca/${f} next to this script."
done
for ids in "$LINUX_AGENTS" "$WINDOWS_AGENTS"; do
  [[ -z "$ids" || "$ids" =~ ^[0-9]+(,[0-9]+)*$ ]] || error "Agent ID lists must look like 001,002 (got '${ids}')."
done
[[ -z "$SOURCE_GROUPS" || "$SOURCE_GROUPS" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]] \
  || error "--groups must look like servers,proxmox (got '${SOURCE_GROUPS}')."

# Group that owns the shared files (wazuh-manager on 5.x packages).
FILE_GROUP="$(stat -c %G "${SHARED_DIR}/default" 2>/dev/null || stat -c %G "$SHARED_DIR")"
info "Manager directory: ${WAZUH_DIR}; group directories: ${SHARED_DIR} (owned by group '${FILE_GROUP}')"
if [[ "$SHARED_DIR" != "${WAZUH_DIR}/etc/shared" && -d "${WAZUH_DIR}/etc/shared" ]]; then
  warn "${WAZUH_DIR}/etc/shared also exists: it is left over from an older 5.0 layout and is not read by this manager."
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
group_registered() {
  # agent_groups -l prints "  <name> (<count>)" per group.
  "$AGENT_GROUPS" -l 2>/dev/null | grep -Eq "^[[:space:]]+${1}[[:space:]]+\([0-9]+\)$"
}

install_file() {  # src dest
  run install -m 0660 -o root -g "$FILE_GROUP" "$1" "$2"
}

write_agent_conf() {  # group os policy
  local group="$1" os="$2" policy="$3" dest="${SHARED_DIR}/$1/agent.conf"
  # agent_groups seeds a new group with a copy of agent-template.conf: nothing to keep. Any
  # other file left in the group directory is pushed to agents inside merged.mg, so no backup
  # is written for it.
  if [[ -f "$dest" && -f "${SHARED_DIR}/agent-template.conf" ]] && cmp -s "$dest" "${SHARED_DIR}/agent-template.conf"; then
    :
  elif [[ -f "$dest" ]] && ! grep -q "$MARKER" "$dest"; then
    # Only reachable with --force (preflight refuses otherwise). Kept outside shared/: a file in
    # the group directory would be pushed to every agent of the group.
    local backup="${CONF_DIR}/ens-install-backups/${group}-agent.conf.$(date +%Y%m%d%H%M%S)"
    run install -d -m 0750 -o root -g "$FILE_GROUP" "${CONF_DIR}/ens-install-backups"
    run cp -p "$dest" "$backup"
    warn "Backed up existing ${dest} to ${backup}"
  fi
  # Policy path relative to the agent's install directory, where it keeps group files: etc/shared/
  # on Linux/macOS, shared\ on Windows (SHAREDCFG_DIR in src/shared/include/defs.h). A Windows
  # agent given etc/shared/... logs "File not found" and silently skips the policy.
  local agent_shared="etc/shared"
  [[ "$os" == "Windows" ]] && agent_shared="shared"
  local tmp; tmp="$(mktemp)"
  cat > "$tmp" <<EOF
<!-- ${MARKER}. Edits are overwritten on reinstall. -->
<agent_config os="${os}">
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>${SCA_INTERVAL}</interval>
    <policies>
      <policy>${agent_shared}/${policy}</policy>
    </policies>
  </sca>
</agent_config>
EOF
  install_file "$tmp" "$dest"
  rm -f "$tmp"
  info "Wrote ${dest}"
}

setup_group() {  # group os policy
  local group="$1" os="$2" policy="$3"
  if group_registered "$group"; then
    info "Group '${group}' already registered"
  else
    run "$AGENT_GROUPS" -a -g "$group" -q
    info "Registered group '${group}'"
  fi
  [[ -d "${SHARED_DIR}/${group}" ]] || run install -d -m 0770 -o root -g "$FILE_GROUP" "${SHARED_DIR}/${group}"
  install_file "${SCRIPT_DIR}/sca/${policy}" "${SHARED_DIR}/${group}/${policy}"
  info "Copied sca/${policy} to ${SHARED_DIR}/${group}/"
  write_agent_conf "$group" "$os" "$policy"
}

# The manager's agent database (wazuh-db's global.db), opened read-only with the manager's
# own Python. agent_groups can list a group's members but not their OS, which --groups needs.
declare -A ASSIGNED=()   # "<group>:<id>" added during this run
GLOBAL_DB="${WAZUH_DIR}/queue/db/global.db"
FRAMEWORK_PY="${WAZUH_DIR}/framework/python/bin/python3"

query_agents() {  # group,group,... -> "id<TAB>platform<TAB>name<TAB>groups" per agent (or all agents); "-" = none
  local py="$FRAMEWORK_PY"
  [[ -x "$py" ]] || py="$(command -v python3)" || error "No Python found to read ${GLOBAL_DB}."
  [[ -r "$GLOBAL_DB" ]] || error "Cannot read the agent database ${GLOBAL_DB} (run as root)."
  "$py" - "$GLOBAL_DB" "${1:-}" <<'PY'
import sqlite3, sys
db, wanted = sys.argv[1], [g for g in sys.argv[2].split(",") if g]
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
groups = {}
for aid, gname in con.execute("SELECT b.id_agent, g.name FROM belongs b JOIN `group` g ON g.id = b.id_group"):
    groups.setdefault(aid, []).append(gname)
known = {r[0] for r in con.execute("SELECT name FROM `group`")}
missing = [g for g in wanted if g not in known]
if missing:
    print("MISSING\t" + ",".join(missing))
    sys.exit(0)
# OS family: os_type (linux/windows/macos) first. Some 5.0 Windows agents report an empty
# os_platform while os_type is set, so os_platform (debian, windows, darwin...) is only the
# fallback. "-" for an unknown OS: bash's read collapses consecutive tabs, so no field may be empty.
cols = {r[1] for r in con.execute("PRAGMA table_info(agent)")}
os_expr = "NULLIF(os_platform, '')"
if "os_type" in cols:
    os_expr = f"NULLIF(os_type, ''), {os_expr}"
for aid, name, platform in con.execute(f"SELECT id, name, COALESCE({os_expr}, '-') FROM agent WHERE id > 0 ORDER BY id"):
    mine = groups.get(aid, [])
    if wanted and not set(wanted) & set(mine):
        continue
    print(f"{aid:03d}\t{platform}\t{name}\t{','.join(mine) or '-'}")
PY
}

assign_one() {  # group id
  local group="$1" id; id="$(printf '%03d' "$((10#$2))")"
  if [[ ",$(agent_memberships "$id")," == *",${group},"* || -n "${ASSIGNED["${group}:${id}"]:-}" ]]; then
    info "Agent ${id} is already in '${group}'"
    return 0
  fi
  ASSIGNED["${group}:${id}"]=1
  if $DRY_RUN; then
    run "$AGENT_GROUPS" -a -i "$id" -g "$group" -q
    return 0
  fi
  # agent_groups exits 0 even when the assignment fails, so check what it printed.
  local out; out="$("$AGENT_GROUPS" -a -i "$id" -g "$group" -q 2>&1 || true)"
  if [[ "$out" == *"added to agent"* ]]; then
    info "Added agent ${id} to '${group}' (its other groups are kept)"
  else
    error "Could not add agent ${id} to '${group}': ${out}"
  fi
}

agent_memberships() {  # id -> comma-separated groups ('' if unknown)
  [[ -n "${AGENT_TABLE:-}" ]] || return 0
  awk -F'\t' -v id="$1" '$1 == id { print $4 }' <<< "$AGENT_TABLE"
}

assign_agents() {  # group id,id,...
  local group="$1" ids="$2" id
  [[ -z "$ids" ]] && return 0
  IFS=',' read -ra list <<< "$ids"
  for id in "${list[@]}"; do
    assign_one "$group" "$id"
  done
}

assign_from_groups() {  # group,group,...
  local src="$1" id platform name groups target n_linux=0 n_windows=0
  [[ -z "$src" ]] && return 0
  local members; members="$(query_agents "$src")"
  [[ -n "$members" ]] || { warn "No agents found in group(s) '${src}'."; return 0; }
  while IFS=$'\t' read -r id platform name groups; do
    case "${platform,,}" in
      windows)      target="$GROUP_WINDOWS"; n_windows=$((n_windows + 1)) ;;
      darwin|macos) warn "Skipping agent ${id} (${name}): macOS has no ENS policy"; continue ;;
      *bsd|sunos|solaris|aix|hp-ux|hpux)
                    warn "Skipping agent ${id} (${name}): no ENS policy for ${platform}"; continue ;;
      -)            warn "Skipping agent ${id} (${name}): it has not reported its OS yet (never connected, or not since registering)"; continue ;;
      *)            target="$GROUP_LINUX"; n_linux=$((n_linux + 1)) ;;
    esac
    info "Group member ${id} (${name}, ${platform}) -> '${target}'"
    assign_one "$target" "$id"
  done <<< "$members"
  info "From group(s) '${src}': ${n_linux} agent(s) for '${GROUP_LINUX}', ${n_windows} for '${GROUP_WINDOWS}'"
}

# ── Preflight: refuse before changing anything ───────────────────────────────
for g in "$GROUP_LINUX" "$GROUP_WINDOWS"; do
  conf="${SHARED_DIR}/${g}/agent.conf"
  if [[ -f "$conf" ]] && ! grep -q "$MARKER" "$conf" && ! $FORCE; then
    error "${conf} exists and was not written by this installer. Nothing was changed. Re-run with --force to replace it (a backup is kept), or add the <sca> block from README.md to it by hand."
  fi
done

AGENT_TABLE=""
if [[ -n "$LINUX_AGENTS$WINDOWS_AGENTS$SOURCE_GROUPS" ]]; then
  AGENT_TABLE="$(query_agents "")"
fi
for id in ${LINUX_AGENTS//,/ } ${WINDOWS_AGENTS//,/ }; do
  id="$(printf '%03d' "$((10#$id))")"
  awk -F'\t' -v id="$id" '$1 == id { found = 1 } END { exit !found }' <<< "$AGENT_TABLE" \
    || error "Agent ${id} is not registered on this manager. Nothing was changed."
done
if [[ -n "$SOURCE_GROUPS" ]]; then
  check="$(query_agents "$SOURCE_GROUPS")"
  [[ "$check" == MISSING* ]] && error "Unknown Wazuh group(s): ${check#MISSING$'\t'}. Nothing was changed."
fi

# ── Install ───────────────────────────────────────────────────────────────────
setup_group "$GROUP_LINUX"   "Linux"   "ens_linux.yml"
setup_group "$GROUP_WINDOWS" "Windows" "ens_windows.yml"
assign_agents "$GROUP_LINUX"   "$LINUX_AGENTS"
assign_agents "$GROUP_WINDOWS" "$WINDOWS_AGENTS"
assign_from_groups "$SOURCE_GROUPS"

echo ""
info "Done. Agents in '${GROUP_LINUX}' / '${GROUP_WINDOWS}' receive the policy on their next sync."
echo ""
echo -e "${YELLOW}--- Required on each agent ---${NC}"
echo "  Many ENS checks run commands (sshd -T, auditctl, secedit...). The agent skips"
echo "  command checks in group-pushed policies unless sca.remote_commands=1 is set in"
echo "  its local_internal_options.conf; skipped checks show up as 'Not applicable'"
echo "  with reason 'Remote commands are disabled for this policy'."
echo "    Linux:   sudo tools/agent_enable_sca_commands.sh"
echo "    Windows: tools\\agent_enable_sca_commands.ps1  (elevated PowerShell)"
echo ""
echo -e "${YELLOW}--- Next steps ---${NC}"
echo "  1. Add agents to the groups (if not done above), by ID or by existing group:"
echo "       sudo ./install.sh --linux-agents <id,id> --groups <group,group>"
echo "  2. Detection rules:  python3 tools/deploy_rules.py --help"
echo "  3. Dashboards:       see dashboards/README.md"
echo "  4. Check results:    GET wazuh-states-sca/_search?q=policy.id:ens_linux"
echo ""
