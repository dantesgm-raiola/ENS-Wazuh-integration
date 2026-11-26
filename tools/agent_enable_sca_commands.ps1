# Enable command checks (c:) for SCA policies pushed from the manager.
#
# Run in an elevated PowerShell on each Windows agent in the ens-windows group.
# The ENS Windows policy reads password and lockout policy with secedit and
# checks antimalware status with Get-MpComputerStatus; the agent skips those
# command checks in group-pushed policies unless sca.remote_commands=1 is set.
# Only enable this on agents whose manager you trust to push policies.
#
# Usage: .\agent_enable_sca_commands.ps1 [-DryRun]
param([switch]$DryRun)
$ErrorActionPreference = 'Stop'

$agentDir = if ($env:WAZUH_AGENT_DIR) { $env:WAZUH_AGENT_DIR } else { "${env:ProgramFiles(x86)}\ossec-agent" }
$opts = Join-Path $agentDir 'local_internal_options.conf'
if (-not (Test-Path $opts)) { throw "Not found: $opts (is the Wazuh agent installed? set WAZUH_AGENT_DIR)" }

$content = Get-Content $opts -ErrorAction Stop
if ($content -match '^\s*sca\.remote_commands\s*=\s*1\s*$') {
    Write-Output "sca.remote_commands=1 already set in $opts"
    exit 0
}
if ($DryRun) {
    Write-Output "[DRY-RUN] would set sca.remote_commands=1 in $opts and restart the Wazuh service"
    exit 0
}
Copy-Item $opts "$opts.bak-$(Get-Date -Format yyyyMMddHHmmss)"
$kept = $content | Where-Object { $_ -notmatch '^\s*sca\.remote_commands\s*=' }
$kept + '' + '# ENS-Wazuh-integration: allow command checks in group-pushed SCA policies' + 'sca.remote_commands=1' |
    Set-Content -Path $opts -Encoding ASCII
Restart-Service -Name WazuhSvc
Write-Output "sca.remote_commands=1 set in $opts; WazuhSvc restarted"
