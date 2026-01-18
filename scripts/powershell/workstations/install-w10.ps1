Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Fail {
  param([Parameter(Mandatory)][string]$Message)
  Write-Host "[-] $Message" -ForegroundColor Red
  throw $Message
}

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "This script must be run as Administrator."
  }
}

function Get-LabConfig {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path $Path)) {
    Fail "Config file not found: $Path"
  }

  try {
    $cfg = Get-Content -Raw -Path $Path | ConvertFrom-Json
  } catch {
    Fail "Unable to read config.json: $($_.Exception.Message)"
  }

  $requiredPaths = @(
    "Win10-PC1.Networking.IpAddress",
    "Win10-PC1.Networking.PrefixLength",
    "Win10-PC1.Networking.Gateway",
    "Win10-PC1.Networking.DnsServer",
    "Win10-PC1.Networking.Hostname",
    "AD.Domain.DnsName",
    "AD.Domain.NetBiosName"
  )

  foreach ($item in $requiredPaths) {
    $parts = $item.Split(".")
    $current = $cfg
    foreach ($part in $parts) {
      if (-not $current.$part) {
        Fail "Missing config value: $item"
      }
      $current = $current.$part
    }
  }

  return $cfg
}

Assert-Admin
Write-Section "WIN10 workstation install initialization"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path (Resolve-Path (Join-Path $scriptRoot "..\..\..\config")) "config.json"
$Config = Get-LabConfig -Path $configPath
$NodeConfig = $Config.'Win10-PC1'.Networking

Write-Section "Sysmon installation"
$sysmonScript = Join-Path $scriptRoot "sysmon-install.ps1"
if (-not (Test-Path $sysmonScript)) {
  Fail "Sysmon install script not found: $sysmonScript"
}
& $sysmonScript

Write-Section "Workstation baseline"
$baselineScript = Join-Path $scriptRoot "workstations-bootstrap.ps1"
if (-not (Test-Path $baselineScript)) {
  Fail "Workstations bootstrap script not found: $baselineScript"
}
& $baselineScript

Write-Section "Wazuh agent installation"
$wazuhScript = Join-Path $scriptRoot "..\\wazuh-agents\\install-wazuh-agent.ps1"
if (-not (Test-Path $wazuhScript)) {
  Fail "Wazuh agent install script not found: $wazuhScript"
}
& $wazuhScript -MachineType "workstation"

Write-Section "Workstation bootstrap"
$bootstrapScript = Join-Path $scriptRoot "w10-workstation-bootstrap.ps1"
if (-not (Test-Path $bootstrapScript)) {
  Fail "Workstation bootstrap script not found: $bootstrapScript"
}
& $bootstrapScript -IpAddress $NodeConfig.IpAddress

Write-Section "Preparing files for Sysprep reuse"
$targetDir = "C:\\Scripts"
if (-not (Test-Path $targetDir)) {
  New-Item -Path $targetDir -ItemType Directory | Out-Null
}
Copy-Item -Path $bootstrapScript -Destination (Join-Path $targetDir "w10-workstation-bootstrap.ps1") -Force
Copy-Item -Path $configPath -Destination (Join-Path $targetDir "config.json") -Force

Write-Host "[+] WIN10 workstation install complete."
