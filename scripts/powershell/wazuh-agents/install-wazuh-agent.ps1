param(
  [string]$MsiPath = (Join-Path $PSScriptRoot "wazuh-agent-4.14.2-1.msi"),
  [string]$AgentName = $env:COMPUTERNAME,
  [ValidateSet("ad","workstation")]
  [string]$MachineType = "workstation",
  [string]$ConfigPath
)

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

  if (-not $cfg.SIEM -or -not $cfg.SIEM.Networking -or -not $cfg.SIEM.Networking.IpAddress) {
    Fail "Missing config value: SIEM.Networking.IpAddress"
  }

  return $cfg
}

function Get-AgentConfigPath {
  $paths = @(
    "C:\\Program Files (x86)\\ossec-agent\\ossec.conf",
    "C:\\Program Files\\ossec-agent\\ossec.conf"
  )

  foreach ($path in $paths) {
    if (Test-Path $path) {
      return $path
    }
  }

  return $null
}

function Get-ConfigTemplatePath {
  param([Parameter(Mandatory)][string]$MachineType)

  $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
  $basePath = Join-Path $scriptRoot "..\\..\\..\\config\\wazuh"
  $fileName = if ($MachineType -eq "ad") { "ad-ossec.conf" } else { "workstation-ossec.conf" }
  return Join-Path $basePath $fileName
}

function Set-WazuhManagerAddress {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Address
  )

  [xml]$xml = Get-Content -Raw -Path $Path
  if (-not $xml.ossec_config -or -not $xml.ossec_config.client -or -not $xml.ossec_config.client.server) {
    Fail "Invalid ossec.conf format: missing client/server definition."
  }

  $servers = $xml.ossec_config.client.server
  foreach ($server in @($servers)) {
    $server.address = $Address
  }

  $xml.Save($Path)
}

Assert-Admin

Write-Section "Wazuh agent installation (offline)"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path (Resolve-Path (Join-Path $scriptRoot "..\..\..\config")) "config.json"
$Config = Get-LabConfig -Path $configPath
$WazuhManager = $Config.SIEM.Networking.IpAddress

$existingService = Get-Service -Name "Wazuh","WazuhSvc" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existingService) {
  Write-Host "[=] Wazuh agent already installed ($($existingService.Name)). Skipping MSI install." -ForegroundColor Yellow
}

if (-not (Test-Path $MsiPath)) {
  Fail "Wazuh agent MSI not found: $MsiPath"
}

if (-not $ConfigPath) {
  $ConfigPath = Get-ConfigTemplatePath -MachineType $MachineType
}
if (-not (Test-Path $ConfigPath)) {
  Fail "Wazuh config template not found: $ConfigPath"
}

Write-Host "Using Wazuh manager: $WazuhManager" -ForegroundColor DarkGray
Write-Host "Using agent name: $AgentName" -ForegroundColor DarkGray
Write-Host "Using config template: $ConfigPath" -ForegroundColor DarkGray

if (-not $existingService) {
  $arguments = @(
    "/i"
    "`"$MsiPath`""
    "/q"
    "WAZUH_MANAGER=$WazuhManager"
    "WAZUH_AGENT_NAME=$AgentName"
  )

  $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -NoNewWindow -PassThru
  if ($process.ExitCode -ne 0) {
    Fail "Wazuh agent installation failed with exit code $($process.ExitCode)."
  }
}

Write-Section "Applying Wazuh agent configuration"
$agentConfigPath = Get-AgentConfigPath
if (-not $agentConfigPath) {
  Fail "Unable to find ossec.conf after installation."
}

Copy-Item -Path $ConfigPath -Destination $agentConfigPath -Force
Set-WazuhManagerAddress -Path $agentConfigPath -Address $WazuhManager

Write-Host "[+] Wazuh agent installation and configuration complete."
