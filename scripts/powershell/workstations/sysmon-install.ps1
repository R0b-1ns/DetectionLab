param(
  [string]$SysmonZipPath = (Join-Path $PSScriptRoot "assets\\Sysmon.zip"),
  [string]$ConfigPath = (Join-Path $PSScriptRoot "assets\\sysmonconfig.xml"),
  [string]$InstallDir = "C:\\Windows"
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

function Get-SysmonService {
  Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
}

Assert-Admin

Write-Section "Installing Sysmon with SwiftOnSecurity configuration"

$tempRoot = Join-Path $env:TEMP "sysmon-install"
if (-not (Test-Path $tempRoot)) {
  New-Item -Path $tempRoot -ItemType Directory | Out-Null
}

$extractDir = Join-Path $tempRoot "sysmon"

if (-not (Test-Path $SysmonZipPath)) {
  Fail "Sysmon zip not found: $SysmonZipPath"
}
if (-not (Test-Path $ConfigPath)) {
  Fail "Sysmon config not found: $ConfigPath"
}

if (Test-Path $extractDir) {
  Remove-Item -Path $extractDir -Recurse -Force
}
Expand-Archive -Path $SysmonZipPath -DestinationPath $extractDir

$sysmonExeName = if ([Environment]::Is64BitOperatingSystem) { "Sysmon64.exe" } else { "Sysmon.exe" }
$sysmonSource = Join-Path $extractDir $sysmonExeName
if (-not (Test-Path $sysmonSource)) {
  Fail "Sysmon binary not found: $sysmonSource"
}

$sysmonDest = Join-Path $InstallDir $sysmonExeName
Copy-Item -Path $sysmonSource -Destination $sysmonDest -Force

$service = Get-SysmonService
if ($service) {
  Write-Host "Updating existing Sysmon configuration" -ForegroundColor DarkGray
  & $sysmonDest -c $ConfigPath | Out-Null
} else {
  Write-Host "Installing Sysmon service" -ForegroundColor DarkGray
  & $sysmonDest -accepteula -i $ConfigPath | Out-Null
}

Write-Host "[+] Sysmon installation/configuration complete."
