Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param(
  [string]$IpAddress,
  [switch]$StartWazuhAgent
)

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

function Resolve-PrimaryInterfaceAlias {
  $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Sort-Object -Property RouteMetric, InterfaceMetric |
    Select-Object -First 1
  if ($defaultRoute) {
    $adapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
    if ($adapter) {
      return $adapter.InterfaceAlias
    }
  }

  $fallback = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
  if ($fallback) {
    return $fallback.InterfaceAlias
  }

  Fail "Unable to determine a network interface to configure."
}

function Read-IPv4Address {
  param([Parameter(Mandatory)][string]$Prompt)

  while ($true) {
    $inputValue = Read-Host $Prompt
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($inputValue, [ref]$ip) -and $ip.AddressFamily -eq "InterNetwork") {
      return $inputValue
    }
    Write-Host "Invalid IPv4 address, try again." -ForegroundColor Yellow
  }
}

function Get-UniqueHostname {
  $uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
  if (-not $uuid) {
    $uuid = [Guid]::NewGuid().ToString()
  }
  $shortId = ($uuid -replace "[^A-Fa-f0-9]", "").ToUpper()
  if ($shortId.Length -gt 8) {
    $shortId = $shortId.Substring(0, 8)
  }
  if (-not $shortId) {
    $shortId = (Get-Random -Minimum 10000000 -Maximum 99999999).ToString()
  }
  return "PC-$shortId"
}

function Start-WazuhAgentService {
  $service = Get-Service -Name "Wazuh","WazuhSvc" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $service) {
    Write-Host "[!] Wazuh service not found; skipping start." -ForegroundColor Yellow
    return
  }

  if ($service.Status -ne "Running") {
    Start-Service -Name $service.Name -ErrorAction Stop
    Write-Host "[+] Wazuh service started." -ForegroundColor Green
  }
}

Assert-Admin
Write-Section "WIN10 workstation bootstrap initialization"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$localConfig = Join-Path $scriptRoot "config.json"
if (Test-Path $localConfig) {
  $configPath = $localConfig
} else {
  $configPath = Join-Path (Resolve-Path (Join-Path $scriptRoot "..\..\..\config")) "config.json"
}
$Config = Get-LabConfig -Path $configPath
$NodeConfig = $Config.'Win10-PC1'.Networking
$needsReboot = $false

$IPAddress = if ($IpAddress) { $IpAddress } else { Read-IPv4Address -Prompt "Enter IPv4 address for this workstation" }
$parsedIp = $null
if (-not ([System.Net.IPAddress]::TryParse($IPAddress, [ref]$parsedIp) -and $parsedIp.AddressFamily -eq "InterNetwork")) {
  Fail "Invalid IPv4 address provided: $IPAddress"
}
$PrefixLength = $NodeConfig.PrefixLength
$Gateway = $NodeConfig.Gateway
$DnsServer = $NodeConfig.DnsServer
$Hostname = Get-UniqueHostname
$DomainDnsName = $Config.AD.Domain.DnsName
$DomainNetBios = $Config.AD.Domain.NetBiosName

Write-Section "System configuration"

if ($Hostname -and ($env:COMPUTERNAME -ne $Hostname)) {
  Write-Host "[!] Renaming computer to $Hostname (reboot required)" -ForegroundColor Yellow
  Rename-Computer -NewName $Hostname -Force
  $needsReboot = $true
}

$InterfaceAlias = Resolve-PrimaryInterfaceAlias
Write-Host "Using interface $InterfaceAlias" -ForegroundColor DarkGray

Write-Host "Removing DHCP configuration" -ForegroundColor DarkGray
$dhcpIps = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object { $_.PrefixOrigin -eq "Dhcp" }
if ($dhcpIps) {
  $dhcpIps | Remove-NetIPAddress -Confirm:$false
}

$otherStaticIps = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object { $_.IPAddress -ne $IPAddress -and $_.PrefixOrigin -ne "Dhcp" }
if ($otherStaticIps) {
  Write-Host "[!] Other static IPv4 addresses exist on $InterfaceAlias; leaving them unchanged." -ForegroundColor Yellow
}

Write-Host "Setting static IP" -ForegroundColor DarkGray
New-NetIPAddress `
  -InterfaceAlias $InterfaceAlias `
  -IPAddress $IPAddress `
  -PrefixLength $PrefixLength `
  -DefaultGateway $Gateway

Write-Host "Setting DNS" -ForegroundColor DarkGray
$currentDns = (Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4).ServerAddresses
if (-not ($currentDns -contains $DnsServer)) {
  Set-DnsClientServerAddress `
    -InterfaceAlias $InterfaceAlias `
    -ServerAddresses $DnsServer
}

Write-Host "Checking domain join status" -ForegroundColor DarkGray
$computerSystem = Get-CimInstance Win32_ComputerSystem
if (-not $computerSystem.PartOfDomain) {
  Write-Host "Joining domain $DomainDnsName" -ForegroundColor DarkGray
  $credential = Get-Credential -Message "Enter credentials for $DomainNetBios domain join"
  Add-Computer -DomainName $DomainDnsName -Credential $credential -ErrorAction Stop
  Write-Host "[!] Domain join complete; reboot required." -ForegroundColor Yellow
  $needsReboot = $true
}

Write-Host "[+] WIN10 workstation bootstrap complete."

if ($StartWazuhAgent) {
  Write-Section "Starting Wazuh agent"
  Start-WazuhAgentService
}

if ($needsReboot) {
  Write-Host "[!] The computer will reboot to apply changes." -ForegroundColor Yellow
  Restart-Computer -Force
}
