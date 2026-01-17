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

Assert-Admin
Write-Section "WIN10-PC1 configuration initialization"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path (Resolve-Path (Join-Path $scriptRoot "..\..\..\config")) "config.json"
$Config = Get-LabConfig -Path $configPath
$NodeConfig = $Config.'Win10-PC1'.Networking

$IPAddress = $NodeConfig.IpAddress
$PrefixLength = $NodeConfig.PrefixLength
$Gateway = $NodeConfig.Gateway
$DnsServer = $NodeConfig.DnsServer
$Hostname = $NodeConfig.Hostname
$DomainDnsName = $Config.AD.Domain.DnsName
$DomainNetBios = $Config.AD.Domain.NetBiosName

Write-Section "System configuration"

if ($Hostname -and ($env:COMPUTERNAME -ne $Hostname)) {
  Write-Host "[!] Renaming computer to $Hostname (reboot required)" -ForegroundColor Yellow
  Rename-Computer -NewName $Hostname -Force
  Write-Host "[!] Reboot and re-run the script to continue." -ForegroundColor Yellow
  exit 0
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
  Write-Host "[!] Domain join complete; rebooting." -ForegroundColor Yellow
  Restart-Computer -Force
  exit 0
}

Write-Host "[+] WIN10-PC1 configuration complete."
