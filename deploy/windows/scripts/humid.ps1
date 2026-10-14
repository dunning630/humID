<#
.SYNOPSIS
  HumID Server for Windows (__HUMID_SERVER_VERSION__): install, run and manage the HumID vault server.

.DESCRIPTION
  Runs the five HumID services and a local web edge as one background task
  that starts with Windows, even when nobody is signed in. It listens on
  127.0.0.1 only; phones reach it through a tunnel (Tailscale Funnel or
  Cloudflare Tunnel), so nothing on your router needs to change.

  Run from Terminal (Admin):
    humid install [-DevicePolicy attested|biometric|demo] [-AppleTeamId ABCDE12345] [-Port 8480] [-StayAwake]
    humid expose tailscale                        give it a public https address through Tailscale Funnel
    humid expose cloudflare -Token <t> -Hostname vault.example.com
    humid expose none                             local only
    humid status | start | stop | restart | logs [-Follow]
    humid set KEY=VALUE [KEY=VALUE ...]           change a setting, then restart
    humid show                                    print the settings (secret key hidden)
    humid mint 50 [batch-name]                    print 50 new access codes to sell (cash or online)
    humid backup [-Path file.zip] | restore -Path file.zip
    humid uninstall [-RemoveData]

  ("humid" works once installed. Before that, run .\humid.ps1 from the unzipped folder,
   or double-click "Install HumID Server.cmd".)
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('install', 'uninstall', 'start', 'stop', 'restart', 'status', 'logs', 'set', 'show', 'mint', 'backup', 'restore', 'expose', 'help')]
  [string]$Command = 'help',
  [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
  [string[]]$Rest = @(),
  [ValidateSet('attested', 'biometric', 'demo')]
  [string]$DevicePolicy,
  [string]$AppleTeamId,
  [int]$Port,
  [string]$NodePath,
  [string]$NodeMajor = '22',
  [string]$Token,
  [string]$Hostname,
  [string]$Path,
  [switch]$StayAwake,
  [switch]$NoStart,
  [switch]$RemoveData,
  [switch]$Follow,
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Windows PowerShell downloads crawl with the progress bar on
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Version     = '__HUMID_SERVER_VERSION__'
$TaskName    = 'HumID Server'
$ProgramFilesDir = $env:ProgramFiles; if (-not $ProgramFilesDir) { $ProgramFilesDir = 'C:\Program Files' }
$ProgramDataDir  = $env:ProgramData;  if (-not $ProgramDataDir)  { $ProgramDataDir = 'C:\ProgramData' }
$InstallDir  = Join-Path $ProgramFilesDir 'HumID Server'
$DataRoot    = Join-Path $ProgramDataDir 'HumID'
$EnvFile     = Join-Path $DataRoot 'humid.env'
$InfoFile    = Join-Path $DataRoot 'server.json'
$LogFile     = Join-Path $DataRoot 'logs\humid-server.log'
$NodeExe     = Join-Path $InstallDir 'node\node.exe'
$ServerJs    = Join-Path $InstallDir 'humid-server.mjs'
$PackageDir  = $PSScriptRoot

# Well-known SIDs, so this works on every Windows language.
$SidSystem       = 'S-1-5-18'
$SidAdmins       = 'S-1-5-32-544'
$SidLocalService = 'S-1-5-19'

# ---------------------------------------------------------------- helpers

function Say([string]$Text)  { Write-Host $Text }
function Step([string]$Text) { Write-Host "-> $Text" -ForegroundColor Cyan }
function Good([string]$Text) { Write-Host "OK $Text" -ForegroundColor Green }
function Warn([string]$Text) { Write-Host "!  $Text" -ForegroundColor Yellow }
function Die([string]$Text)  { Write-Host "X  $Text" -ForegroundColor Red; exit 1 }

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Require-Admin {
  if (-not (Test-Admin)) {
    Die "This needs administrator rights. Open Terminal (Admin) or PowerShell (Admin) and run it again."
  }
}

function Require-Installed {
  if (-not (Test-Path $ServerJs) -or -not (Test-Path $NodeExe)) { Die "HumID Server isn't installed. Run: .\humid.ps1 install" }
}

function Confirm-Yes([string]$Question, [bool]$Default = $true) {
  if ($Quiet) { return $Default }
  $hint = '[y/N]'
  if ($Default) { $hint = '[Y/n]' }
  $a = Read-Host "$Question $hint"
  if ([string]::IsNullOrWhiteSpace($a)) { return $Default }
  return $a.Trim().ToLower().StartsWith('y')
}

function Account-Of([string]$Sid) {
  return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
}

# Windows PowerShell 5.1 turns anything a program writes to stderr into an error,
# which -ErrorAction Stop makes fatal. Run programs through these instead.
function Run-Native {
  param([string]$Exe, [string[]]$Arguments = @(), [switch]$Silent)
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    if ($Silent) { & $Exe @Arguments 2>&1 | Out-Null }
    else { & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host "   $_" } }
  } finally { $ErrorActionPreference = $old }
  return $LASTEXITCODE
}

function Capture-Native {
  param([string]$Exe, [string[]]$Arguments = @())
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { $out = & $Exe @Arguments 2>$null } finally { $ErrorActionPreference = $old }
  return ($out -join "`n")
}

function Invoke-Server {
  param([string[]]$ServerArgs)
  $code = Run-Native $NodeExe (@('--no-warnings', $ServerJs) + $ServerArgs)
  if ($code -ne 0) { Die "humid-server $($ServerArgs[0]) failed (exit $code)." }
}

function Get-Setting([string]$Name, [string]$Default = '') {
  if (-not (Test-Path $EnvFile)) { return $Default }
  foreach ($line in Get-Content -LiteralPath $EnvFile) {
    if ($line -match "^\s*$Name\s*=\s*(.*?)\s*$") { if ($Matches[1] -ne '') { return $Matches[1] } }
  }
  return $Default
}

function Get-Info {
  if (-not (Test-Path $InfoFile)) { return $null }
  try { return Get-Content -LiteralPath $InfoFile -Raw | ConvertFrom-Json } catch { return $null }
}

function Test-Healthy([int]$P) {
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$P/healthz" -TimeoutSec 3
    return ($r.StatusCode -eq 200)
  } catch { return $false }
}

function Wait-Healthy([int]$Seconds = 90, [datetime]$Since = [datetime]::MinValue) {
  $p = [int](Get-Setting 'HUMID_PORT' '8480')
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    $info = Get-Info
    $fresh = $info -and ([datetime]$info.startedAt).ToUniversalTime() -ge $Since.ToUniversalTime()
    if ($fresh -and (Test-Healthy $p)) { return $true }
    Start-Sleep -Seconds 2
  }
  return $false
}

function Show-RecentErrors {
  if (Test-Path $LogFile) {
    $lines = Get-Content -LiteralPath $LogFile -Tail 400 | Where-Object { $_ -match '"level":"error"' } | Select-Object -Last 5
    if ($lines) { Warn 'Recent errors from the log:'; $lines | ForEach-Object { Say "   $_" } }
  }
}

function Start-Server {
  $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $t) { Die 'HumID Server is not installed.' }
  if ($t.State -eq 'Running' -and (Test-Healthy ([int](Get-Setting 'HUMID_PORT' '8480')))) { Good 'HumID Server is already running.'; return $true }
  $since = (Get-Date).AddSeconds(-2)
  Start-ScheduledTask -TaskName $TaskName
  Step 'Starting...'
  if (Wait-Healthy -Seconds 90 -Since $since) { Good 'HumID Server is running.'; return $true }
  Warn "It didn't come up within 90 seconds."
  Show-RecentErrors
  Say "   Full log: $LogFile"
  return $false
}

function Stop-Server {
  $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $t) { return }
  if ($t.State -eq 'Running') { Stop-ScheduledTask -TaskName $TaskName; Start-Sleep -Seconds 2 }
  # Ending the task ends node.exe; make sure nothing is left holding the databases.
  Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($ServerJs) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Set-DataAcl {
  # Only SYSTEM and Administrators (full) and the LOCAL SERVICE account the server runs as (modify).
  $code = Run-Native 'icacls.exe' @($DataRoot, '/inheritance:r', '/grant:r', "*$($SidSystem):(OI)(CI)F", "*$($SidAdmins):(OI)(CI)F", "*$($SidLocalService):(OI)(CI)M") -Silent
  if ($code -ne 0) { Die "Couldn't set permissions on $DataRoot." }
}

function Find-Tool([string]$Name, [string[]]$Candidates) {
  $c = Get-Command $Name -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  foreach ($p in $Candidates) { if ($p -and (Test-Path $p)) { return $p } }
  return $null
}

function Show-AppBuildHint {
  $info = Get-Info
  $url = Get-Setting 'HUMID_PUBLIC_URL'
  if (-not $info -or -not $url) { return }
  Say ''
  Say 'To build the phone apps for this server, set these repository variables on GitHub'
  Say '(Settings > Secrets and variables > Actions > Variables), then run Actions > Release apps:'
  Say "   HUMID_SERVER_URL = $url"
  Say "   HUMID_SERVER_KID = $($info.kid)"
}

# ---------------------------------------------------------------- Node.js runtime

function Install-Node {
  $nodeDir = Split-Path $NodeExe
  New-Item -ItemType Directory -Force -Path $nodeDir | Out-Null
  if ($NodePath) {
    if (-not (Test-Path $NodePath)) { Die "No node.exe at $NodePath" }
    Copy-Item -LiteralPath $NodePath -Destination $NodeExe -Force
    Good "Using Node.js from $NodePath ($(Capture-Native $NodeExe @('--version')))"
    return
  }
  if (Test-Path $NodeExe) {
    $have = (Capture-Native $NodeExe @('--version')).Trim()
    if ($have -like "v$NodeMajor.*") { Good "Node.js $have already installed."; return }
  }
  $arch = 'x64'
  if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
  Step "Finding the newest Node.js $NodeMajor for Windows $arch on nodejs.org..."
  $index = Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json' -TimeoutSec 60
  $rel = $index | Where-Object { $_.version -like "v$NodeMajor.*" -and ($_.files -contains "win-$arch-zip") } | Select-Object -First 1
  if (-not $rel) { Die "nodejs.org lists no Node.js $NodeMajor build for win-$arch." }
  $v = $rel.version
  $name = "node-$v-win-$arch.zip"
  $base = "https://nodejs.org/dist/$v"
  $tmp = Join-Path $env:TEMP "humid-node-$([guid]::NewGuid().ToString('N'))"
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  try {
    Step "Downloading $name..."
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $tmp $name) -TimeoutSec 600
    $sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHASUMS256.txt" -TimeoutSec 60).Content
    $line = ($sums -split "`n") | Where-Object { $_ -match "\s$([regex]::Escape($name))\s*$" } | Select-Object -First 1
    if (-not $line) { Die "SHASUMS256.txt has no entry for $name." }
    $want = ($line.Trim() -split '\s+')[0].ToLower()
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $tmp $name)).Hash.ToLower()
    if ($want -ne $got) { Die "Checksum mismatch for $name. Expected $want, got $got. Nothing was installed." }
    Good "Checksum verified ($($got.Substring(0, 16))...)."
    Expand-Archive -LiteralPath (Join-Path $tmp $name) -DestinationPath $tmp -Force
    $src = Join-Path $tmp "node-$v-win-$arch"
    Copy-Item -LiteralPath (Join-Path $src 'node.exe') -Destination $NodeExe -Force
    Copy-Item -LiteralPath (Join-Path $src 'LICENSE') -Destination (Join-Path $nodeDir 'LICENSE') -Force
    Good "Node.js $v installed."
  } finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# ---------------------------------------------------------------- commands

function Do-Install {
  Require-Admin
  if (-not [Environment]::Is64BitOperatingSystem) { Die 'HumID Server needs 64-bit Windows.' }
  Say "HumID Server for Windows $Version"
  Say ''

  $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($existing) { Step 'Updating an existing install (settings and data are kept).'; Stop-Server }

  # Program files
  $samePlace = (Resolve-Path $PackageDir).Path.TrimEnd('\') -eq $InstallDir.TrimEnd('\')
  if (-not $samePlace) {
    if (-not (Test-Path (Join-Path $PackageDir 'humid-server.mjs'))) { Die "Run this from the unzipped HumID-Server folder." }
    Step "Copying the server to $InstallDir"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Remove-Item -LiteralPath (Join-Path $InstallDir 'app') -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $PackageDir -Force | Where-Object { $_.Name -ne 'node' } |
      ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $InstallDir -Recurse -Force }
  }
  Get-ChildItem -LiteralPath $InstallDir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
  Set-Content -LiteralPath (Join-Path $InstallDir 'humid.cmd') -Encoding ASCII -Value "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0humid.ps1`" %*"
  Install-Node
  Run-Native 'icacls.exe' @($InstallDir, '/grant', "*$($SidLocalService):(OI)(CI)RX") -Silent | Out-Null

  # Data, settings, keys
  Step "Preparing $DataRoot (readable only by administrators and the server)"
  New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
  Set-DataAcl
  $sets = @()
  if ($DevicePolicy) { $sets += @('--set', "HUMID_DEVICE_POLICY=$DevicePolicy") }
  if ($AppleTeamId) {
    $team = $AppleTeamId.Trim().ToUpper()
    if ($team -notmatch '^[A-Z0-9]{10}$') { Die 'The Apple Team ID is 10 letters and digits (Apple Developer > Membership).' }
    $sets += @('--set', "HUMID_IOS_APP_ID=$team.app.humid.vault")
  }
  if ($Port) { $sets += @('--set', "HUMID_PORT=$Port") }
  Invoke-Server (@('init', '--root', $DataRoot) + $sets)
  Set-DataAcl

  # Background task: at startup, as LOCAL SERVICE, restarted if it stops.
  Step "Registering the '$TaskName' task (starts with Windows, runs as LOCAL SERVICE)"
  $account = Account-Of $SidLocalService
  $action = New-ScheduledTaskAction -Execute $NodeExe -Argument "--no-warnings `"$ServerJs`" run --service --root `"$DataRoot`"" -WorkingDirectory $InstallDir
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType ServiceAccount
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -Priority 5
  Register-ScheduledTask -TaskName $TaskName -Description "HumID vault server ($Version). Listens on 127.0.0.1; reached through a tunnel." `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

  # "humid" on the PATH for administrators' terminals
  $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($machinePath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', ($machinePath.TrimEnd(';') + ";$InstallDir"), 'Machine')
  }

  # A laptop that sleeps can't answer phones.
  $awake = $StayAwake.IsPresent
  if (-not $awake -and -not $Quiet) { $awake = Confirm-Yes 'Keep this laptop awake while it is plugged in (even with the lid closed), so phones can always reach the server?' $true }
  if ($awake) {
    Run-Native 'powercfg.exe' @('/change', 'standby-timeout-ac', '0') -Silent | Out-Null
    Run-Native 'powercfg.exe' @('/change', 'hibernate-timeout-ac', '0') -Silent | Out-Null
    Run-Native 'powercfg.exe' @('/setacvalueindex', 'SCHEME_CURRENT', 'SUB_BUTTONS', 'LIDACTION', '0') -Silent | Out-Null
    Run-Native 'powercfg.exe' @('/setactive', 'SCHEME_CURRENT') -Silent | Out-Null
    Good 'Plugged in, the laptop now stays awake (on battery it still sleeps as usual).'
  }

  if ($NoStart) { Good 'Installed. Start it with: humid start'; return }
  if (-not (Start-Server)) { exit 1 }
  Do-Status
  if (-not (Get-Setting 'HUMID_PUBLIC_URL')) {
    Say ''
    Say 'Next: give it an https address phones can reach. With Tailscale installed and signed in:'
    Say '   humid expose tailscale'
    Say '(or see README.txt for Cloudflare Tunnel with your own domain).'
  }
}

function Do-Uninstall {
  Require-Admin
  Stop-Server
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Good 'Background task removed.'
  }
  $url = Get-Setting 'HUMID_PUBLIC_URL'
  if ($url -like '*.ts.net') {
    $ts = Find-Tool 'tailscale' @("$env:ProgramFiles\Tailscale\tailscale.exe")
    if ($ts) { Run-Native $ts @('funnel', '--https=443', 'off') -Silent | Out-Null; Good 'Tailscale Funnel turned off.' }
  } elseif ($url) {
    Warn "If you set up a Cloudflare Tunnel for $url, remove it with: cloudflared service uninstall"
  }
  $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  $kept = ($machinePath -split ';') | Where-Object { $_ -and $_ -ne $InstallDir }
  [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
  if (Test-Path $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue; Good "Removed $InstallDir" }
  if ($RemoveData) {
    if ($Quiet -or (Confirm-Yes "Delete $DataRoot for good? Every account, sealed document and the server's identity will be gone." $false)) {
      Remove-Item -LiteralPath $DataRoot -Recurse -Force
      Good "Deleted $DataRoot"
    }
  } else {
    Say "Kept the data in $DataRoot (accounts, sealed documents, server keys). Reinstalling picks it up again."
  }
}

function Do-Status {
  $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $t) { Die 'HumID Server is not installed.' }
  $ti = Get-ScheduledTaskInfo -TaskName $TaskName
  $p = [int](Get-Setting 'HUMID_PORT' '8480')
  $healthy = Test-Healthy $p
  $info = Get-Info
  Say ''
  Say "HumID Server $Version"
  Say ("  Task            {0} (last result {1})" -f $t.State, $ti.LastTaskResult)
  if ($healthy) { Say "  Health          ok" } else { Say "  Health          not answering on 127.0.0.1:$p" }
  if ($info) {
    Say "  Local address   $($info.localUrl)"
    $pub = Get-Setting 'HUMID_PUBLIC_URL'
    if ($pub) { Say "  Public address  $pub" } else { Say "  Public address  (none yet: humid expose tailscale)" }
    Say "  Fingerprint     $($info.fingerprint)"
    Say "  Key id          $($info.kid)"
    Say "  Device policy   $($info.devicePolicy)"
    if ($info.iphones) { Say "  iPhones         accepted" } else { Say "  iPhones         not yet (humid set HUMID_IOS_APP_ID=<TeamID>.app.humid.vault)" }
    Say "  Running since   $($info.startedAt)"
  }
  Say "  Data            $DataRoot"
  Say "  Log             $LogFile"
  if (-not $healthy) { Show-RecentErrors }
  Show-AppBuildHint
}

function Do-Set {
  Require-Admin; Require-Installed
  if (-not $Rest -or $Rest.Count -eq 0) { Die 'Usage: humid set KEY=VALUE [KEY=VALUE ...]' }
  Invoke-Server (@('set', '--root', $DataRoot) + $Rest)
  Stop-Server
  if (-not (Start-Server)) { exit 1 }
}

function Do-Backup {
  Require-Admin; Require-Installed
  $target = $Path
  if (-not $target) { $target = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ("HumID-backup-{0}.zip" -f (Get-Date -Format 'yyyyMMdd-HHmm')) }
  Step 'Stopping the server for a consistent copy...'
  Stop-Server
  try {
    Compress-Archive -Path (Join-Path $DataRoot 'humid.env'), (Join-Path $DataRoot 'data') -DestinationPath $target -Force
    Good "Backup written to $target"
    Warn 'It holds the server keys and every sealed document. Keep it somewhere safe and offline.'
  } finally {
    Start-Server | Out-Null
  }
}

function Do-Restore {
  Require-Admin; Require-Installed
  if (-not $Path -or -not (Test-Path $Path)) { Die 'Usage: humid restore -Path <backup.zip>' }
  if (-not $Quiet -and -not (Confirm-Yes "Replace the current data in $DataRoot with $($Path)?" $false)) { return }
  Stop-Server
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $old = Join-Path $DataRoot "before-restore-$stamp"
  New-Item -ItemType Directory -Force -Path $old | Out-Null
  foreach ($n in @('humid.env', 'data')) { $f = Join-Path $DataRoot $n; if (Test-Path $f) { Move-Item -LiteralPath $f -Destination $old } }
  Expand-Archive -LiteralPath $Path -DestinationPath $DataRoot -Force
  Set-DataAcl
  Good "Restored. The previous data is in $old"
  Start-Server | Out-Null
}

function Do-Expose {
  Require-Admin; Require-Installed
  $how = 'help'
  if ($Rest -and $Rest.Count -gt 0) { $how = $Rest[0].ToLower() }
  $p = [int](Get-Setting 'HUMID_PORT' '8480')
  switch ($how) {
    'tailscale' {
      $ts = Find-Tool 'tailscale' @("$env:ProgramFiles\Tailscale\tailscale.exe")
      if (-not $ts) {
        Warn 'Tailscale is not installed.'
        Say '   1. Install it: winget install --id Tailscale.Tailscale   (or https://tailscale.com/download/windows)'
        Say '   2. Sign in from the Tailscale icon in the taskbar.'
        Say '   3. Run: humid expose tailscale'
        exit 1
      }
      $st = $null
      try { $st = Capture-Native $ts @('status', '--json') | ConvertFrom-Json } catch {}
      if (-not $st) { Die "Couldn't read Tailscale's status. Is the Tailscale service running?" }
      if ($st.BackendState -ne 'Running') { Die 'Tailscale is installed but not signed in. Sign in from the Tailscale icon in the taskbar, then run this again.' }
      $dns = ([string]$st.Self.DNSName).TrimEnd('.')
      if (-not $dns) { Die "Tailscale didn't report this computer's name." }
      Step "Turning on Tailscale Funnel: https://$dns -> 127.0.0.1:$p"
      Say '   (If your tailnet hasn''t allowed Funnel yet, Tailscale prints a link: open it, approve, and this continues.)'
      $code = Run-Native $ts @('funnel', '--bg', "$p")
      if ($code -ne 0) { Die 'Tailscale Funnel did not start. Check that HTTPS certificates and Funnel are enabled for your tailnet (login.tailscale.com > DNS and Access controls), then try again.' }
      $url = "https://$dns"
    }
    'cloudflare' {
      $cf = Find-Tool 'cloudflared' @("${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe", "$env:ProgramFiles\cloudflared\cloudflared.exe")
      if (-not $cf) { Die 'cloudflared is not installed. Install it with: winget install --id Cloudflare.cloudflared' }
      if (-not $Token -or -not $Hostname) {
        Say 'In the Cloudflare dashboard (your domain must use Cloudflare DNS):'
        Say '   Zero Trust > Networks > Tunnels > Create a tunnel > Cloudflared, name it humid, copy the token.'
        Say "   Public hostname: e.g. vault.yourdomain.com  ->  Service: HTTP  127.0.0.1:$p"
        Say 'Then run:  humid expose cloudflare -Token <token> -Hostname vault.yourdomain.com'
        exit 1
      }
      Step 'Installing the Cloudflare Tunnel service...'
      $code = Run-Native $cf @('service', 'install', $Token)
      if ($code -ne 0) { Die 'cloudflared service install failed (if a tunnel service already exists: cloudflared service uninstall, then retry).' }
      $url = "https://$($Hostname.Trim().TrimEnd('/'))"
    }
    'none' { $url = '' }
    default {
      Say 'Usage:'
      Say '   humid expose tailscale                                   free; an address like https://your-laptop.tailnet-name.ts.net'
      Say '   humid expose cloudflare -Token <t> -Hostname <host>      your own domain, e.g. https://vault.humidsecure.com'
      Say '   humid expose none                                        local only'
      return
    }
  }
  Invoke-Server @('set', '--root', $DataRoot, "HUMID_PUBLIC_URL=$url")
  Stop-Server
  if (-not (Start-Server)) { exit 1 }
  if ($url) {
    Step "Checking $url/healthz from the internet side..."
    $ok = $false
    for ($i = 0; $i -lt 20 -and -not $ok; $i++) {
      try { $r = Invoke-WebRequest -UseBasicParsing -Uri "$url/healthz" -TimeoutSec 10; $ok = ($r.StatusCode -eq 200) } catch { Start-Sleep -Seconds 5 }
    }
    if ($ok) { Good "Phones can reach $url" } else { Warn "$url doesn't answer yet. New certificates and DNS can take a few minutes; check again with: humid status" }
    if ($how -eq 'tailscale') { Warn 'In Tailscale, turn on Preferences > Run unattended, so the address keeps working when nobody is signed in to Windows.' }
  }
  Show-AppBuildHint
}

function Do-Logs {
  if (-not (Test-Path $LogFile)) { Die "No log yet at $LogFile" }
  if ($Follow) { Get-Content -LiteralPath $LogFile -Tail 60 -Wait } else { Get-Content -LiteralPath $LogFile -Tail 60 }
}

switch ($Command) {
  'install'   { Do-Install }
  'uninstall' { Do-Uninstall }
  'start'     { Require-Admin; Require-Installed; if (-not (Start-Server)) { exit 1 } }
  'stop'      { Require-Admin; Stop-Server; Good 'Stopped.' }
  'restart'   { Require-Admin; Require-Installed; Stop-Server; if (-not (Start-Server)) { exit 1 } }
  'status'    { Require-Admin; Do-Status }
  'logs'      { Require-Admin; Do-Logs }
  'set'       { Do-Set }
  'show'      { Require-Admin; Require-Installed; Invoke-Server @('show', '--root', $DataRoot) }
  'mint'      { Require-Admin; Require-Installed; Invoke-Server (@('mint', '--root', $DataRoot) + $Rest) }
  'backup'    { Do-Backup }
  'restore'   { Do-Restore }
  'expose'    { Do-Expose }
  default     { Get-Help $PSCommandPath -Detailed | Out-Host }
}
