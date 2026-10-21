<#
.SYNOPSIS
  HumID Server for Windows (__HUMID_SERVER_VERSION__): install, run and manage the HumID vault server.

.DESCRIPTION
  Runs the HumID services and a local web edge as one background task
  that starts with Windows, even when nobody is signed in. It listens on
  127.0.0.1 only; phones reach it through a tunnel (Tailscale Funnel or
  Cloudflare Tunnel), so nothing on your router needs to change.

  Beside it runs HumID Admin, the admin console (docs/ADMIN.md): server health,
  Windows and HumID updates, backups. It's on 127.0.0.1:8490 only, and every
  change it makes waits for a live check on an administrator's phone.

  With Check-in on (docs/CHECKIN.md), an armed vault's keys live in the
  server's memory only, so the commands that stop the server say how many
  vaults that would erase and go on only once you type ERASE.

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
    humid console                                 open the admin console (a sign-in link that works once)
    humid admin token <github-token>              let the console check the private repository for HumID updates
    humid admin token clear | admin repo owner/name | admin reset (forget every administrator phone)
    humid uninstall [-RemoveData]

  ("humid" works once installed. Before that, run .\humid.ps1 from the unzipped folder,
   or double-click "Install HumID Server.cmd".)
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('install', 'uninstall', 'start', 'stop', 'restart', 'status', 'logs', 'set', 'show', 'mint', 'backup', 'restore', 'expose', 'console', 'admin', 'probe', 'job-run', 'help')]
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
$AdminJs     = Join-Path $InstallDir 'humid-admin.mjs'
$AdminDir    = Join-Path $DataRoot 'admin'        # the console's own records: SYSTEM and Administrators only
$BackupDir   = Join-Path $DataRoot 'backups'      # SYSTEM and Administrators only
$AdminLog    = Join-Path $DataRoot 'admin\logs\humid-admin.log'   # beside the console's records, not in logs\ (the server writes there)
$PrevDir     = "$InstallDir.previous"             # the version before the last update, for rollback
$AdminTask   = 'HumID Admin'
$JobTask     = 'HumID Admin Job'
$BridgeDir   = Join-Path $DataRoot 'data\admin'   # where the console and the server meet (docs/ADMIN.md)
# Where the server (LOCAL SERVICE) keeps its own databases and keys: data\<service>. The only
# folders under the data root it may change, with logs\ (Set-DataAcl).
$ServerDataDirs = @('identity', 'vault', 'ledger', 'recovery', 'access', 'keyshare', 'gateway')

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

# Check-in (docs/CHECKIN.md) keeps an armed vault's keys in the server's memory only, so anything
# that stops the server erases every armed vault for good. The server writes how many are armed to
# server-status.json every 15 s; a file older than 45 s means it isn't running, and then none is left.
function Get-ArmedCount {
  $f = Join-Path $DataRoot 'server-status.json'
  try {
    $item = Get-Item -LiteralPath $f -ErrorAction Stop
    if (((Get-Date).ToUniversalTime() - $item.LastWriteTimeUtc).TotalSeconds -gt 45) { return 0 }
    $s = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
    if ($s.checkin -and $s.checkin.armed) { return [int]$s.checkin.armed }
  } catch {}
  return 0
}

# Before anything that stops the server: say how many armed vaults it would erase, and go on only
# when ERASE is typed. -Quiet goes on after the warning, as the console's approved jobs do (the
# console showed the same count before the phone approved).
function Confirm-ArmedErase([string]$What) {
  $n = Get-ArmedCount
  if ($n -le 0) { return }
  $which = if ($n -eq 1) { '1 vault is' } else { "$n vaults are" }
  Warn "Check-in: $which armed. Their keys live only in the server's memory, so $What erases them for good."
  if ($Quiet) { Warn 'Going ahead (-Quiet).'; return }
  Say '   Ask their holders to turn Check-in off first.'
  $a = $null
  try { $a = Read-Host 'Type ERASE to go ahead anyway' } catch {}
  if (("$a").Trim() -cne 'ERASE') { Die 'Stopped. Nothing was changed.' }
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

# HumID never makes a junction or a symbolic link under its data root. One there would let
# whoever made it point something HumID does as SYSTEM (a restore, an update, a backup, setting
# permissions) at another place. These check the path and every folder above it, up to the data root.
function Test-Reparse([string]$P) {
  $i = Get-Item -LiteralPath $P -Force -ErrorAction SilentlyContinue
  return [bool]($i -and ($i.Attributes -band [IO.FileAttributes]::ReparsePoint))
}

function Assert-NoReparse([string]$Path) {
  $top = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
  $p = [IO.Path]::GetFullPath($Path).TrimEnd('\')
  if (-not ($p -eq $top -or $p.StartsWith("$top\", [StringComparison]::OrdinalIgnoreCase))) { throw "$Path isn't under $DataRoot." }
  while ($true) {
    if (Test-Reparse $p) {
      throw "$p is a link (a junction or symbolic link). HumID never makes one there: something on this computer did, perhaps to redirect what HumID does as SYSTEM. Nothing was changed. Remove the link (rmdir `"$p`"), check this computer, then try again."
    }
    if ($p.Length -le $top.Length) { break }
    $p = [IO.Path]::GetDirectoryName($p)
  }
}

# Up to 2.1.0 the server's account could write anywhere under the data root, so it could have
# left links there. Take out every junction and symbolic link below $Dir: the link only, never
# what it points to, and never following one. (Other reparse points, such as a deduplicated
# file, are data and stay.)
function Remove-ReparsePoints([string]$Dir) {
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  $stack = New-Object System.Collections.Stack
  $stack.Push((Get-Item -LiteralPath $Dir -Force))
  while ($stack.Count -gt 0) {
    $d = $stack.Pop()
    foreach ($i in $d.GetFileSystemInfos()) {
      if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if (@('Junction', 'SymbolicLink') -contains [string]$i.LinkType) {
          Warn "Removing a link HumID didn't make: $($i.FullName)"
          if ($i -is [IO.DirectoryInfo]) { [IO.Directory]::Delete($i.FullName, $false) } else { [IO.File]::Delete($i.FullName) }
        }
        continue   # never walk into a reparse point
      }
      if ($i -is [IO.DirectoryInfo]) { $stack.Push($i) }
    }
  }
}

# Refuse if there is any junction or symbolic link below $Dir (for anything that would follow one).
function Assert-NoReparseBelow([string]$Dir) {
  Assert-NoReparse $Dir
  $stack = New-Object System.Collections.Stack
  $stack.Push((Get-Item -LiteralPath $Dir -Force))
  while ($stack.Count -gt 0) {
    foreach ($i in $stack.Pop().GetFileSystemInfos()) {
      if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if (@('Junction', 'SymbolicLink') -contains [string]$i.LinkType) { throw "$($i.FullName) is a link (a junction or symbolic link). HumID never makes one; nothing was backed up. Run humid install again to remove it, and check this computer." }
        continue
      }
      if ($i -is [IO.DirectoryInfo]) { $stack.Push($i) }
    }
  }
}

function Invoke-Icacls([string[]]$Arguments) {
  $code = Run-Native 'icacls.exe' $Arguments -Silent
  if ($code -ne 0) { throw "Couldn't set permissions on $($Arguments[0])." }
}

function Set-DataAcl {
  # SYSTEM and Administrators: full. The server's account (LOCAL SERVICE) reads everything here
  # (not admin\ or backups\, see Set-PrivateAcl) and changes only what it must:
  #   data\<service>          its own databases and keys
  #   logs\                   its log
  #   the data root           new files, no folders: it replaces server.json and server-status.json
  #   data\admin\approvals    new files, no folders: the drop box for approvals the console checks
  # So it can't make a folder (or a junction) anywhere SYSTEM reads, writes or unpacks into, and
  # it can't change humid.env or what the console writes. Making a symbolic link needs a right
  # it doesn't have. Run with the server stopped.
  $data = Join-Path $DataRoot 'data'
  $logs = Join-Path $DataRoot 'logs'
  $approvals = Join-Path $BridgeDir 'approvals'
  New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
  Assert-NoReparse $DataRoot
  Remove-ReparsePoints $DataRoot
  $dirs = @($data, $logs, $BridgeDir, (Join-Path $BridgeDir 'requests'), $approvals) + @($ServerDataDirs | ForEach-Object { Join-Path $data $_ })
  foreach ($d in $dirs) { Assert-NoReparse $d; New-Item -ItemType Directory -Force -Path $d | Out-Null }

  $sys = "*$($SidSystem)"; $adm = "*$($SidAdmins)"; $ls = "*$($SidLocalService)"; $creator = '*S-1-3-0'
  # Administrators own what SYSTEM uses: an owner can always rewrite permissions, and in
  # 2.1.0 and earlier the server's account made some of these folders itself.
  Invoke-Icacls @($DataRoot, '/setowner', $adm, '/C', '/Q')
  Invoke-Icacls @($DataRoot, '/inheritance:r', '/grant:r', "$($sys):(OI)(CI)F", "$($adm):(OI)(CI)F", "$($ls):(OI)(CI)RX", "$($creator):(OI)(NP)(IO)M")
  Invoke-Icacls @($DataRoot, '/grant', "$($ls):(WD)")
  # Everything else inherits from the data root again: an older version's permissions (and
  # any the server's account added as an owner) are dropped. admin\ and backups\ keep their own.
  foreach ($i in Get-ChildItem -LiteralPath $DataRoot -Force) {
    if (@('admin', 'backups') -contains $i.Name) { continue }
    Invoke-Icacls @($i.FullName, '/setowner', $adm, '/C', '/Q')
    Invoke-Icacls @($i.FullName, '/reset', '/C', '/Q')
  }
  Invoke-Icacls @($BridgeDir, '/setowner', $adm, '/T', '/C', '/Q')   # small, and free of links (above)
  Invoke-Icacls @($BridgeDir, '/reset', '/T', '/C', '/Q')
  foreach ($d in @($ServerDataDirs | ForEach-Object { Join-Path $data $_ }) + @($logs)) {
    Invoke-Icacls @($d, '/setowner', $adm, '/C', '/Q')
    Invoke-Icacls @($d, '/reset', '/C', '/Q')
    Invoke-Icacls @($d, '/grant:r', "$($ls):(OI)(CI)M")
  }
  Invoke-Icacls @($approvals, '/grant', "$($ls):(WD)", "$($creator):(OI)(NP)(IO)M")
  foreach ($n in @('server.json', 'server-status.json')) {
    $f = Join-Path $DataRoot $n
    if (Test-Path -LiteralPath $f) { Invoke-Icacls @($f, '/grant', "$($ls):M") }
  }
}

function Set-PrivateAcl([string]$Dir) {
  # SYSTEM and Administrators only: the HumID server's own account (LOCAL SERVICE) can't read it.
  Assert-NoReparse $Dir
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $code = Run-Native 'icacls.exe' @($Dir, '/setowner', "*$($SidAdmins)", '/C', '/Q') -Silent
  if ($code -eq 0) { $code = Run-Native 'icacls.exe' @($Dir, '/inheritance:r', '/grant:r', "*$($SidSystem):(OI)(CI)F", "*$($SidAdmins):(OI)(CI)F") -Silent }
  if ($code -ne 0) { throw "Couldn't set permissions on $Dir." }
}

function Stop-Admin {
  $t = Get-ScheduledTask -TaskName $AdminTask -ErrorAction SilentlyContinue
  if ($t -and $t.State -eq 'Running') { Stop-ScheduledTask -TaskName $AdminTask; Start-Sleep -Seconds 1 }
  Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($AdminJs) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Start-Admin {
  if (Get-ScheduledTask -TaskName $AdminTask -ErrorAction SilentlyContinue) { Start-ScheduledTask -TaskName $AdminTask }
}

function Register-AdminTasks {
  # The console runs as SYSTEM: it installs Windows updates and new HumID versions, but only
  # what an administrator's phone approved (docs/ADMIN.md). It listens on 127.0.0.1 only.
  $system = New-ScheduledTaskPrincipal -UserId (Account-Of $SidSystem) -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  $action = New-ScheduledTaskAction -Execute $NodeExe -Argument "--no-warnings `"$AdminJs`" run --service --root `"$DataRoot`"" -WorkingDirectory $InstallDir
  Register-ScheduledTask -TaskName $AdminTask -Description "HumID admin console ($Version). 127.0.0.1 only; changes need an administrator's phone." `
    -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $system -Settings $settings -Force | Out-Null
  # Approved work (updates, backups, restarts) runs here, apart from the console, so an
  # update can replace the console and restart it without stopping itself.
  $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $jobAction = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'humid.ps1')`" job-run" -WorkingDirectory $InstallDir
  $jobSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $JobTask -Description "HumID admin jobs: runs what an administrator approved in the console." `
    -Action $jobAction -Principal $system -Settings $jobSettings -Force | Out-Null
}

function Make-Backup([string]$Target) {
  # A consistent copy needs the databases closed: stop, zip settings + data, start again.
  New-Item -ItemType Directory -Force -Path (Split-Path $Target) | Out-Null
  Stop-Server
  try {
    Assert-NoReparseBelow (Join-Path $DataRoot 'data')   # Compress-Archive would follow a link
    Compress-Archive -Path (Join-Path $DataRoot 'humid.env'), (Join-Path $DataRoot 'data') -DestinationPath $Target -Force
  } finally { Start-Server | Out-Null }
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
  if ($existing) { Confirm-ArmedErase 'updating HumID Server'; Step 'Updating an existing install (settings and data are kept).'; Stop-Server }
  Stop-Admin

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
  Step "Preparing $DataRoot (readable only by administrators and the server; the server writes only its own data)"
  try { Set-DataAcl } catch { Die $_.Exception.Message }
  $sets = @()
  if ($DevicePolicy) { $sets += @('--set', "HUMID_DEVICE_POLICY=$DevicePolicy") }
  if ($AppleTeamId) {
    $team = $AppleTeamId.Trim().ToUpper()
    if ($team -notmatch '^[A-Z0-9]{10}$') { Die 'The Apple Team ID is 10 letters and digits (Apple Developer > Membership).' }
    $sets += @('--set', "HUMID_IOS_APP_ID=$team.app.humid.vault")
  }
  if ($Port) { $sets += @('--set', "HUMID_PORT=$Port") }
  Invoke-Server (@('init', '--root', $DataRoot) + $sets)
  try {
    Set-DataAcl
    Set-PrivateAcl $AdminDir
    Set-PrivateAcl $BackupDir
  } catch { Die $_.Exception.Message }

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
  Step "Registering '$AdminTask' (the admin console, as SYSTEM, 127.0.0.1 only) and '$JobTask'"
  Register-AdminTasks

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
  Start-Admin
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
  Confirm-ArmedErase 'uninstalling'
  Stop-Server
  Stop-Admin
  foreach ($n in @($TaskName, $AdminTask, $JobTask)) {
    if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {
      Unregister-ScheduledTask -TaskName $n -Confirm:$false
      Good "Background task '$n' removed."
    }
  }
  if (Test-Path $PrevDir) { Remove-Item -LiteralPath $PrevDir -Recurse -Force -ErrorAction SilentlyContinue }
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
      # Windows PowerShell's Remove-Item -Recurse follows junctions into what they point to: take the links out first.
      try { Assert-NoReparse $DataRoot; Remove-ReparsePoints $DataRoot } catch { Die $_.Exception.Message }
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
  if ((Get-Setting 'HUMID_CHECKIN' 'off') -eq 'on') {
    $armed = Get-ArmedCount
    if ($armed) { Say "  Check-in        on, $armed armed (anything that stops the server erases them)" } else { Say "  Check-in        on, none armed" }
  }
  $at = Get-ScheduledTask -TaskName $AdminTask -ErrorAction SilentlyContinue
  if ($at) { Say ("  Admin console   http://127.0.0.1:{0}  ({1}; open it with: humid console)" -f (Get-Setting 'HUMID_ADMIN_PORT' '8490'), $at.State) }
  else { Say "  Admin console   not installed (run humid install again)" }
  Say "  Data            $DataRoot"
  Say "  Log             $LogFile"
  if (-not $healthy) { Show-RecentErrors }
  Show-AppBuildHint
}

function Do-Set {
  Require-Admin; Require-Installed
  if (-not $Rest -or $Rest.Count -eq 0) { Die 'Usage: humid set KEY=VALUE [KEY=VALUE ...]' }
  Confirm-ArmedErase 'changing a setting, which restarts the server,'
  Invoke-Server (@('set', '--root', $DataRoot) + $Rest)
  Stop-Server
  if (-not (Start-Server)) { exit 1 }
  Stop-Admin; Start-Admin
}

function Do-Backup {
  Require-Admin; Require-Installed
  $target = $Path
  if (-not $target) { $target = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ("HumID-backup-{0}.zip" -f (Get-Date -Format 'yyyyMMdd-HHmm')) }
  Confirm-ArmedErase 'a backup, which stops the server,'
  Step 'Stopping the server for a consistent copy...'
  Make-Backup $target
  Good "Backup written to $target"
  Warn 'It holds the server keys and every sealed document. Keep it somewhere safe and offline.'
}

function Do-Restore {
  Require-Admin; Require-Installed
  if (-not $Path -or -not (Test-Path $Path)) { Die 'Usage: humid restore -Path <backup.zip>' }
  Confirm-ArmedErase 'restoring a backup'
  if (-not $Quiet -and -not (Confirm-Yes "Replace the current data in $DataRoot with $($Path)?" $false)) { return }
  try { $old = Restore-Data $Path } catch { Start-Server | Out-Null; Die $_.Exception.Message }
  Good "Restored. The previous data is in $old"
  Start-Server | Out-Null
}

# Unpack a backup into a new folder only SYSTEM and Administrators can open (under admin\),
# check it, and only then swap it in for humid.env and data\. Nothing is ever unpacked into a
# folder the server's account can write. Stops the server; returns where the old data went.
function Restore-Data([string]$Zip) {
  $workRoot = Join-Path $AdminDir 'work'
  Set-PrivateAcl $AdminDir
  Assert-NoReparse $workRoot
  New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $work = Join-Path $workRoot "restore-$stamp"
  if (Test-Path -LiteralPath $work) { throw "$work already exists." }
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    Expand-Archive -LiteralPath $Zip -DestinationPath $work
    if (-not (Test-Path -LiteralPath (Join-Path $work 'data') -PathType Container) -or -not (Test-Path -LiteralPath (Join-Path $work 'humid.env') -PathType Leaf)) {
      throw "$(Split-Path $Zip -Leaf) isn't a HumID backup (no humid.env and data folder inside). Nothing was changed."
    }
    Stop-Server
    $old = Join-Path $DataRoot "before-restore-$stamp"
    Assert-NoReparse $old
    New-Item -ItemType Directory -Force -Path $old | Out-Null
    foreach ($n in @('humid.env', 'data')) {
      $f = Join-Path $DataRoot $n
      Assert-NoReparse $f
      if (Test-Path -LiteralPath $f) { Move-Item -LiteralPath $f -Destination $old }
    }
    foreach ($n in @('humid.env', 'data')) { Move-Item -LiteralPath (Join-Path $work $n) -Destination $DataRoot }
  } finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
  Set-DataAcl
  return $old
}

function Do-Expose {
  Require-Admin; Require-Installed
  $how = 'help'
  if ($Rest -and $Rest.Count -gt 0) { $how = $Rest[0].ToLower() }
  if (@('tailscale', 'cloudflare', 'none') -contains $how) { Confirm-ArmedErase 'changing the public address, which restarts the server,' }
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

# ---------------------------------------------------------------- admin console (docs/ADMIN.md)

function New-Token {
  $bytes = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Sha256-Hex([string]$Text) {
  $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
  return (($h | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Write-JsonAtomic([string]$File, $Value) {
  $tmp = "$File.$PID.tmp"
  [IO.File]::WriteAllText($tmp, ($Value | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $tmp -Destination $File -Force
}

function Do-Console {
  Require-Admin; Require-Installed
  $t = Get-ScheduledTask -TaskName $AdminTask -ErrorAction SilentlyContinue
  if (-not $t) { Die 'The admin console is not installed yet. Run: humid install (from the HumID-Server folder of version 2.0.0 or later).' }
  if ($t.State -ne 'Running') { Step 'Starting the admin console...'; Start-ScheduledTask -TaskName $AdminTask; Start-Sleep -Seconds 3 }
  # A one-time sign-in link: only its hash is stored, it works once, for two minutes.
  $token = New-Token
  $logins = Join-Path $AdminDir 'logins'
  New-Item -ItemType Directory -Force -Path $logins | Out-Null
  $exp = [DateTimeOffset]::UtcNow.AddMinutes(2).ToUnixTimeMilliseconds()
  [IO.File]::WriteAllText((Join-Path $logins "$(Sha256-Hex $token).json"), "{`"exp`":$exp}")
  $url = "http://127.0.0.1:$(Get-Setting 'HUMID_ADMIN_PORT' '8490')/#login=$token"
  # Explorer opens it in your normal (not elevated) browser.
  try { Start-Process -FilePath 'explorer.exe' -ArgumentList $url } catch {}
  try { Set-Clipboard -Value $url } catch {}
  Good 'Opening the admin console in your browser. The link works once, for two minutes (also copied to the clipboard):'
  Say "   $url"
}

function Do-AdminCmd {
  Require-Admin; Require-Installed
  $sub = ''; if ($Rest -and $Rest.Count -gt 0) { $sub = $Rest[0].ToLower() }
  $envFile = Join-Path $AdminDir 'admin.env'
  Set-PrivateAcl $AdminDir
  switch ($sub) {
    'token' {
      $tok = ''; if ($Rest.Count -gt 1) { $tok = $Rest[1].Trim() }
      if ($tok -eq 'clear') { $tok = '' }
      elseif ($tok -notmatch '^(github_pat_|ghp_)[A-Za-z0-9_]{20,}$') {
        Say 'Make a token at github.com > Settings > Developer settings > Fine-grained tokens:'
        Say '   Repository access: only the HumID repository. Permissions: Contents, read-only. Nothing else.'
        Say 'Then run:  humid admin token github_pat_...'
        exit 1
      }
      Set-AdminSetting $envFile 'HUMID_UPDATE_TOKEN' $tok
      if ($tok) { Good 'Saved. The console can now check the repository for HumID updates (it never shows the token).' } else { Good 'Token removed.' }
    }
    'repo' {
      $r = ''; if ($Rest.Count -gt 1) { $r = $Rest[1].Trim() }
      if ($r -notmatch '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$') { Die 'Usage: humid admin repo owner/name' }
      Set-AdminSetting $envFile 'HUMID_UPDATE_REPO' $r
      Good "Updates come from github.com/$r"
    }
    'reset' {
      if (-not $Quiet -and -not (Confirm-Yes 'Forget every administrator phone? Until you add one again, nothing can be changed from the console.' $false)) { return }
      $code = Run-Native $NodeExe @('--no-warnings', $AdminJs, 'reset-admins', '--root', $DataRoot)
      if ($code -ne 0) { Die 'Reset failed.' }
    }
    default {
      Say 'Usage:'
      Say '   humid admin token <github-token>    read-only token for the private repository (HumID updates)'
      Say '   humid admin token clear'
      Say '   humid admin repo owner/name         where HumID updates come from (default dunning630/humID)'
      Say '   humid admin reset                   forget every administrator phone (break-glass)'
    }
  }
}

function Set-AdminSetting([string]$File, [string]$Name, [string]$Value) {
  $lines = @()
  if (Test-Path $File) { $lines = @(Get-Content -LiteralPath $File | Where-Object { $_ -notmatch "^\s*$Name\s*=" }) }
  if ($Value) { $lines += "$Name=$Value" }
  [IO.File]::WriteAllText($File, (($lines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
}

function Read-PackageVersion([string]$Dir) {
  $f = Join-Path $Dir 'VERSION.txt'
  if (-not (Test-Path $f)) { return $null }
  $m = [regex]::Match((Get-Content -LiteralPath $f -TotalCount 1), 'HumID Server for Windows (\d+\.\d+\.\d+)')
  if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

# One JSON line about this computer, for the admin console.
function Do-Probe {
  $o = [ordered]@{}
  $o.computer = $env:COMPUTERNAME
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $o.os = @{ caption = [string]$os.Caption; version = [string]$os.Version; build = [string]$os.BuildNumber }
    $o.lastBoot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
  } catch {}
  $o.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object {
    @{ drive = [string]$_.DeviceID; label = [string]$_.VolumeName; sizeBytes = [int64]$_.Size; freeBytes = [int64]$_.FreeSpace } })
  try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $o.defender = @{ available = $true; antivirus = [bool]$mp.AntivirusEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled; signatureAgeDays = [int]$mp.AntivirusSignatureAge; signatureVersion = [string]$mp.AntivirusSignatureVersion }
  } catch { $o.defender = @{ available = $false } }
  try { $o.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { @{ profile = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') } }) } catch { $o.firewall = @() }
  try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $o.bitlocker = @{ drive = $env:SystemDrive; status = $(if ([string]$bl.ProtectionStatus -eq 'On') { 'on' } else { 'off' }) }
  } catch { $o.bitlocker = $null }
  $reasons = @()
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component servicing' }
  $o.pendingReboot = ($reasons.Count -gt 0)
  $o.pendingRebootReasons = $reasons
  $o.tasks = @(foreach ($n in @($TaskName, $AdminTask, $JobTask)) {
    $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
    if ($t) { $i = Get-ScheduledTaskInfo -TaskName $n; @{ name = $n; state = [string]$t.State; lastResult = [int64]$i.LastTaskResult; lastRun = $(if ($i.LastRunTime) { $i.LastRunTime.ToUniversalTime().ToString('o') } else { $null }) } }
  })
  $o.installed = @{ version = (Read-PackageVersion $InstallDir) }
  $prev = Read-PackageVersion $PrevDir
  $o.previous = $(if ($prev) { @{ version = $prev } } else { $null })
  $url = Get-Setting 'HUMID_PUBLIC_URL'
  if ($url -like '*.ts.net') { $svc = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue; $o.tunnel = @{ kind = 'Tailscale'; state = $(if ($svc) { [string]$svc.Status } else { 'not installed' }) } }
  elseif ($url) { $svc = Get-Service -Name 'cloudflared' -ErrorAction SilentlyContinue; $o.tunnel = @{ kind = 'Cloudflare Tunnel'; state = $(if ($svc) { [string]$svc.Status } else { 'not installed' }) } }
  [Console]::Out.WriteLine(($o | ConvertTo-Json -Depth 6 -Compress))
}

# ---------------------------------------------------------------- approved jobs

$script:Job = $null
$script:JobFile = $null

function Job-Save { Write-JsonAtomic $script:JobFile $script:Job }
function Job-Step([string]$Msg) {
  $script:Job.steps += @(@{ t = (Get-Date).ToUniversalTime().ToString('o'); msg = $Msg })
  Job-Save
}

function Do-JobRun {
  $dir = Join-Path $AdminDir 'jobs'
  if (-not (Test-Path $dir)) { return }
  Assert-NoReparse $dir
  # A job left "running" by a process that's gone (a crash, a power cut) failed.
  foreach ($f in Get-ChildItem -LiteralPath $dir -Filter '*.json' | Where-Object { $_.Name -notlike '*.request.json' }) {
    try {
      $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
      if ($j.state -eq 'running' -and -not (Get-Process -Id $j.pid -ErrorAction SilentlyContinue)) {
        $j.state = 'failed'; $j | Add-Member -Force -NotePropertyName error -NotePropertyValue 'Interrupted (the computer restarted or the job stopped).'
        Write-JsonAtomic $f.FullName $j
      }
    } catch {}
  }
  while ($true) {
    $next = Get-ChildItem -LiteralPath $dir -Filter '*.request.json' | Sort-Object Name |
      Where-Object { -not (Test-Path (Join-Path $dir ($_.Name -replace '\.request\.json$', '.json'))) } | Select-Object -First 1
    if (-not $next) { break }
    Run-Job $next.FullName
  }
}

function Run-Job([string]$RequestFile) {
  $req = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
  $script:JobFile = $RequestFile -replace '\.request\.json$', '.json'
  $script:Job = [ordered]@{ id = $req.id; state = 'running'; pid = $PID; startedAt = (Get-Date).ToUniversalTime().ToString('o'); steps = @(); result = $null }
  Job-Save
  try {
    $result = switch ($req.type) {
      'restart-server'  { Job-Restart }
      'backup'          { Job-Backup }
      'update-humid'    { Job-Update $req.args }
      'rollback-humid'  { Job-Rollback $req.args }
      'os-scan'         { Job-OsScan }
      'os-install'      { Job-OsInstall $req.args }
      'defender-update' { Job-Defender }
      'reboot'          { Job-Reboot }
      default           { throw "Unknown job type $($req.type)" }
    }
    $script:Job.result = $result
    $script:Job.state = 'done'
  } catch {
    $script:Job.state = 'failed'
    $script:Job.error = $_.Exception.Message
  }
  $script:Job.finishedAt = (Get-Date).ToUniversalTime().ToString('o')
  Job-Save
}

function Job-Restart {
  Job-Step 'Stopping the HumID server'
  Stop-Server
  Job-Step 'Starting it again'
  if (-not (Start-Server)) { throw "The server didn't come up within 90 seconds. See $LogFile" }
  Job-Step 'It answers its health check'
  return @{ ok = $true }
}

function Prune-Backups([int]$Keep = 10) {
  Get-ChildItem -LiteralPath $BackupDir -Filter '*.zip' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -Skip $Keep |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
}

function Job-Backup([string]$Name) {
  Set-PrivateAcl $BackupDir
  if (-not $Name) { $Name = "HumID-backup-$(Get-Date -Format 'yyyyMMdd-HHmm').zip" }
  $target = Join-Path $BackupDir $Name
  Job-Step "Backing up to backups\$Name (the server stops for a moment)"
  Make-Backup $target
  if (-not (Test-Path $target)) { throw 'The backup file was not written.' }
  Job-Step ("Backup written ({0:N0} MB)" -f ((Get-Item -LiteralPath $target).Length / 1MB))
  Prune-Backups 10
  return @{ file = $Name; bytes = (Get-Item -LiteralPath $target).Length }
}

# Same server identity, the expected version, healthy: or the reason it isn't.
function Test-Updated([string]$Want, [string]$Kid, [datetime]$Since) {
  if (-not (Wait-Healthy -Seconds 120 -Since $Since)) { return "it didn't answer its health check within 2 minutes" }
  $info = Get-Info
  if ($info.version -ne $Want) { return "it reports version $($info.version), not $Want" }
  if ($Kid -and $info.kid -ne $Kid) { return "its server identity changed ($($info.kid)); phones would refuse it" }
  try {
    $keys = Invoke-RestMethod -Uri "http://127.0.0.1:$(Get-Setting 'HUMID_PORT' '8480')/htp/v1/keys" -TimeoutSec 10
    if ($Kid -and $keys.kid -ne $Kid) { return "it serves a different server key" }
  } catch { return "its key bundle doesn't answer" }
  return $null
}

function Install-Package([string]$Dir) {
  $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  return (Run-Native $ps @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Dir 'humid.ps1'), 'install', '-Quiet', '-NoStart') -Silent)
}

function Copy-Program([string]$From, [string]$To) {
  if (Test-Path $To) { Remove-Item -LiteralPath $To -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $To | Out-Null
  Get-ChildItem -LiteralPath $From -Force | Where-Object { $_.Name -ne 'node' } |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $To -Recurse -Force }
}

function Restore-Quietly([string]$Zip) {
  Restore-Data $Zip | Out-Null
}

# Switch the program to the package in $Pkg; on any failure, put $Fallback back (and the data, if needed).
function Switch-Program([string]$Pkg, [string]$Want, [string]$FallbackDir, [string]$FallbackVersion, [string]$Kid, [string]$BackupZip) {
  $since = (Get-Date).AddSeconds(-2)
  Job-Step "Installing $Want"
  $code = Install-Package $Pkg
  $problem = $null
  if ($code -ne 0) { $problem = "the installer stopped (exit $code)" }
  else {
    Start-Server | Out-Null
    $problem = Test-Updated $Want $Kid $since
  }
  if (-not $problem) { Start-Admin; Job-Step "$Want is running with the same server identity"; return }

  Job-Step "$Want didn't work: $problem. Putting $FallbackVersion back"
  $since = (Get-Date).AddSeconds(-2)
  $code = Install-Package $FallbackDir
  Start-Server | Out-Null
  $again = $null
  if ($code -ne 0) { $again = "the installer stopped (exit $code)" } else { $again = Test-Updated $FallbackVersion $Kid $since }
  if ($again) {
    Job-Step "$FallbackVersion didn't come up either ($again). Restoring the data from the backup taken first"
    Restore-Quietly $BackupZip
    $since = (Get-Date).AddSeconds(-2)
    Start-Server | Out-Null
    $again = Test-Updated $FallbackVersion $Kid $since
  }
  Start-Admin
  if ($again) { throw "$Want failed ($problem), and so did putting $FallbackVersion back ($again). Run humid status in Terminal (Admin); the backup is backups\$(Split-Path $BackupZip -Leaf)." }
  throw "$Want failed ($problem). $FallbackVersion is running again; nothing was lost."
}

# The zip must carry a signature by a HumID release key that the installed console pins
# (release-keys.mjs), for exactly this file and version. GitHub's digest and the phone's
# approval prove which bytes; this proves who made them. Checked right before unpacking.
function Assert-ReleaseSignature([string]$Zip, [string]$Want) {
  $out = Capture-Native $NodeExe @('--no-warnings', $AdminJs, 'verify-release', '--zip', $Zip, '--version', $Want)
  $code = $LASTEXITCODE
  $line = @(("$out" -split "`n") | Where-Object { $_.Trim() }) | Select-Object -Last 1
  if ($code -ne 0) {
    if (-not $line) { $line = "The release signature couldn't be checked (exit $code). Nothing was installed." }
    throw $line
  }
  return $line
}

function Job-Update($A) {
  $file = [string]$A.file
  if ($file -notmatch '^HumID-Server-Windows-\d+\.\d+\.\d+\.zip$') { throw 'Bad update file name.' }
  $zip = Join-Path $AdminDir "downloads\$file"
  Assert-NoReparse $zip
  Assert-NoReparse "$zip.sig"
  if (-not (Test-Path $zip)) { throw "$file isn't in the console's downloads." }
  Job-Step 'Checking the file against the approved SHA-256'
  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLower()
  if ($got -ne ([string]$A.sha256).ToLower()) { throw "The file changed since it was approved (SHA-256 $($got.Substring(0, 16))...). Nothing was installed." }
  Job-Step 'Checking its HumID release signature'
  Job-Step (Assert-ReleaseSignature $zip ([string]$A.version))
  $work = Join-Path $AdminDir "work\$($script:Job.id)"
  Assert-NoReparse $work
  if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
  Expand-Archive -LiteralPath $zip -DestinationPath $work -Force
  $pkg = Join-Path $work 'HumID-Server'
  $v = Read-PackageVersion $pkg
  if ($v -ne [string]$A.version) { throw "The zip holds version $v, not $($A.version)." }
  foreach ($need in @('humid.ps1', 'humid-server.mjs', 'humid-admin.mjs')) { if (-not (Test-Path (Join-Path $pkg $need))) { throw "The zip has no $need." } }
  Get-ChildItem -LiteralPath $pkg -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
  $from = Read-PackageVersion $InstallDir
  $kid = (Get-Info).kid
  $backup = Job-Backup "pre-update-$from-to-$v-$(Get-Date -Format 'yyyyMMdd-HHmm').zip"
  Job-Step "Keeping $from for rollback"
  Copy-Program $InstallDir $PrevDir
  Switch-Program $pkg $v $PrevDir $from $kid (Join-Path $BackupDir $backup.file)
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  return @{ from = $from; to = $v }
}

function Job-Rollback($A) {
  $to = Read-PackageVersion $PrevDir
  if (-not $to -or $to -ne [string]$A.to) { throw "The kept version is $to, not $($A.to)." }
  $from = Read-PackageVersion $InstallDir
  $kid = (Get-Info).kid
  $backup = Job-Backup "pre-rollback-$from-to-$to-$(Get-Date -Format 'yyyyMMdd-HHmm').zip"
  $current = "$InstallDir.rollback"
  Job-Step "Keeping $from aside"
  Copy-Program $InstallDir $current
  Switch-Program $PrevDir $to $current $from $kid (Join-Path $BackupDir $backup.file)
  # Now $from is the one kept, so it can be rolled forward again.
  Copy-Program $current $PrevDir
  Remove-Item -LiteralPath $current -Recurse -Force -ErrorAction SilentlyContinue
  return @{ from = $from; to = $to }
}

function New-UpdateSession {
  $s = New-Object -ComObject Microsoft.Update.Session
  $s.ClientApplicationID = 'HumID Admin'
  return $s
}

function Job-OsScan {
  $out = Join-Path $AdminDir 'os-updates.json'
  Job-Step 'Asking Windows Update'
  try {
    $session = New-UpdateSession
    $searcher = $session.CreateUpdateSearcher()
    $r = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $list = @(foreach ($u in $r.Updates) {
      $cats = @($u.Categories | ForEach-Object { [string]$_.Name })
      $sev = [string]$u.MsrcSeverity
      @{
        id = [string]$u.Identity.UpdateID; title = [string]$u.Title; kb = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
        severity = $sev; categories = $cats; security = (($cats -contains 'Security Updates') -or ($cats -contains 'Critical Updates') -or [bool]$sev)
        sizeMB = [math]::Round($u.MaxDownloadSize / 1MB); downloaded = [bool]$u.IsDownloaded
        rebootRequired = ([int]$u.InstallationBehavior.RebootBehavior -ne 0)
        published = $(try { $u.LastDeploymentChangeTime.ToUniversalTime().ToString('o') } catch { $null })
      }
    })
    $last = $null
    $n = $searcher.GetTotalHistoryCount()
    if ($n -gt 0) {
      foreach ($h in $searcher.QueryHistory(0, [Math]::Min($n, 20))) { if ($h.ResultCode -eq 2 -and $h.Title) { $last = @{ title = [string]$h.Title; date = $h.Date.ToUniversalTime().ToString('o') }; break } }
    }
    Write-JsonAtomic $out @{ checkedAt = (Get-Date).ToUniversalTime().ToString('o'); updates = $list; lastInstalled = $last }
    Job-Step "$($list.Count) update(s) available"
    return @{ count = $list.Count }
  } catch {
    Write-JsonAtomic $out @{ checkedAt = (Get-Date).ToUniversalTime().ToString('o'); updates = @(); error = $_.Exception.Message }
    throw
  }
}

function Job-OsInstall($A) {
  $ids = @($A.updates | ForEach-Object { [string]$_.id })
  $session = New-UpdateSession
  Job-Step 'Finding the approved updates'
  $r = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $coll = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $r.Updates) {
    if ($ids -contains [string]$u.Identity.UpdateID) {
      if (-not $u.EulaAccepted) { $u.AcceptEula() }
      $coll.Add($u) | Out-Null
    }
  }
  if ($coll.Count -eq 0) { Job-OsScan | Out-Null; throw 'None of the approved updates are still needed.' }
  Job-Step "Downloading $($coll.Count) update(s)"
  $d = $session.CreateUpdateDownloader(); $d.Updates = $coll; $d.Download() | Out-Null
  Job-Step 'Installing'
  $i = $session.CreateUpdateInstaller(); $i.Updates = $coll
  $res = $i.Install()
  $ok = 0; $bad = @()
  for ($k = 0; $k -lt $coll.Count; $k++) {
    $rc = $res.GetUpdateResult($k).ResultCode
    if ($rc -eq 2 -or $rc -eq 3) { $ok++ } else { $bad += [string]$coll.Item($k).Title }
  }
  Job-Step "$ok installed$(if ($bad.Count) { ", $($bad.Count) failed" })$(if ($res.RebootRequired) { '; Windows needs a restart to finish' })"
  Job-OsScan | Out-Null
  if ($bad.Count -and -not $ok) { throw "Windows Update couldn't install: $($bad -join '; ')" }
  return @{ installed = $ok; failed = $bad; rebootRequired = [bool]$res.RebootRequired }
}

function Job-Defender {
  Job-Step 'Updating Microsoft Defender definitions'
  Update-MpSignature -ErrorAction Stop
  $mp = Get-MpComputerStatus
  Job-Step "Definitions $($mp.AntivirusSignatureVersion)"
  return @{ version = [string]$mp.AntivirusSignatureVersion }
}

function Job-Reboot {
  Job-Step 'Restarting this computer in 60 seconds'
  $code = Run-Native 'shutdown.exe' @('/r', '/t', '60', '/d', 'p:2:17', '/c', 'HumID: restarting to finish updates, as approved on an administrator''s phone.') -Silent
  if ($code -ne 0) { throw "shutdown.exe refused (exit $code)." }
  return @{ at = (Get-Date).AddSeconds(60).ToUniversalTime().ToString('o') }
}

switch ($Command) {
  'install'   { Do-Install }
  'uninstall' { Do-Uninstall }
  'start'     { Require-Admin; Require-Installed; if (-not (Start-Server)) { exit 1 } }
  'stop'      { Require-Admin; Confirm-ArmedErase 'stopping the server'; Stop-Server; Good 'Stopped.' }
  'restart'   { Require-Admin; Require-Installed; Confirm-ArmedErase 'restarting the server'; Stop-Server; if (-not (Start-Server)) { exit 1 } }
  'status'    { Require-Admin; Do-Status }
  'logs'      { Require-Admin; Do-Logs }
  'set'       { Do-Set }
  'show'      { Require-Admin; Require-Installed; Invoke-Server @('show', '--root', $DataRoot) }
  'mint'      { Require-Admin; Require-Installed; Invoke-Server (@('mint', '--root', $DataRoot) + $Rest) }
  'backup'    { Do-Backup }
  'restore'   { Do-Restore }
  'expose'    { Do-Expose }
  'console'   { Do-Console }
  'admin'     { Do-AdminCmd }
  'probe'     { Do-Probe }
  'job-run'   { Require-Admin; Do-JobRun }
  default     { Get-Help $PSCommandPath -Detailed | Out-Host }
}
