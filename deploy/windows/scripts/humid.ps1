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

  Backups are encrypted to a backup key whose private half you keep off this computer
  (humid backup-key new -Path <file>), keyshare's half in a file of its own; this computer can
  make backups but not open them. Server secrets are sealed with DPAPI. Only updates signed by
  the HumID release key are installed. Roles can run on separate machines with
  mutual TLS between them (docs/DEPLOY-VMS.md).

  Run from Terminal (Admin):
    humid install [-DevicePolicy attested|biometric|demo] [-AppleTeamId ABCDE12345] [-Port 8480] [-AdminPort 8490] [-StayAwake]
    humid expose tailscale                        give it a public https address through Tailscale Funnel
    humid expose cloudflare -Token <t> -Hostname vault.example.com
    humid expose none                             local only
    humid status | start | stop | restart | logs [-Follow]
    humid set KEY=VALUE [KEY=VALUE ...]           change a setting, then restart
    humid show                                    print the settings (secret key hidden)
    humid mint 50 [batch-name]                    print 50 new access codes to sell (cash or online)
    humid backup-key new -Path E:\humid-backup.key [-Replace]   once: make the backup key. Its private key goes to the
                                                  file you name (a USB drive); only its public key stays here
    humid backup-key [show] | backup-key keyshare <folder>|default   the backup key, and where the console puts keyshare's half
    humid backup [-Path <file or folder>] [-KeysharePath <file>]   encrypted to the backup key; keyshare's data goes
                                                  to its own file (put it on another disk)
    humid restore -Path <backup.humidbak> -KeysharePath <keyshare.humidbak> -Key <backup key file>
                                                  (-KeysharePath and -Key alone: keyshare's half only, for a keys machine;
                                                   -Path <backup.zip>: a backup from HumID 2.x)
    humid pki init | status | issue core|keys -Path <dir> | import -Path <dir>   roles on separate machines
    humid selftest                                run the end-to-end self-test against this server
    humid console                                 open the admin console (a sign-in link that works once)
    humid admin token <github-token>              let the console check the private repository for HumID updates
    humid admin token clear | admin repo owner/name | admin reset (forget every administrator phone)
    humid uninstall [-RemoveData]

  A test instance beside the live server (its own folders, data, ports and tasks; plain "humid"
  still means the default install):
    .\humid.ps1 install -Instance test -Port 8580 -DevicePolicy biometric
    & "C:\Program Files\HumID Server (test)\humid.cmd" status | selftest | uninstall -RemoveData

  ("humid" works once installed. Before that, run .\humid.ps1 from the unzipped folder,
   or double-click "Install HumID Server.cmd".)
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('install', 'uninstall', 'start', 'stop', 'restart', 'status', 'logs', 'set', 'show', 'mint', 'backup', 'restore', 'backup-key', 'pki', 'selftest', 'expose', 'console', 'admin', 'probe', 'job-run', 'help')]
  [string]$Command = 'help',
  [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
  [string[]]$Rest = @(),
  [ValidateSet('attested', 'biometric', 'demo')]
  [string]$DevicePolicy,
  [string]$AppleTeamId,
  [int]$Port,
  [int]$AdminPort,
  [string]$Instance,
  [string]$NodePath,
  [string]$NodeMajor = '22',
  [string]$Token,
  [string]$Hostname,
  [string[]]$Path,
  [string]$KeysharePath,
  [string]$Key,
  [switch]$StayAwake,
  [switch]$NoStart,
  [switch]$RemoveData,
  [switch]$Follow,
  [switch]$Replace,
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
# Started from PowerShell 7 (Windows Terminal's default, or `humid` typed in it), Windows PowerShell 5.1
# inherits PowerShell 7's module folders and then can't load its own built-in commands (Get-FileHash,
# among others: "is not recognized"). Keep only Windows PowerShell's own module folders.
if ($PSVersionTable.PSVersion.Major -le 5 -and $env:PSModulePath) {
  $env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\' }) -join ';'
}
$ProgressPreference = 'SilentlyContinue'   # Windows PowerShell downloads crawl with the progress bar on
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Version     = '__HUMID_SERVER_VERSION__'

# Side by side: an instance (say, version 3.0 tried out beside the live server) has its own tasks,
# program folder, data folder and ports, every name ending in " (<name>)". The instance's copy of
# this script finds its name in instance.txt beside it, so its humid.cmd needs no flag. With neither
# -Instance nor instance.txt, every name below is what it always was: the default install.
if (-not $Instance -and $PSScriptRoot) {
  $instanceFile = Join-Path $PSScriptRoot 'instance.txt'
  if (Test-Path -LiteralPath $instanceFile) {
    $Instance = ('' + (Get-Content -LiteralPath $instanceFile -TotalCount 1)).Trim()   # '' + : an empty file gives $null
    # Never fall back to the default install from an instance's own folder: that would act on the live server.
    if (-not $Instance) { Write-Host "X  $instanceFile is empty; it should name this instance. Install the instance again with -Instance <name>." -ForegroundColor Red; exit 1 }
  }
}
if ($Instance -and $Instance -cnotmatch '^[a-z][a-z0-9]{0,15}$') {
  Write-Host "X  An instance name is 1 to 16 lower-case letters and digits, starting with a letter (for example: test). `"$Instance`" isn't one." -ForegroundColor Red
  exit 1
}
$Suffix      = ''
if ($Instance) { $Suffix = " ($Instance)" }

$TaskName    = "HumID Server$Suffix"
$ProgramFilesDir = $env:ProgramFiles; if (-not $ProgramFilesDir) { $ProgramFilesDir = 'C:\Program Files' }
$ProgramDataDir  = $env:ProgramData;  if (-not $ProgramDataDir)  { $ProgramDataDir = 'C:\ProgramData' }
$InstallDir  = Join-Path $ProgramFilesDir "HumID Server$Suffix"
$DataRoot    = Join-Path $ProgramDataDir 'HumID'
if ($Instance) { $DataRoot = Join-Path $ProgramDataDir "HumID-$Instance" }
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
$AdminTask   = "HumID Admin$Suffix"
$JobTask     = "HumID Admin Job$Suffix"
# How to run this install's commands in messages: "humid" (on the PATH) is the default install's;
# an instance is run through its own humid.cmd.
$HumidCmd    = 'humid'
if ($Instance) { $HumidCmd = "& `"$(Join-Path $InstallDir 'humid.cmd')`"" }
# -Path as one string: humid.cmd (powershell -File) passes "a,b" as one value, a PowerShell prompt as two.
$PathText    = (@($Path) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() }) -join ','
$BridgeDir   = Join-Path $DataRoot 'data\admin'   # where the console and the server meet (docs/ADMIN.md)
# Where the server (LOCAL SERVICE) keeps its own databases and keys: data\<service>. The only
# folders under the data root it may change, with logs\ (Set-DataAcl).
$ServerDataDirs = @('identity', 'vault', 'ledger', 'recovery', 'access', 'keyshare', 'relay', 'gateway')

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
  $how = '.\humid.ps1 install'
  if ($Instance) { $how += " -Instance $Instance" }
  if (-not (Test-Path $ServerJs) -or -not (Test-Path $NodeExe)) { Die "$TaskName isn't installed. Run: $how" }
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

# Run humid-server.mjs and keep what it printed, for the commands whose answer this script reads
# (one JSON line, an access code): the exit code, stdout lines, stderr lines.
function Invoke-ServerCapture {
  param([string[]]$ServerArgs)
  $all = $null
  $code = 1
  $out = @(); $err = @()
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $a = @('--no-warnings', $ServerJs) + $ServerArgs
    $all = & $NodeExe @a 2>&1
    $code = $LASTEXITCODE
  } catch { $err += $_.Exception.Message }   # node.exe missing: say so, don't stop (humid status still shows the rest)
  finally { $ErrorActionPreference = $old }
  foreach ($l in $all) {
    if ($l -is [System.Management.Automation.ErrorRecord]) { $err += $l.ToString() } else { $out += [string]$l }
  }
  return [pscustomobject]@{ Code = $code; Out = $out; Err = $err }
}

# The last line of a command's output that is a JSON object, parsed; $null if there is none.
function Get-JsonLine($Lines) {
  $line = @($Lines | Where-Object { ([string]$_).Trim().StartsWith('{') }) | Select-Object -Last 1
  if (-not $line) { return $null }
  try { return ($line | ConvertFrom-Json) } catch { return $null }
}

# What went wrong, in one line: the first line humid-server wrote to stderr (a stack trace's first
# line is its message), without the "Error:" in front.
function Get-Reason($Result) {
  $first = @(@($Result.Err) + @($Result.Out) | Where-Object { ([string]$_).Trim() }) | Select-Object -First 1
  if (-not $first) { return "exit $($Result.Code)" }
  return (([string]$first).Trim() -replace '^\w*Error:\s*', '')
}

# A full path for a -Path value, relative to the current folder; it doesn't have to exist yet.
function Get-FullPath([string]$P) {
  return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($P)
}

# Run a humid-admin.mjs command (backups, the backup key) and collect what it prints: plain
# lines, "Warning: ..." for warnings, and on failure a last line saying why.
function Invoke-AdminJs([string[]]$Arguments) {
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { $lines = @(& $NodeExe (@('--no-warnings', $AdminJs) + $Arguments) 2>&1 | ForEach-Object { "$_" }) }
  finally { $ErrorActionPreference = $old }
  return [pscustomobject]@{ Code = $LASTEXITCODE; Lines = $lines }
}

function Show-AdminLines([string[]]$Lines) {
  foreach ($l in $Lines) {
    if ($l -like 'Warning: *') { Warn $l.Substring(9) }
    elseif (-not $l.StartsWith('{')) { Say "   $l" }   # a line starting with { is the summary for jobs
  }
}

# Why a humid-admin.mjs command failed: its last line.
function Why-AdminFailed($R) {
  $why = @($R.Lines) | Where-Object { $_.Trim() } | Select-Object -Last 1
  if ($why) { return $why } else { return "humid-admin.mjs stopped (exit $($R.Code))." }
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

# The roles this machine runs (docs/DEPLOY-VMS.md): front (edge + gateway), core, keys. What the
# server reported when it last started, else the setting; all three unless split.
function Get-Roles {
  $info = Get-Info
  if ($info -and $info.roles) { return @($info.roles | ForEach-Object { ([string]$_).Trim().ToLower() }) }
  return @((Get-Setting 'HUMID_ROLES' 'front,core,keys') -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
}

# Tailscale Funnel gives this computer one public address. The other HumID installs here (the
# default one, instances) whose public address is on it, so one never takes Funnel from another,
# or turns it off under it, by accident.
function Get-OtherFunnelUsers {
  $roots = @(Join-Path $ProgramDataDir 'HumID') + @(Get-ChildItem -LiteralPath $ProgramDataDir -Directory -Filter 'HumID-*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
  $names = @()
  foreach ($r in $roots) {
    if ($r.TrimEnd('\') -eq $DataRoot.TrimEnd('\')) { continue }
    $f = Join-Path $r 'humid.env'
    $lines = @()
    try { if (Test-Path -LiteralPath $f) { $lines = @(Get-Content -LiteralPath $f) } } catch {}
    foreach ($line in $lines) {
      if ($line -match '^\s*HUMID_PUBLIC_URL\s*=\s*(\S+)\s*$' -and $Matches[1] -like '*.ts.net') {
        $leaf = Split-Path $r -Leaf
        if ($leaf -eq 'HumID') { $names += 'HumID Server' } else { $names += "HumID Server ($($leaf.Substring(6)))" }
      }
    }
  }
  return $names
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
  if (-not $t) { Die "$TaskName is not installed." }
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
# left links there. Take out every junction and symbolic link below $Dir (any folder that is a
# reparse point counts): the link only, never what it points to, and never following one. (A
# file that's another kind of reparse point, such as a deduplicated file, is data and stays.)
function Test-Link($Item) {
  return ($Item -is [IO.DirectoryInfo]) -or (@('Junction', 'SymbolicLink') -contains [string]$Item.LinkType)
}

function Remove-ReparsePoints([string]$Dir) {
  if (-not (Test-Path -LiteralPath $Dir)) { return }
  $stack = New-Object System.Collections.Stack
  $stack.Push((Get-Item -LiteralPath $Dir -Force))
  while ($stack.Count -gt 0) {
    $d = $stack.Pop()
    foreach ($i in $d.GetFileSystemInfos()) {
      if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        if (Test-Link $i) {
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
        if (Test-Link $i) { throw "$($i.FullName) is a link (a junction or symbolic link). HumID never makes one; nothing was backed up. Run humid install again to remove it, and check this computer." }
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
  # The server rewrites these through a .tmp file (a leftover .tmp too, or it couldn't start).
  foreach ($n in @('server.json', 'server-status.json', 'server.json.tmp', 'server-status.json.tmp')) {
    $f = Join-Path $DataRoot $n
    if (Test-Path -LiteralPath $f) { Invoke-Icacls @($f, '/grant', "$($ls):M") }
  }
}

function Set-PrivateAcl([string]$Dir) {
  # SYSTEM and Administrators only: the HumID server's own account (LOCAL SERVICE) can't read it.
  # Under the data root, no link on the way (a folder elsewhere, such as a pki bundle, is the administrator's choice).
  $top = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
  $full = [IO.Path]::GetFullPath($Dir).TrimEnd('\')
  if ($full -eq $top -or $full.StartsWith("$top\", [StringComparison]::OrdinalIgnoreCase)) { Assert-NoReparse $Dir }
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $code = Run-Native 'icacls.exe' @($Dir, '/setowner', "*$($SidAdmins)", '/C', '/Q') -Silent
  if ($code -eq 0) { $code = Run-Native 'icacls.exe' @($Dir, '/inheritance:r', '/grant:r', "*$($SidSystem):(OI)(CI)F", "*$($SidAdmins):(OI)(CI)F") -Silent }
  if ($code -ne 0) { throw "Couldn't set permissions on $Dir." }
}

# A moved file or folder keeps the permissions of the place it came from: make it inherit from where it is now.
function Reset-Inherited([string]$Item) {
  $a = @($Item, '/reset', '/C', '/Q')
  if (Test-Path -LiteralPath $Item -PathType Container) { $a += '/T' }   # /T on a file would match that name in every folder below
  $code = Run-Native 'icacls.exe' $a -Silent
  if ($code -ne 0) { Warn "Couldn't reset the permissions of $Item (icacls exit $code)." }
}

# Server 3.0 test builds kept a backup key on this computer (backup-key\, sealed with DPAPI), so
# the server could open its own backups. Since 3.1 (PC-10) the backup key's private half is kept
# off the computer, and nothing here can open a backup: that old key goes. (So do the 3.0 test
# builds' backups: 3.1 can't read their format. Make a new backup after installing.)
function Remove-OldBackupKey {
  $dir = Join-Path $DataRoot 'backup-key'
  if (-not (Test-Path -LiteralPath $dir)) { return }
  Assert-NoReparse $dir
  Remove-ReparsePoints $dir   # Windows PowerShell's Remove-Item -Recurse would follow one
  Warn "Removing $dir, the backup key a 3.0 test build kept on this computer: backups are now encrypted to a key you keep off it."
  Say "   Make one: $HumidCmd backup-key new -Path E:\humid-backup.key (a USB drive). Backups from the 3.0 test build can't be restored by this version."
  Remove-Item -LiteralPath $dir -Recurse -Force
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
  $jobArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'humid.ps1')`" job-run"
  # An instance's script also knows its name from instance.txt beside it; saying it here as well
  # means a job can never run against the default install's data.
  if ($Instance) { $jobArgs += " -Instance $Instance" }
  $jobAction = New-ScheduledTaskAction -Execute $ps -Argument $jobArgs -WorkingDirectory $InstallDir
  $jobSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $JobTask -Description "HumID admin jobs: runs what an administrator approved in the console." `
    -Action $jobAction -Principal $system -Settings $jobSettings -Force | Out-Null
}

# Backups (docs/ADMIN.md, "Backups") are written by humid-admin.mjs with the databases closed:
# check first (no backup key, a file already there) without stopping anything, then stop the
# server, write, and start it again. Every lasting backup is encrypted to the backup key, and
# keyshare's data goes to its own file. Returns what it printed.
function Make-Backup([string[]]$BackupArgs) {
  $base = @('backup', '--root', $DataRoot) + $BackupArgs
  $check = Invoke-AdminJs ($base + @('--check'))
  if ($check.Code -ne 0) { throw (Why-AdminFailed $check) }
  Stop-Server
  try { $r = Invoke-AdminJs $base }
  finally { Start-Server | Out-Null }
  if ($r.Code -ne 0) { throw (Why-AdminFailed $r) }
  return $r.Lines
}

function Move-Into([string]$From, [string]$To) {
  New-Item -ItemType Directory -Force -Path (Split-Path $To) | Out-Null
  Move-Item -LiteralPath $From -Destination $To
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
  if (-not $info -or -not $url -or -not $info.kid) { return }   # no kid: this machine has no front role
  Say ''
  Say 'To build the phone apps for this server, set these repository variables on GitHub'
  Say '(Settings > Secrets and variables > Actions > Variables), then run Actions > Release apps:'
  Say "   HUMID_SERVER_URL = $url"
  Say "   HUMID_SERVER_KID = $($info.kid)"
}

# After a fresh install: backups wait until there is a backup key, so say how to make one.
function Show-BackupKeyHint {
  Say ''
  Warn 'Backups wait until you make a backup key. Its private key goes to a file you keep off this computer:'
  Say "   $HumidCmd backup-key new -Path E:\humid-backup.key   (a USB drive; keep a second copy somewhere safe)"
}

# How to reach an instance: plain "humid" is the default install's.
function Show-InstanceHint {
  if (-not $Instance) { return }
  Say ''
  Say "This is the instance '$Instance'. Plain ""humid"" still means the default install; run this one's commands with its own humid.cmd:"
  Say "   $HumidCmd status"
  Say "   $HumidCmd selftest"
  Say "   $HumidCmd uninstall -RemoveData"
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
  if ($Instance) { Say "HumID Server for Windows $Version, instance '$Instance' ($InstallDir, data in $DataRoot)" }
  else { Say "HumID Server for Windows $Version" }
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
  # The instance's copy of this script reads its name from here (its humid.cmd, its job task).
  if ($Instance) { Set-Content -LiteralPath (Join-Path $InstallDir 'instance.txt') -Encoding ASCII -Value $Instance }
  Install-Node
  Run-Native 'icacls.exe' @($InstallDir, '/grant', "*$($SidLocalService):(OI)(CI)RX") -Silent | Out-Null

  # Data, settings, keys
  Step "Preparing $DataRoot (readable only by administrators and the server; the server writes only its own data)"
  $fresh = -not (Test-Path $EnvFile)
  # (the old key goes before Set-DataAcl, which would open its folder to the server's account)
  try { Remove-OldBackupKey; Set-DataAcl } catch { Die $_.Exception.Message }
  $sets = @()
  if ($DevicePolicy) { $sets += @('--set', "HUMID_DEVICE_POLICY=$DevicePolicy") }
  if ($AppleTeamId) {
    $team = $AppleTeamId.Trim().ToUpper()
    if ($team -notmatch '^[A-Z0-9]{10}$') { Die 'The Apple Team ID is 10 letters and digits (Apple Developer > Membership).' }
    $sets += @('--set', "HUMID_IOS_APP_ID=$team.app.humid.vault")
  }
  $serverPort = $Port; $consolePort = $AdminPort
  if ($Instance -and $fresh) {
    # A new instance must not take the default install's ports (8480, 8490).
    if (-not $serverPort) { $serverPort = 8580 }
    if (-not $consolePort) { $consolePort = 8590 }
  }
  if ($serverPort) { $sets += @('--set', "HUMID_PORT=$serverPort") }
  if ($consolePort) { $sets += @('--set', "HUMID_ADMIN_PORT=$consolePort") }
  # init also makes the seal key (keys\, read by the server). The backup key isn't made here: its
  # private half belongs off this computer (humid backup-key new -Path <file>).
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

  # "humid" on the PATH for administrators' terminals: the default install's only, so "humid"
  # always means the live server. An instance is run through its own humid.cmd.
  if (-not $Instance) {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (($machinePath -split ';') -notcontains $InstallDir) {
      [Environment]::SetEnvironmentVariable('Path', ($machinePath.TrimEnd(';') + ";$InstallDir"), 'Machine')
    }
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

  # A new server has no backup key yet: say how to make one.
  $showKey = $fresh -and -not $Quiet
  if ($NoStart) { Good "Installed. Start it with: $HumidCmd start"; Show-InstanceHint; if ($showKey) { Show-BackupKeyHint }; return }
  if (-not (Start-Server)) { if ($showKey) { Show-BackupKeyHint }; exit 1 }
  Start-Admin
  Do-Status
  if (-not (Get-Setting 'HUMID_PUBLIC_URL') -and ((Get-Roles) -contains 'front')) {
    Say ''
    Say 'Next: give it an https address phones can reach. With Tailscale installed and signed in:'
    Say "   $HumidCmd expose tailscale"
    Say '(or see README.txt for Cloudflare Tunnel with your own domain).'
  }
  Show-InstanceHint
  if ($showKey) { Show-BackupKeyHint }
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
    # Funnel is one address for the whole computer: leave it on while another HumID install here uses it.
    $others = @(Get-OtherFunnelUsers)
    if ($others.Count) { Say "Tailscale Funnel stays on: $($others -join ', ') on this computer uses it." }
    else {
      $ts = Find-Tool 'tailscale' @("$env:ProgramFiles\Tailscale\tailscale.exe")
      if ($ts) { Run-Native $ts @('funnel', '--https=443', 'off') -Silent | Out-Null; Good 'Tailscale Funnel turned off.' }
    }
  } elseif ($url) {
    if ($Instance) { Warn "If you added $url to a Cloudflare Tunnel, remove that public hostname in the Cloudflare dashboard (the tunnel may serve another HumID server too)." }
    else { Warn "If you set up a Cloudflare Tunnel for $url, remove it with: cloudflared service uninstall" }
  }
  # Only the default install is on the PATH; an instance never touches it.
  if (-not $Instance) {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $kept = ($machinePath -split ';') | Where-Object { $_ -and $_ -ne $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
  }
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

# Which of the server's secrets are sealed under the seal key (DPAPI on Windows).
function Show-SealStatus {
  $r = Invoke-ServerCapture @('seal-status', '--root', $DataRoot)
  $s = Get-JsonLine $r.Out
  if ($r.Code -ne 0 -or -not $s) { Write-Host "  Secrets         couldn't check ($(Get-Reason $r))" -ForegroundColor Yellow; return }
  $sealed = @($s.sealed | Where-Object { $_ })
  $plain = @($s.plain | Where-Object { $_ })
  $mode = ([string]$s.mode).ToLower()
  if ($mode -eq 'off') { Write-Host "  Secrets         not sealed (HUMID_SEAL=off): a copy of the data folder holds the server's keys" -ForegroundColor Yellow; return }
  $how = 'DPAPI'
  if ($mode -eq 'file') { $how = 'key file' }
  $total = $sealed.Count + $plain.Count
  $line = "sealed ($how), $($sealed.Count) of $total"
  if ($total -eq 0) { $line = "sealed ($how); the server makes its keys when it first starts" }
  $loose = @($plain)
  if ($s.internalKey -eq 'plain') { $loose += 'the internal key in humid.env' }
  if ($loose.Count) { Write-Host "  Secrets         $line; still in plain: $($loose -join ', ') (the server seals them when it starts: $HumidCmd restart)" -ForegroundColor Yellow }
  else { Say "  Secrets         $line" }
}

function Do-Status {
  $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $t) { Die "$TaskName is not installed." }
  $ti = Get-ScheduledTaskInfo -TaskName $TaskName
  $p = [int](Get-Setting 'HUMID_PORT' '8480')
  $healthy = Test-Healthy $p
  $info = Get-Info
  $roles = @(Get-Roles)
  $front = $roles -contains 'front'
  Say ''
  Say "HumID Server $Version"
  if ($Instance) { Say "  Instance        $Instance  (beside the default install; commands: $HumidCmd ...)" }
  Say ("  Task            {0} (last result {1})" -f $t.State, $ti.LastTaskResult)
  if ($healthy) { Say "  Health          ok" } else { Say "  Health          not answering on 127.0.0.1:$p" }
  Say "  Roles           $($roles -join ', ')"
  Show-SealStatus
  if ($info) {
    if ($front) { Say "  Local address   $($info.localUrl)" } else { Say "  Local address   $($info.localUrl) (health check only: the front role runs elsewhere)" }
    $pub = Get-Setting 'HUMID_PUBLIC_URL'
    if ($front) {
      if ($pub) { Say "  Public address  $pub" } else { Say "  Public address  (none yet: $HumidCmd expose tailscale)" }
    }
    if ($info.fingerprint) { Say "  Fingerprint     $($info.fingerprint)" }
    if ($info.kid) { Say "  Key id          $($info.kid)" }
    if (-not $front -and $info.internal) {
      # core and keys for a gateway on another machine: fixed ports, mutual TLS only
      $label = '  Internal        '
      foreach ($svc in $info.internal.PSObject.Properties) {
        Say "$label$($svc.Name) on $($svc.Value) (mutual TLS)"
        $label = '                  '
      }
    }
    if ($front) {
      Say "  Device policy   $($info.devicePolicy)"
      if ($info.iphones) { Say "  iPhones         accepted" } else { Say "  iPhones         not yet (humid set HUMID_IOS_APP_ID=<TeamID>.app.humid.vault)" }
    }
    Say "  Running since   $($info.startedAt)"
  }
  if ((Get-Setting 'HUMID_CHECKIN' 'off') -eq 'on') {
    $armed = Get-ArmedCount
    if ($armed) { Say "  Check-in        on, $armed armed (anything that stops the server erases them)" } else { Say "  Check-in        on, none armed" }
  }
  $at = Get-ScheduledTask -TaskName $AdminTask -ErrorAction SilentlyContinue
  if ($at) { Say ("  Admin console   http://127.0.0.1:{0}  ({1}; open it with: {2} console)" -f (Get-Setting 'HUMID_ADMIN_PORT' '8490'), $at.State, $HumidCmd) }
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
  # -Path: a file, or a folder (both files go there); by default Documents. Keyshare's half goes
  # beside it unless -KeysharePath puts it elsewhere (another disk).
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $target = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "HumID-backup-$stamp.humidbak"
  if ($PathText) {
    $p = Get-FullPath $PathText
    if ((Test-Path -LiteralPath $p -PathType Container) -or $PathText.EndsWith('\') -or $PathText.EndsWith('/')) { $target = Join-Path $p "HumID-backup-$stamp.humidbak" }
    else { $target = $p }
  }
  $ks = $KeysharePath
  if ($ks) { $ks = Get-FullPath $ks } else { $ks = Join-Path (Split-Path -Parent $target) "HumID-keyshare-$stamp.humidbak" }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target), (Split-Path -Parent $ks) | Out-Null
  $check = Invoke-AdminJs @('backup', '--root', $DataRoot, '--out', $target, '--keyshare-out', $ks, '--check')
  if ($check.Code -ne 0) { Die (Why-AdminFailed $check) }
  Confirm-ArmedErase 'a backup, which stops the server,'
  Step 'Stopping the server for a consistent copy...'
  try { $lines = Make-Backup @('--out', $target, '--keyshare-out', $ks) } catch { Die "The backup failed: $($_.Exception.Message)" }
  Show-AdminLines $lines
  Good 'Backup written.'
  Say '   Copy both files off this computer, onto different disks. Restoring needs both and the backup key file:'
  Say "   $HumidCmd restore -Path `"$target`" -KeysharePath `"$ks`" -Key <backup key file>"
}

function Do-Restore {
  Require-Admin; Require-Installed
  $usage = "Usage: $HumidCmd restore -Path <HumID-backup-....humidbak> -KeysharePath <HumID-keyshare-....humidbak> -Key <backup key file>   (keyshare's half alone: -KeysharePath and -Key; a 2.x backup: -Path <backup.zip>)"
  if (-not $PathText -and -not $KeysharePath) { Die $usage }
  $src = @{}
  if ($PathText) {
    if ($PathText.Contains(',')) { Die "Give the backup with -Path and keyshare's half with -KeysharePath (not both in -Path).`n   $usage" }
    $p = Get-FullPath $PathText
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { Die "There's no file at $p." }
    $src.Path = $p
  }
  if ($src.Path -like '*.zip') {
    Warn "$(Split-Path $src.Path -Leaf) is a backup from 2.1.0 or earlier: not encrypted, keyshare's data inside."
  } else {
    foreach ($q in @(@('Keyshare', $KeysharePath), @('Key', $Key))) {
      if (-not $q[1]) { continue }
      $f = Get-FullPath $q[1]
      if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Die "There's no file at $f." }
      $src[$q[0]] = $f
    }
  }
  $what = $src.Path
  if (-not $what) {
    $what = "keyshare's half in $($src.Keyshare)"
    Warn 'This is keyshare''s half alone: it replaces the key-share data (data\keyshare) and the seal key that opens it. Everything else stays.'
  }
  Confirm-ArmedErase 'restoring a backup'
  if (-not $Quiet -and -not (Confirm-Yes "Replace the current data in $DataRoot with $($what)?" $false)) { return }
  Step 'Opening the backup (the key and every piece are checked before anything changes)...'
  $r = $null
  try { $r = Restore-Data $src } catch { Start-Server | Out-Null; Die "$(([string]$_.Exception.Message).TrimEnd('.')). Nothing was changed." }
  Good "Restored. The previous data is in $($r.Old)"
  if ($r.Kind -eq 'keyshare' -and @(Get-ChildItem -LiteralPath (Join-Path $DataRoot 'pki') -Filter '*.key' -ErrorAction SilentlyContinue).Count) {
    # This machine's role certificate key was sealed under its own seal key, which the restore just replaced.
    Warn 'If keyshare''s half came from another machine, this machine''s role certificate (pki) was sealed under the seal key it replaced.'
    Say "   If the server doesn't start, issue the role's bundle again on the front machine (humid pki issue keys -Path <dir>) and import it here ($HumidCmd pki import -Path <dir>)."
  }
  if (-not (Start-Server)) { exit 1 }
}

# Unpack a backup into a new folder only SYSTEM and Administrators can open (admin\work), check
# it, and only then swap it in. Nothing is ever unpacked into a folder the server's account can
# write. An encrypted backup needs its keyshare file and the backup key file (humid-admin.mjs
# restore checks them, and every piece, before anything moves; it seals the seal key the backup
# carries again under this machine's DPAPI); a local rollback copy needs neither. So a refused
# restore changes nothing, and the server keeps running.
#   full backup   replaces humid.env, data, pki, csca (and keys, the seal key, when it brought one)
#   keyshare's half alone   replaces data\keyshare and keys (a keys machine, docs/DEPLOY-VMS.md)
#   2.x zip       replaces humid.env and data (the server seals their secrets at its next start)
# The current data moves to before-restore-<stamp>; if moving fails half way, everything is put
# back. Stops the server; the caller starts it. Returns @{ Old = before-restore folder; Kind }.
#   $Src  @{ Path = backup (or none, for keyshare's half alone); Keyshare = keyshare's file; Key = backup key file }
function Restore-Data([hashtable]$Src) {
  $workRoot = Join-Path $AdminDir 'work'
  Set-PrivateAcl $AdminDir
  Assert-NoReparse $workRoot
  New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
  $now = Get-Date -Format 'yyyyMMdd-HHmmss'
  $stamp = $now
  for ($n = 2; (Test-Path -LiteralPath (Join-Path $workRoot "restore-$stamp")) -or (Test-Path -LiteralPath (Join-Path $DataRoot "before-restore-$stamp")); $n++) { $stamp = "$now-$n" }
  $work = Join-Path $workRoot "restore-$stamp"
  $kind = 'data'
  try {
    if ($Src.Path -like '*.zip') {
      $kind = 'zip'
      New-Item -ItemType Directory -Path $work | Out-Null
      Expand-Archive -LiteralPath $Src.Path -DestinationPath $work
    } else {
      $a = @('restore', '--root', $DataRoot, '--into', $work)
      if ($Src.Path) { $a += @('--in', $Src.Path) }
      if ($Src.Keyshare) { $a += @('--keyshare', $Src.Keyshare) }
      if ($Src.Key) { $a += @('--key', $Src.Key) }
      $r = Invoke-AdminJs $a
      if ($r.Code -ne 0) { throw (Why-AdminFailed $r) }
      $res = Get-JsonLine $r.Lines
      if ($res -and $res.kind) { $kind = [string]$res.kind }
    }
    $names = @()
    if ($kind -eq 'keyshare') {
      if (-not (Test-Path -LiteralPath (Join-Path $work 'data\keyshare') -PathType Container)) { throw "$(Split-Path $Src.Keyshare -Leaf) holds no key-share data." }
      $names = @('data\keyshare')
    } else {
      $what = $Src.Path; if (-not $what) { $what = $Src.Keyshare }
      if (-not (Test-Path -LiteralPath (Join-Path $work 'data') -PathType Container) -or -not (Test-Path -LiteralPath (Join-Path $work 'humid.env') -PathType Leaf)) {
        throw "$(Split-Path $what -Leaf) isn't a HumID backup (no humid.env and data folder inside)"
      }
      $names = @('humid.env', 'data')
      if ($kind -ne 'zip') { $names += @('pki', 'csca') }
    }
    if ($kind -ne 'zip' -and (Test-Path -LiteralPath (Join-Path $work 'keys') -PathType Container)) { $names += 'keys' }

    Stop-Server
    $old = Join-Path $DataRoot "before-restore-$stamp"
    Assert-NoReparse $old
    New-Item -ItemType Directory -Force -Path $old | Out-Null
    $movedOut = @(); $movedIn = @()
    try {
      foreach ($n in $names) {
        $cur = Join-Path $DataRoot $n
        Assert-NoReparse $cur
        if (Test-Path -LiteralPath $cur) { Move-Into $cur (Join-Path $old $n); $movedOut += $n }
      }
      foreach ($n in $names) {
        $from = Join-Path $work $n
        if (Test-Path -LiteralPath $from) { Move-Into $from (Join-Path $DataRoot $n); $movedIn += $n }
      }
    } catch {
      $why = $_.Exception.Message
      # Half a restore is worse than none: put everything back where it was.
      foreach ($n in $movedIn) { try { Move-Into (Join-Path $DataRoot $n) (Join-Path $work $n) } catch {} }
      foreach ($n in $movedOut) { try { Move-Into (Join-Path $old $n) (Join-Path $DataRoot $n) } catch {} }
      throw "Moving the backup into place failed ($why). The previous data was put back; anything left over is in $old"
    }
  } finally {
    # The opened backup holds every server key: it never stays behind, whatever happened.
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  }
  # What came from admin\work (closed to the server's account) inherits the data folder's permissions now.
  foreach ($n in $movedIn) { Reset-Inherited (Join-Path $DataRoot $n) }
  Set-DataAcl
  # As an administrator (or SYSTEM), not as the server: seal secrets a 2.x backup kept in plain in
  # humid.env, and add settings it lacks. The server's account can't change humid.env (PC-09).
  if ($kind -ne 'keyshare') {
    $code = Run-Native $NodeExe @('--no-warnings', $ServerJs, 'init', '--root', $DataRoot) -Silent
    if ($code -ne 0) { Warn "humid-server init after the restore stopped (exit $code); the server may not start. Run: $HumidCmd install" }
  }
  return @{ Old = $old; Kind = $kind }
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
      # One Funnel address per computer: turning it on here would point the other server's address at this one.
      $others = @(Get-OtherFunnelUsers)
      if ($others.Count) {
        Warn "$($others -join ', ') on this computer already uses Tailscale Funnel (https://$dns). Turning it on here takes that address away from it."
        if (-not (Confirm-Yes 'Point the Funnel address at this server instead?' $false)) { Die 'Stopped. Nothing was changed. (A test instance can be tried locally, or through a Cloudflare Tunnel hostname.)' }
      }
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
      if ($code -ne 0 -and $Instance) { Die "cloudflared service install failed. If a tunnel service already runs (for the other HumID server on this computer), don't uninstall it: add a public hostname for this instance to that tunnel (Service: HTTP 127.0.0.1:$p), then: $HumidCmd set HUMID_PUBLIC_URL=https://<that hostname>" }
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

function Do-BackupKey {
  Require-Admin; Require-Installed
  $sub = 'show'; if ($Rest -and $Rest.Count -gt 0) { $sub = $Rest[0].ToLower() }
  Set-PrivateAcl $AdminDir
  $r = $null
  switch ($sub) {
    'new' {
      if (-not $PathText) {
        Say 'Make the backup key. Its private key goes to the file you name, which you keep off this computer'
        Say '(a USB drive, and a second copy somewhere safe); only its public key stays here. Restoring needs that file.'
        Say '   humid backup-key new -Path E:\humid-backup.key'
        exit 1
      }
      $a = @('backup-key-new', '--root', $DataRoot, '--out', (Get-FullPath $PathText))
      if ($Replace) { $a += '--replace' }
      $r = Invoke-AdminJs $a
    }
    'keyshare' {
      $d = ''; if ($Rest.Count -gt 1) { $d = $Rest[1] } elseif ($PathText) { $d = $PathText }
      if (-not $d) { Die 'Usage: humid backup-key keyshare D:\HumID-keyshare   (or: default, for backups\keyshare)' }
      if ($d -ne 'default') { $d = Get-FullPath $d }
      $r = Invoke-AdminJs @('backup-keyshare-dir', '--root', $DataRoot, '--dir', $d)
    }
    'show' { $r = Invoke-AdminJs @('backup-key-show', '--root', $DataRoot) }
    default {
      Say 'Usage:'
      Say '   humid backup-key new -Path E:\humid-backup.key [-Replace]   make the backup key (its private key goes to that file)'
      Say '   humid backup-key [show]                                    the backup key and where backups go'
      Say '   humid backup-key keyshare D:\HumID-keyshare | default      where the console puts keyshare''s half of each backup'
      return
    }
  }
  if ($r.Code -ne 0) { Die (Why-AdminFailed $r) }
  Show-AdminLines $r.Lines
}

function Do-Logs {
  if (-not (Test-Path $LogFile)) { Die "No log yet at $LogFile" }
  if ($Follow) { Get-Content -LiteralPath $LogFile -Tail 60 -Wait } else { Get-Content -LiteralPath $LogFile -Tail 60 }
}

# Certificates for running the roles on separate machines, with mutual TLS between them (docs/DEPLOY-VMS.md).
function Do-Pki {
  Require-Admin; Require-Installed
  $sub = ''; if ($Rest -and $Rest.Count -gt 0) { $sub = $Rest[0].ToLower() }
  $more = @(); if ($Rest.Count -gt 1) { $more = @($Rest[1..($Rest.Count - 1)]) }
  switch ($sub) {
    'init' {
      $extra = @($more | ForEach-Object { if (@('force', '-force', '--force') -contains $_.ToLower()) { '--force' } else { $_ } })
      Invoke-Server (@('pki', 'init', '--root', $DataRoot) + $extra)
      Say "Next: humid pki issue core|keys -Path <folder>, for each role that runs on another machine."
    }
    'status' { Invoke-Server @('pki', 'status', '--root', $DataRoot) }
    'issue' {
      $role = ''; if ($more.Count) { $role = ([string]$more[0]).ToLower() }
      if (@('core', 'keys') -notcontains $role -or -not $PathText) { Die 'Usage: humid pki issue core|keys -Path <folder>   (a bundle to carry to the machine that runs that role)' }
      $dir = Get-FullPath $PathText
      # The bundle holds the role's private key until it is imported: a new folder starts closed to all but administrators.
      if (-not (Test-Path -LiteralPath $dir)) { try { Set-PrivateAcl $dir } catch {} }
      Invoke-Server @('pki', 'issue', $role, '--out', $dir, '--root', $DataRoot)
      Warn "$dir holds the $role role's private key. Carry it to the $role machine, run humid pki import -Path <folder> there, then delete it on both."
    }
    'import' {
      if (-not $PathText) { Die 'Usage: humid pki import -Path <folder>   (the bundle humid pki issue made on the front machine)' }
      $dir = Get-FullPath $PathText
      if (-not (Test-Path -LiteralPath $dir -PathType Container)) { Die "No folder at $dir" }
      # The same choice humid-server makes: the bundle's role is the one whose certificate and key are in it.
      $role = 'keys'
      if ((Test-Path -LiteralPath (Join-Path $dir 'core.crt')) -and (Test-Path -LiteralPath (Join-Path $dir 'core.key'))) { $role = 'core' }
      Invoke-Server @('pki', 'import', '--from', $dir, '--root', $DataRoot)
      Say ''
      Say "Next, give this machine its role and the address the gateway reaches it on (set restarts the server with it):"
      Say "   $HumidCmd set HUMID_ROLES=$role HUMID_INTERNAL_BIND=<this machine's internal address>"
      Say "Then, on the front machine, leave the $role role out and point at this one: humid set HUMID_ROLES=... HUMID_$($role.ToUpper())_HOST=<that address>"
      Warn "Delete $dir now. Until the set above, this machine can't run the front role (its internal private key was removed)."
    }
    default {
      Say 'Usage (roles on separate machines, mutual TLS between them; docs/DEPLOY-VMS.md):'
      Say '   humid pki init                          on the front machine: a private CA and a certificate per role'
      Say '   humid pki status                        the certificates on this machine and the days they have left'
      Say '   humid pki issue core|keys -Path <dir>   a bundle to carry to the machine that runs that role'
      Say '   humid pki import -Path <dir>            on that machine: take the bundle in'
    }
  }
}

# The deployment smoke test as one file (humid-selftest.mjs), run against this server's own 127.0.0.1
# address with the bundled Node.js: a throwaway account, a sealed document, a second device, an
# open with a live check, the log, and closing the account.
function Do-Selftest {
  Require-Admin; Require-Installed   # admin: it reads the settings and mints an access code
  $test = Join-Path $InstallDir 'humid-selftest.mjs'
  if (-not (Test-Path -LiteralPath $test)) { Die "$test is missing (it comes with HumID Server 3.0 and later)." }
  $roles = @(Get-Roles)
  if ($roles -notcontains 'front') { Die "This machine runs $($roles -join ', '), not the front role: run the self-test on the front machine." }
  $p = [int](Get-Setting 'HUMID_PORT' '8480')
  if (-not (Test-Healthy $p)) { Die "The server doesn't answer on 127.0.0.1:$p. Start it first: $HumidCmd start" }
  $policy = Get-Setting 'HUMID_DEVICE_POLICY' 'attested'
  $info = Get-Info
  if ($info -and $info.devicePolicy) { $policy = [string]$info.devicePolicy }
  $code = ''
  if ((Get-Setting 'HUMID_REGISTRATION' 'pass') -eq 'pass') {
    # A new account needs an access pass, so the test spends one access code of its own.
    $m = Invoke-ServerCapture @('mint', '--root', $DataRoot, '1', 'selftest')
    $code = [regex]::Match(($m.Out -join "`n"), 'HA-[0-9A-Z-]+').Value
    if ($m.Code -ne 0 -or -not $code) { Die "Couldn't mint an access code for the self-test: $(Get-Reason $m)" }
    Say 'Minted one access code for the self-test (batch "selftest").'
  }
  if ($policy -eq 'attested') {
    Say 'The device policy is attested and the self-test has no phone, so it checks that a device without hardware proof is refused.'
    Say 'On a TEST instance (never the live server), humid set HUMID_DEVICE_POLICY=biometric lets it run the whole flow.'
  }
  Step "Self-test against http://127.0.0.1:$p"
  $a = @('--no-warnings', $test, "http://127.0.0.1:$p")
  if ($code) { $a += $code }
  $rc = Run-Native $NodeExe $a
  if ($rc -eq 0) { Good 'Self-test passed.' } else { Warn "Self-test failed (exit $rc)." }
  exit $rc
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

function Job-Backup {
  Set-PrivateAcl $BackupDir
  Job-Step 'Backing up, encrypted to the backup key (the server stops for a moment)'
  $lines = Make-Backup @('--console')
  $sum = (@($lines) | Where-Object { $_.StartsWith('{') } | Select-Object -Last 1) | ConvertFrom-Json
  Job-Step ("Backup written to backups\{0} ({1:N0} MB); keyshare's half to {2}" -f $sum.file, ($sum.bytes / 1MB), $sum.keyshare)
  foreach ($w in @($lines) | Where-Object { $_ -like 'Warning: *' }) { Job-Step $w.Substring(9) }
  return @{ file = $sum.file; bytes = $sum.bytes; keyshare = $sum.keyshare; key = $sum.key }
}

# Before an update or a rollback: a copy of humid.env and data\ to put back if neither version
# comes up. It's in admin\rollback (SYSTEM and Administrators only) and is NOT encrypted to the
# backup key: the job has to restore it by itself, and the key is kept off this computer. It's
# deleted as soon as the change has worked (after a failed one, at the next update or rollback).
# With a backup key set, a lasting encrypted backup is made in the same stop.
function Job-Snapshot([string]$Name) {
  $dir = Join-Path $AdminDir 'rollback'
  Set-PrivateAcl $dir
  Get-ChildItem -LiteralPath $dir -Filter '*.humidbak' | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }   # older ones are out of date
  $file = Join-Path $dir "$Name.humidbak"
  Job-Step 'Taking a local rollback copy (the server stops for a moment)'
  $lines = Make-Backup @('--local', $file, '--console-if-key')
  if (-not (Test-Path -LiteralPath $file)) { throw 'The rollback copy was not written.' }
  $sum = @($lines) | Where-Object { $_.StartsWith('{') } | Select-Object -Last 1
  if ($sum) { $sum = $sum | ConvertFrom-Json; Job-Step "Backup written to backups\$($sum.file), encrypted to backup key $($sum.key)" }
  else { Job-Step 'No backup key is set, so only the local rollback copy was taken (it''s deleted after the update). Set one up: humid backup-key new' }
  return $file
}

# Same server identity, the expected version, healthy: or the reason it isn't.
function Test-Updated([string]$Want, [string]$Kid, [datetime]$Since) {
  if (-not (Wait-Healthy -Seconds 120 -Since $Since)) { return "it didn't answer its health check within 2 minutes" }
  $info = Get-Info
  if ($info.version -ne $Want) { return "it reports version $($info.version), not $Want" }
  if ($Kid -and $info.kid -ne $Kid) { return "its server identity changed ($($info.kid)); phones would refuse it" }
  # Only the front role (the gateway) has a key bundle; core and keys answer just their health check.
  if ($Kid -or ((Get-Roles) -contains 'front')) {
    try {
      $keys = Invoke-RestMethod -Uri "http://127.0.0.1:$(Get-Setting 'HUMID_PORT' '8480')/htp/v1/keys" -TimeoutSec 10
      if ($Kid -and $keys.kid -ne $Kid) { return "it serves a different server key" }
    } catch { return "its key bundle doesn't answer" }
  }
  return $null
}

function Install-Package([string]$Dir) {
  $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $a = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $Dir 'humid.ps1'), 'install', '-Quiet', '-NoStart')
  # An update package doesn't know which install it is for: without this, an instance's update
  # would install over the default one.
  if ($Instance) { $a += @('-Instance', $Instance) }
  return (Run-Native $ps $a -Silent)
}

function Copy-Program([string]$From, [string]$To) {
  if (Test-Path $To) { Remove-Item -LiteralPath $To -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $To | Out-Null
  Get-ChildItem -LiteralPath $From -Force | Where-Object { $_.Name -ne 'node' } |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $To -Recurse -Force }
}

function Restore-Quietly([string]$Snapshot) {
  Restore-Data @{ Path = $Snapshot } | Out-Null
}

# Switch the program to the package in $Pkg; on any failure, put $Fallback back (and the data,
# from the local rollback copy $Snapshot, if needed).
function Switch-Program([string]$Pkg, [string]$Want, [string]$FallbackDir, [string]$FallbackVersion, [string]$Kid, [string]$Snapshot) {
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
    Job-Step "$FallbackVersion didn't come up either ($again). Restoring the data from the copy taken first"
    try { Restore-Quietly $Snapshot } catch { Job-Step "The restore didn't work either: $($_.Exception.Message)" }
    $since = (Get-Date).AddSeconds(-2)
    Start-Server | Out-Null
    $again = Test-Updated $FallbackVersion $Kid $since
  }
  Start-Admin
  if ($again) { throw "$Want failed ($problem), and so did putting $FallbackVersion back ($again). Run humid status in Terminal (Admin); the copy taken first is $Snapshot (humid restore -Path `"$Snapshot`")." }
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
  $snap = Job-Snapshot "pre-update-$from-to-$v-$(Get-Date -Format 'yyyyMMdd-HHmm')"
  Job-Step "Keeping $from for rollback"
  Copy-Program $InstallDir $PrevDir
  Switch-Program $pkg $v $PrevDir $from $kid $snap
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $snap -Force -ErrorAction SilentlyContinue
  Job-Step 'Deleted the local rollback copy'
  return @{ from = $from; to = $v }
}

function Job-Rollback($A) {
  $to = Read-PackageVersion $PrevDir
  if (-not $to -or $to -ne [string]$A.to) { throw "The kept version is $to, not $($A.to)." }
  $from = Read-PackageVersion $InstallDir
  $kid = (Get-Info).kid
  $snap = Job-Snapshot "pre-rollback-$from-to-$to-$(Get-Date -Format 'yyyyMMdd-HHmm')"
  $current = "$InstallDir.rollback"
  Job-Step "Keeping $from aside"
  Copy-Program $InstallDir $current
  Switch-Program $PrevDir $to $current $from $kid $snap
  Remove-Item -LiteralPath $snap -Force -ErrorAction SilentlyContinue
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
  'backup-key' { Do-BackupKey }
  'pki'       { Do-Pki }
  'selftest'  { Do-Selftest }
  'expose'    { Do-Expose }
  'console'   { Do-Console }
  'admin'     { Do-AdminCmd }
  'probe'     { Do-Probe }
  'job-run'   { Require-Admin; Do-JobRun }
  default     { Get-Help $PSCommandPath -Detailed | Out-Host }
}
