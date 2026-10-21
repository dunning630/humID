# The admin console on a real Windows machine (CI, after `humid install`):
#   - HumID Admin runs as SYSTEM, on 127.0.0.1 only; its folder is closed to the server's account
#   - the server's account writes only its own data, logs and the approvals drop box; a junction
#     planted where SYSTEM reads (the approvals folder, a service's data) is refused, and
#     installing again removes it without touching what it points to
#   - `humid probe` reads this computer; `humid console` makes a one-time sign-in link that works
#   - approved jobs run through the "HumID Admin Job" task: backup, restart
#   - an update must be signed by a release key the console pins: unsigned or wrongly signed
#     zips are refused before they're unpacked (CI installs a test build of the same version
#     whose console also trusts a release key made for this run only)
#   - an update that breaks is put back by itself; a good update keeps the server's identity;
#     rollback returns to the version before
# Jobs are queued the way the console queues them after a phone's approval; the approval
# itself is tested end to end in tests/e2e/admin-console.test.js.
#
#   pwsh tests/windows/admin-console.ps1 -Repo <checkout>
param([string]$Repo = (Get-Location).Path)
$ErrorActionPreference = 'Stop'
$humid = 'C:\Program Files\HumID Server\humid.ps1'
$data = 'C:\ProgramData\HumID'
$jobs = Join-Path $data 'admin\jobs'
$base = 'http://127.0.0.1:8490'

function Say($m) { Write-Host "-> $m" -ForegroundColor Cyan }
# (not H: in PowerShell that's the Get-History alias, and aliases beat functions)
function Invoke-Humid { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $humid @args; if ($LASTEXITCODE) { throw "humid $($args -join ' ') failed ($LASTEXITCODE)" } }
function Info { Get-Content (Join-Path $data 'server.json') -Raw | ConvertFrom-Json }

# No automatic Windows Update scans while this runs (keeping the backup key the job before set, if any).
Add-Content -Path (Join-Path $data 'admin\admin.env') -Value 'HUMID_AUTO_CHECKS=0' -Encoding ascii

Say 'HumID Admin runs as SYSTEM; its folder is closed to the server account'
$t = Get-ScheduledTask -TaskName 'HumID Admin'
if ($t.Principal.UserId -notmatch 'SYSTEM') { throw "the console runs as $($t.Principal.UserId)" }
Get-ScheduledTask -TaskName 'HumID Admin Job' | Out-Null
$acl = (Get-Acl (Join-Path $data 'admin')).Access | ForEach-Object { $_.IdentityReference.Value }
if ($acl -match 'LOCAL SERVICE|Users|Everyone') { throw "admin folder is open to: $($acl -join ', ')" }
$acl = (Get-Acl (Join-Path $data 'backups')).Access | ForEach-Object { $_.IdentityReference.Value }
if ($acl -match 'LOCAL SERVICE|Users|Everyone') { throw "backups folder is open to: $($acl -join ', ')" }

Say 'The console answers on 127.0.0.1:8490, and only there'
$up = $false
for ($i = 0; $i -lt 60 -and -not $up; $i++) { try { $up = (Invoke-WebRequest -UseBasicParsing "$base/healthz" -TimeoutSec 3).StatusCode -eq 200 } catch { Start-Sleep 2 } }
if (-not $up) { Get-Content (Join-Path $data 'admin\logs\humid-admin.log') -Tail 80 -ErrorAction SilentlyContinue; throw 'the console never answered' }
$listen = @(Get-NetTCPConnection -LocalPort 8490 -State Listen)
if ($listen.LocalAddress | Where-Object { $_ -ne '127.0.0.1' }) { throw "the console listens on $($listen.LocalAddress -join ', ')" }

Say 'humid probe'
$p = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $humid probe | Select-Object -Last 1) | ConvertFrom-Json
if (-not $p.disks -or -not $p.installed.version) { throw "probe: $($p | ConvertTo-Json -Depth 4)" }
$orig = $p.installed.version
"   Windows $($p.os.caption), Defender available: $($p.defender.available), tasks: $(($p.tasks | ForEach-Object { "$($_.name)=$($_.state)" }) -join ', ')"

Say 'humid console: a link that signs in once'
$out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $humid console) | Out-String
$token = [regex]::Match($out, '#login=([A-Za-z0-9_-]+)').Groups[1].Value
if (-not $token) { throw "no link in: $out" }
$s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$hdr = @{ 'x-humid-console' = '1' }
Invoke-RestMethod -Method Post "$base/api/login" -Headers $hdr -ContentType 'application/json' -Body (@{ token = $token } | ConvertTo-Json) -WebSession $s | Out-Null
try { Invoke-RestMethod -Method Post "$base/api/login" -Headers $hdr -ContentType 'application/json' -Body (@{ token = $token } | ConvertTo-Json) | Out-Null; throw 'a link worked twice' } catch { if ($_.Exception.Message -eq 'a link worked twice') { throw } }
$st = $null
for ($i = 0; $i -lt 20; $i++) { $st = Invoke-RestMethod "$base/api/state" -WebSession $s; if ($st.server.up) { break }; Start-Sleep 3 }
if (-not $st.server.up) { throw "the console doesn't see the server up: $($st.server | ConvertTo-Json -Depth 3)" }
if (@($st.server.status.services).Count -ne 7) { throw 'expected seven services in the status' }
"   alerts: $((@($st.alerts) | ForEach-Object { $_.title }) -join ' | ')"

function Run-Job([string]$Type, $JobArgs = @{}, [int]$Minutes = 10) {
  $id = "ci-{0:yyyyMMddHHmmss}-$Type-$(Get-Random)" -f (Get-Date)
  @{ id = $id; type = $Type; args = $JobArgs; title = "CI $Type"; requestedAt = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Depth 5 |
    Set-Content -Path (Join-Path $jobs "$id.request.json") -Encoding utf8
  & schtasks.exe /Run /TN 'HumID Admin Job' | Out-Null
  $deadline = (Get-Date).AddMinutes($Minutes)
  $f = Join-Path $jobs "$id.json"
  while ((Get-Date) -lt $deadline) {
    if (Test-Path $f) {
      $j = Get-Content $f -Raw | ConvertFrom-Json
      if ($j.state -eq 'done' -or $j.state -eq 'failed') { $j.steps | ForEach-Object { "   $($_.msg)" }; if ($j.error) { "   error: $($j.error)" }; return $j }
    }
    Start-Sleep 3
  }
  throw "job $Type didn't finish in $Minutes minutes"
}

Say 'Job: backup, encrypted to the backup key, keyshare''s half in its own file'
$usb = Join-Path $env:RUNNER_TEMP 'console-usb'
New-Item -ItemType Directory -Force -Path $usb | Out-Null
Invoke-Humid backup-key new -Path (Join-Path $usb 'humid-backup.key') -Replace
$j = Run-Job 'backup'
if ($j.state -ne 'done' -or -not (Test-Path (Join-Path $data "backups\$($j.result.file)"))) { throw 'backup job failed' }
if ($j.result.file -notlike '*.humidbak' -or -not (Test-Path $j.result.keyshare)) { throw "expected an encrypted backup and keyshare's half: $($j.result | ConvertTo-Json -Compress)" }
if (Select-String -LiteralPath (Join-Path $data "backups\$($j.result.file)") -Pattern 'HUMID_INTERNAL_SK' -SimpleMatch -Quiet) { throw 'the backup holds the settings in the clear' }
$st = Invoke-RestMethod "$base/api/state" -WebSession $s
if (-not $st.backupKey.fingerprint) { throw 'the console doesn''t see the backup key' }
if (-not (@($st.alerts) | Where-Object { $_.title -like 'Both halves of every split key*' })) { throw 'no warning that both halves are on one disk' }

Say 'The server''s account writes only its own data, its log, and new files in the approvals drop box'
$bad = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, ChangePermissions, TakeOwnership'
function LsRights([string]$P) {
  $r = 0
  foreach ($a in (Get-Acl -LiteralPath $P).Access) {
    if ($a.AccessControlType -eq 'Allow' -and $a.IdentityReference.Value -match 'LOCAL ?SERVICE' -and -not ($a.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { $r = $r -bor [int]$a.FileSystemRights }
  }
  return [Security.AccessControl.FileSystemRights]$r
}
foreach ($p in 'data', 'data\admin', 'data\admin\requests', 'csca') {
  $full = Join-Path $data $p
  if (-not (Test-Path $full)) { continue }
  $r = LsRights $full
  if ([int]$r -band [int]$bad) { throw "the server's account can change $p ($r)" }
}
foreach ($p in '.', 'data\admin\approvals') {
  $r = LsRights (Join-Path $data $p)
  if (-not ([int]$r -band [int][Security.AccessControl.FileSystemRights]::CreateFiles)) { throw "the server's account can't add files to $p ($r)" }
  if ([int]$r -band [int]([Security.AccessControl.FileSystemRights]'AppendData, Delete, DeleteSubdirectoriesAndFiles, WriteAttributes, ChangePermissions')) { throw "the server's account can do more than add files to $p ($r)" }
}
foreach ($p in 'humid.env', 'data\admin\summary.json') {
  $full = Join-Path $data $p
  if ((Test-Path $full) -and ([int](LsRights $full) -band [int]$bad)) { throw "the server's account can change $p" }
}
foreach ($p in 'data\vault', 'data\keyshare', 'logs') {
  $m = [int][Security.AccessControl.FileSystemRights]::Modify
  if (([int](LsRights (Join-Path $data $p)) -band $m) -ne $m) { throw "the server's account can't write $p" }
}
if ((Get-Acl (Join-Path $data 'data\admin')).Owner -match 'LOCAL ?SERVICE') { throw 'the server''s account owns data\admin' }

Say 'A junction planted as the approvals folder is refused by the console'
$elsewhere = Join-Path $env:RUNNER_TEMP 'humid-planted'
New-Item -ItemType Directory -Force -Path $elsewhere | Out-Null
Set-Content -Path (Join-Path $elsewhere 'keep.txt') -Value 'not HumID''s' -Encoding ascii
$approvals = Join-Path $data 'data\admin\approvals'
$aside = Join-Path $data 'data\admin\approvals.real'
Move-Item -LiteralPath $approvals -Destination $aside
New-Item -ItemType Junction -Path $approvals -Target $elsewhere | Out-Null
$seen = $false
for ($i = 0; $i -lt 20 -and -not $seen; $i++) { Start-Sleep 2; $st = Invoke-RestMethod "$base/api/state" -WebSession $s; $seen = [bool](@($st.alerts) | Where-Object { $_.title -eq 'Approvals can''t be read safely' }) }
if (-not $seen) { throw 'the console didn''t notice the junction' }
[IO.Directory]::Delete($approvals, $false)
Move-Item -LiteralPath $aside -Destination $approvals

Say 'Job: a backup refuses a junction planted in a service''s data'
$planted = Join-Path $data 'data\vault\planted'
New-Item -ItemType Junction -Path $planted -Target $elsewhere | Out-Null
$j = Run-Job 'backup'
if ($j.state -ne 'failed' -or $j.error -notmatch 'is a link') { throw "expected the backup to refuse the junction, got $($j.state): $($j.error)" }

Say 'Installing again removes planted junctions, and nothing they point to'
New-Item -ItemType Junction -Path (Join-Path $data 'data\admin\requests\planted') -Target $elsewhere | Out-Null
Invoke-Humid install -Quiet
foreach ($p in $planted, (Join-Path $data 'data\admin\requests\planted')) { if (Test-Path -LiteralPath $p) { throw "$p is still there" } }
if (-not (Test-Path (Join-Path $elsewhere 'keep.txt'))) { throw 'removing a junction touched what it pointed to' }
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-WebRequest -UseBasicParsing "$base/healthz" -TimeoutSec 3).StatusCode -eq 200) { break } } catch { Start-Sleep 2 } }

Say 'Job: restart the server'
$kid = (Info).kid
$j = Run-Job 'restart-server'
if ($j.state -ne 'done') { throw 'restart job failed' }
if ((Info).kid -ne $kid) { throw 'the server identity changed on restart' }

# Release keys made for this run only: the console of a test build trusts the first.
$releaseTool = Join-Path $Repo 'tools\release-key.mjs'
$ciKey = Join-Path $env:RUNNER_TEMP 'ci-release.key'
$otherKey = Join-Path $env:RUNNER_TEMP 'ci-other.key'
foreach ($k in $ciKey, $otherKey) { & node $releaseTool keygen --out $k | Out-Null; if ($LASTEXITCODE) { throw 'release keygen failed' } }
$ciPub = (Get-Content $ciKey -Raw | ConvertFrom-Json).pk

Say "Installing a test build of $orig whose console also trusts this run's release key"
$sameDir = Join-Path $env:RUNNER_TEMP 'humid-same-version'
& node (Join-Path $Repo 'deploy\windows\build.mjs') --zip --as-version $orig --out $sameDir --test-release-key $ciPub | Out-Null
if ($LASTEXITCODE) { throw 'test build failed' }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $sameDir 'HumID-Server\humid.ps1') install -Quiet
if ($LASTEXITCODE) { throw "installing the test build failed ($LASTEXITCODE)" }
if ((Info).kid -ne $kid) { throw 'the server identity changed on reinstall' }
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-WebRequest -UseBasicParsing "$base/healthz" -TimeoutSec 3).StatusCode -eq 200) { break } } catch { Start-Sleep 2 } }

# Two builds labelled 9.9.9: one that can't start, one that's fine. Both signed with the run's key.
Say 'Building test packages labelled 9.9.9'
$work = Join-Path $env:RUNNER_TEMP 'humid-update-test'
& node (Join-Path $Repo 'deploy\windows\build.mjs') --zip --as-version 9.9.9 --out $work --test-release-key $ciPub | Out-Null
if ($LASTEXITCODE) { throw 'test build failed' }
$good = Join-Path $work 'HumID-Server-Windows-9.9.9.zip'
$brokenDir = Join-Path $env:RUNNER_TEMP 'humid-broken'
Expand-Archive -Path $good -DestinationPath $brokenDir -Force
Set-Content -Path (Join-Path $brokenDir 'HumID-Server\humid-server.mjs') -Value 'process.exit(3)' -Encoding ascii
$brokenOut = Join-Path $env:RUNNER_TEMP 'humid-broken-zip'
New-Item -ItemType Directory -Force -Path $brokenOut | Out-Null
$broken = Join-Path $brokenOut 'HumID-Server-Windows-9.9.9.zip'
Compress-Archive -Path (Join-Path $brokenDir 'HumID-Server') -DestinationPath $broken -Force
foreach ($z in $good, $broken) { & node $releaseTool sign $z --key $ciKey | Out-Null; if ($LASTEXITCODE) { throw "signing $z failed" } }
$downloads = Join-Path $data 'admin\downloads'
New-Item -ItemType Directory -Force -Path $downloads | Out-Null
function Stage([string]$Zip, [switch]$NoSig) {
  $to = Join-Path $downloads 'HumID-Server-Windows-9.9.9.zip'
  Copy-Item $Zip $to -Force
  Remove-Item "$to.sig" -Force -ErrorAction SilentlyContinue
  if (-not $NoSig) { Copy-Item "$Zip.sig" "$to.sig" -Force }
  return (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLower()
}

Say 'Job: an update that can''t start is put back by itself'
$sha = Stage $broken
$j = Run-Job 'update-humid' @{ version = '9.9.9'; from = $orig; file = 'HumID-Server-Windows-9.9.9.zip'; sha256 = $sha } 15
if ($j.state -ne 'failed' -or $j.error -notmatch 'running again') { throw "expected an automatic rollback, got $($j.state): $($j.error)" }
if ((Info).version -ne $orig -or (Info).kid -ne $kid) { throw 'not back on the original version and identity' }

Say 'Job: a file that changed after approval is refused'
$null = Stage $good
$j = Run-Job 'update-humid' @{ version = '9.9.9'; from = $orig; file = 'HumID-Server-Windows-9.9.9.zip'; sha256 = $sha }
if ($j.state -ne 'failed' -or $j.error -notmatch 'changed since it was approved') { throw "expected a refusal, got $($j.state): $($j.error)" }

Say 'Job: an unsigned zip is refused before it''s unpacked'
$sha = Stage $good -NoSig
$j = Run-Job 'update-humid' @{ version = '9.9.9'; from = $orig; file = 'HumID-Server-Windows-9.9.9.zip'; sha256 = $sha }
if ($j.state -ne 'failed' -or $j.error -notmatch 'no signature') { throw "expected a refusal (unsigned), got $($j.state): $($j.error)" }
if ((Info).version -ne $orig) { throw 'an unsigned update changed the installed version' }

Say 'Job: a zip signed by a key the console doesn''t pin is refused'
$otherDir = Join-Path $env:RUNNER_TEMP 'humid-other-signer'
New-Item -ItemType Directory -Force -Path $otherDir | Out-Null
$otherZip = Join-Path $otherDir 'HumID-Server-Windows-9.9.9.zip'
Copy-Item $good $otherZip -Force
& node $releaseTool sign $otherZip --key $otherKey | Out-Null
$sha = Stage $otherZip
$j = Run-Job 'update-humid' @{ version = '9.9.9'; from = $orig; file = 'HumID-Server-Windows-9.9.9.zip'; sha256 = $sha }
if ($j.state -ne 'failed' -or $j.error -notmatch 'isn.t signed by a HumID release key') { throw "expected a refusal (other key), got $($j.state): $($j.error)" }
if ((Info).version -ne $orig) { throw 'a wrongly signed update changed the installed version' }

Say 'Job: a good update keeps the server identity'
$sha = Stage $good
$j = Run-Job 'update-humid' @{ version = '9.9.9'; from = $orig; file = 'HumID-Server-Windows-9.9.9.zip'; sha256 = $sha } 15
if ($j.state -ne 'done') { throw "update failed: $($j.error)" }
if ((Info).version -ne '9.9.9' -or (Info).kid -ne $kid) { throw "after the update: version $((Info).version), kid changed: $((Info).kid -ne $kid)" }
if (@(Get-ChildItem (Join-Path $data 'admin\rollback') -Filter '*.humidbak' -ErrorAction SilentlyContinue).Count) { throw 'the local rollback copy is still there after a good update' }
$p = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $humid probe | Select-Object -Last 1) | ConvertFrom-Json
if ($p.previous.version -ne $orig) { throw "expected $orig kept for rollback, got $($p.previous.version)" }
& node (Join-Path $Repo 'tests\smoke.mjs') http://127.0.0.1:8480
if ($LASTEXITCODE) { throw 'smoke test failed after the update' }
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-WebRequest -UseBasicParsing "$base/healthz" -TimeoutSec 3).StatusCode -eq 200) { break } } catch { Start-Sleep 2 } }

Say 'Job: roll back'
$j = Run-Job 'rollback-humid' @{ from = '9.9.9'; to = $orig } 15
if ($j.state -ne 'done') { throw "rollback failed: $($j.error)" }
if ((Info).version -ne $orig -or (Info).kid -ne $kid) { throw 'not back on the original version and identity' }
$p = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $humid probe | Select-Object -Last 1) | ConvertFrom-Json
if ($p.previous.version -ne '9.9.9') { throw 'the rolled-back version should be kept, to roll forward again' }

Say 'Admin console OK'
