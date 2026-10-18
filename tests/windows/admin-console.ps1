# The admin console on a real Windows machine (CI, after `humid install`):
#   - HumID Admin runs as SYSTEM, on 127.0.0.1 only; its folder is closed to the server's account
#   - `humid probe` reads this computer; `humid console` makes a one-time sign-in link that works
#   - approved jobs run through the "HumID Admin Job" task: backup, restart
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
function H { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $humid @args; if ($LASTEXITCODE) { throw "humid $($args -join ' ') failed ($LASTEXITCODE)" } }
function Info { Get-Content (Join-Path $data 'server.json') -Raw | ConvertFrom-Json }

# No automatic Windows Update scans while this runs.
Set-Content -Path (Join-Path $data 'admin\admin.env') -Value 'HUMID_AUTO_CHECKS=0' -Encoding ascii

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
if (-not $up) { Get-Content (Join-Path $data 'logs\humid-admin.log') -Tail 80 -ErrorAction SilentlyContinue; throw 'the console never answered' }
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

Say 'Job: backup'
$j = Run-Job 'backup'
if ($j.state -ne 'done' -or -not (Test-Path (Join-Path $data "backups\$($j.result.file)"))) { throw 'backup job failed' }

Say 'Job: restart the server'
$kid = (Info).kid
$j = Run-Job 'restart-server'
if ($j.state -ne 'done') { throw 'restart job failed' }
if ((Info).kid -ne $kid) { throw 'the server identity changed on restart' }

# Two builds labelled 9.9.9: one that can't start, one that's fine.
Say 'Building test packages labelled 9.9.9'
$work = Join-Path $env:RUNNER_TEMP 'humid-update-test'
& node (Join-Path $Repo 'deploy\windows\build.mjs') --zip --as-version 9.9.9 --out $work | Out-Null
if ($LASTEXITCODE) { throw 'test build failed' }
$good = Join-Path $work 'HumID-Server-Windows-9.9.9.zip'
$brokenDir = Join-Path $env:RUNNER_TEMP 'humid-broken'
Expand-Archive -Path $good -DestinationPath $brokenDir -Force
Set-Content -Path (Join-Path $brokenDir 'HumID-Server\humid-server.mjs') -Value 'process.exit(3)' -Encoding ascii
$broken = Join-Path $env:RUNNER_TEMP 'HumID-Server-Windows-9.9.9.zip'
Compress-Archive -Path (Join-Path $brokenDir 'HumID-Server') -DestinationPath $broken -Force
$downloads = Join-Path $data 'admin\downloads'
New-Item -ItemType Directory -Force -Path $downloads | Out-Null
function Stage([string]$Zip) {
  Copy-Item $Zip (Join-Path $downloads 'HumID-Server-Windows-9.9.9.zip') -Force
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

Say 'Job: a good update keeps the server identity'
$sha = Stage $good
$j = Run-Job 'update-humid' @{ version = '9.9.9'; from = $orig; file = 'HumID-Server-Windows-9.9.9.zip'; sha256 = $sha } 15
if ($j.state -ne 'done') { throw "update failed: $($j.error)" }
if ((Info).version -ne '9.9.9' -or (Info).kid -ne $kid) { throw "after the update: version $((Info).version), kid changed: $((Info).kid -ne $kid)" }
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
