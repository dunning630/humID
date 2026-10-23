# Hyper-V steps for HumID holder cells (docs/CELLS.md). Called by the cell controller
# (humid-server.mjs cells run, as SYSTEM) and by `humid cells`. One verb per call; the last
# line printed is JSON: {"ok":true,...} or {"ok":false,"error":"..."}.
#
#   Test-Host                          can this PC run cells? (edition, Hyper-V, memory)
#   Install-Switch                     the internal switch HumID-Cells, host 10.77.0.1/24, no routing
#   New-Cell -Id -Ip -SeedDir -MemoryMB -DiskMB -Image -VmDir
#   Remove-Seed -Id -VmDir             detach and delete a running cell's seed disk
#   Remove-Cell -Id -VmDir             turn off, remove the VM and every disk it had
#   Get-FreeMemory
#
# Windows PowerShell 5.1. Needs the Hyper-V PowerShell module (Hyper-V on Windows 10/11 Pro,
# Enterprise or Education).

param(
  [Parameter(Position = 0, Mandatory = $true)][string]$Verb,
  [string]$Id, [string]$Ip, [string]$SeedDir, [int]$MemoryMB = 512, [int]$DiskMB = 1024,
  [string]$Image, [string]$VmDir
)

$ErrorActionPreference = 'Stop'
$SwitchName = 'HumID-Cells'
$HostIp = '10.77.0.1'

function Out-Json($o) { $o | ConvertTo-Json -Compress -Depth 4 | Write-Output }
function Need-Id { if ($Id -notmatch '^[a-z0-9]{8,32}$') { throw "bad cell id '$Id'" } }
function Cell-Dir { if (-not $VmDir -or -not [IO.Path]::IsPathRooted($VmDir)) { throw 'VmDir must be an absolute path' }; Join-Path $VmDir $Id }
function VmName { "humid-cell-$Id" }

function Test-Host {
  $os = Get-CimInstance Win32_OperatingSystem
  $feature = $null
  try { $feature = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State } catch { $feature = 'Unavailable' }
  $module = [bool](Get-Module -ListAvailable -Name Hyper-V)
  $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
  $hv = ($null -ne (Get-CimInstance Win32_ComputerSystem).HypervisorPresent) -and (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
  $problems = @()
  if ($os.Caption -match 'Home') { $problems += "Windows Home can't run Hyper-V: cells need Pro, Enterprise or Education." }
  if ($feature -ne 'Enabled') { $problems += "Hyper-V isn't turned on (Turn Windows features on or off > Hyper-V, then restart)." }
  if (-not $module) { $problems += 'The Hyper-V PowerShell module is missing (Hyper-V Management Tools).' }
  if (-not $hv -and -not $cpu.VirtualizationFirmwareEnabled) { $problems += 'Virtualization is off in the firmware (BIOS/UEFI): turn on Intel VT-x or AMD-V.' }
  Out-Json @{
    ok = $true; ready = ($problems.Count -eq 0); problems = $problems
    edition = $os.Caption; build = $os.BuildNumber; hyperV = $feature; hypervisorRunning = [bool]$hv
    memoryMb = [int]($os.TotalVisibleMemorySize / 1024); freeMb = [int]($os.FreePhysicalMemory / 1024)
  }
}

function Install-Switch {
  if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
  }
  $nic = Get-NetAdapter | Where-Object { $_.Name -eq "vEthernet ($SwitchName)" }
  if (-not $nic) { throw "The host adapter for $SwitchName didn't appear." }
  if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $HostIp -ErrorAction SilentlyContinue)) {
    Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $HostIp -PrefixLength 24 | Out-Null
  }
  # Cells reach nothing but the host's replies: no forwarding, no NAT, nothing inbound from them.
  Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Forwarding Disabled
  Disable-NetAdapterBinding -Name $nic.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
  if (-not (Get-NetFirewallRule -Name 'HumID-Cells-NoInbound' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'HumID-Cells-NoInbound' -DisplayName 'HumID cells: nothing inbound from cells' -Direction Inbound -Action Block -RemoteAddress '10.77.0.0/24' -Profile Any | Out-Null
  }
  Out-Json @{ ok = $true; switch = $SwitchName; host = $HostIp }
}

function New-SeedDisk($path) {
  New-VHD -Path $path -SizeBytes 64MB -Dynamic | Out-Null
  $mnt = Join-Path $env:TEMP ("humid-seed-" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $mnt | Out-Null
  $disk = Mount-VHD -Path $path -Passthru | Get-Disk
  try {
    Initialize-Disk -Number $disk.Number -PartitionStyle MBR
    $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize
    Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel 'HUMIDSEED' -Confirm:$false | Out-Null
    Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath $mnt
    foreach ($f in 'cell.json', 'ca.crt', 'cell.crt', 'cell.key') { Copy-Item (Join-Path $SeedDir $f) (Join-Path $mnt $f) }
    Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath $mnt
  } finally {
    Dismount-VHD -Path $path
    Remove-Item $mnt -Force -ErrorAction SilentlyContinue
  }
}

function New-Cell {
  Need-Id
  if ($Ip -notmatch '^10\.77\.0\.(\d{1,3})$' -or [int]$Matches[1] -lt 10 -or [int]$Matches[1] -gt 250) { throw "bad cell address '$Ip'" }
  if (-not (Test-Path $Image)) { throw "The cell image $Image doesn't exist (humid cells image -Path ...)." }
  if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) { throw "No $SwitchName switch: run humid cells enable." }
  $dir = Cell-Dir
  if (Get-VM -Name (VmName) -ErrorAction SilentlyContinue) { throw "A VM named $(VmName) already exists." }
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  # SYSTEM and Administrators only: a cell's disks hold its holder's sealed documents.
  icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
  $os = Join-Path $dir 'os.vhdx'; $data = Join-Path $dir 'data.vhdx'; $seed = Join-Path $dir 'seed.vhdx'
  New-VHD -Path $os -ParentPath $Image -Differencing | Out-Null
  New-VHD -Path $data -SizeBytes ([int64]$DiskMB * 1MB) -Dynamic | Out-Null
  New-SeedDisk $seed
  $vm = New-VM -Name (VmName) -Generation 2 -MemoryStartupBytes 256MB -VHDPath $os -SwitchName $SwitchName -Path $dir
  Set-VM -VM $vm -DynamicMemory -MemoryMinimumBytes 128MB -MemoryMaximumBytes ([int64]$MemoryMB * 1MB) -ProcessorCount 1 `
    -AutomaticStartAction Start -AutomaticStopAction ShutDown -CheckpointType Disabled -AutomaticCheckpointsEnabled $false -Notes "HumID holder cell $Id ($Ip)"
  Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
  Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $data
  Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $seed
  Set-VMNetworkAdapter -VM $vm -MacAddressSpoofing Off -DhcpGuard On -RouterGuard On
  Disable-VMIntegrationService -VM $vm -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
  Start-VM -VM $vm
  Out-Json @{ ok = $true; id = $Id; ip = $Ip }
}

function Remove-Seed {
  Need-Id
  $vm = Get-VM -Name (VmName)
  $drive = Get-VMHardDiskDrive -VM $vm | Where-Object { $_.Path -like '*\seed.vhdx' }
  if ($drive) { Remove-VMHardDiskDrive -VMHardDiskDrive $drive }
  $seed = Join-Path (Cell-Dir) 'seed.vhdx'
  if (Test-Path $seed) { Remove-Item $seed -Force }
  Out-Json @{ ok = $true; id = $Id }
}

function Remove-Cell {
  Need-Id
  $vm = Get-VM -Name (VmName) -ErrorAction SilentlyContinue
  if ($vm) {
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
    Remove-VM -VM $vm -Force
  }
  $dir = Cell-Dir
  if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
  Out-Json @{ ok = $true; id = $Id }
}

function Get-FreeMemory {
  $os = Get-CimInstance Win32_OperatingSystem
  Out-Json @{ ok = $true; freeMb = [int]($os.FreePhysicalMemory / 1024); totalMb = [int]($os.TotalVisibleMemorySize / 1024) }
}

try {
  switch ($Verb) {
    'Test-Host' { Test-Host }
    'Install-Switch' { Install-Switch }
    'New-Cell' { New-Cell }
    'Remove-Seed' { Remove-Seed }
    'Remove-Cell' { Remove-Cell }
    'Get-FreeMemory' { Get-FreeMemory }
    default { throw "Unknown verb '$Verb'" }
  }
} catch {
  Out-Json @{ ok = $false; error = $_.Exception.Message }
  exit 1
}
