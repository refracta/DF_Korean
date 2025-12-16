[CmdletBinding()]
param(
  [ValidateSet('Debug', 'Release')]
  [string] $Configuration = 'Release',

  [ValidateSet('Win32', 'x64')]
  [string] $Platform = 'x64',

  [string] $DistDir = (Join-Path $PSScriptRoot '..' 'dist'),

  [string] $ZipName = 'DF_Korean.zip',

  [switch] $Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Assert-FileExists {
  param([Parameter(Mandatory = $true)][string] $Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Missing file: $Path"
  }
}

function Invoke-MsBuild {
  param(
    [Parameter(Mandatory = $true)][string] $ProjectOrSolutionPath,
    [Parameter(Mandatory = $true)][string] $OutDir
  )

  $msbuild = Get-Command msbuild -ErrorAction SilentlyContinue
  if (-not $msbuild) {
    throw 'msbuild not found. On GitHub Actions, add microsoft/setup-msbuild before running this script.'
  }

  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  if (-not $OutDir.EndsWith('\')) {
    $OutDir = "$OutDir\"
  }

  & $msbuild.Source $ProjectOrSolutionPath `
    /m `
    /p:Configuration=$Configuration `
    /p:Platform=$Platform `
    /p:OutDir=$OutDir `
    /verbosity:minimal
}

function Get-PeImportDllNames {
  param([Parameter(Mandatory = $true)][string] $Path)

  $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $br = New-Object System.IO.BinaryReader($fs)

    if ($br.ReadUInt16() -ne 0x5A4D) { return @() }

    $fs.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
    $peOffset = $br.ReadUInt32()
    $fs.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
    if ($br.ReadUInt32() -ne 0x00004550) { return @() }

    $null = $br.ReadUInt16() # Machine
    $numberOfSections = $br.ReadUInt16()
    $fs.Seek(12, [System.IO.SeekOrigin]::Current) | Out-Null
    $sizeOfOptionalHeader = $br.ReadUInt16()
    $fs.Seek(2, [System.IO.SeekOrigin]::Current) | Out-Null

    $optHeaderStart = $fs.Position
    $magic = $br.ReadUInt16()
    $isPE32Plus = $magic -eq 0x20B
    $dataDirOffset = if ($isPE32Plus) { 112 } else { 96 }

    $fs.Seek($optHeaderStart + $dataDirOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $null = $br.ReadUInt32(); $null = $br.ReadUInt32() # Export
    $importRva = $br.ReadUInt32(); $null = $br.ReadUInt32() # Import

    $fs.Seek($optHeaderStart + $sizeOfOptionalHeader, [System.IO.SeekOrigin]::Begin) | Out-Null
    $sections = @()
    for ($i = 0; $i -lt $numberOfSections; $i++) {
      $nameBytes = $br.ReadBytes(8)
      $name = ([System.Text.Encoding]::ASCII.GetString($nameBytes)).TrimEnd([char]0)
      $virtualSize = $br.ReadUInt32()
      $virtualAddress = $br.ReadUInt32()
      $sizeOfRawData = $br.ReadUInt32()
      $pointerToRawData = $br.ReadUInt32()
      $fs.Seek(16, [System.IO.SeekOrigin]::Current) | Out-Null

      $sections += [pscustomobject]@{
        Name    = $name
        VA      = $virtualAddress
        VS      = $virtualSize
        RawSize = $sizeOfRawData
        RawPtr  = $pointerToRawData
      }
    }

    function RvaToOffset([uint32] $rva) {
      foreach ($s in $sections) {
        $size = [Math]::Max($s.VS, $s.RawSize)
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $size)) {
          return [uint32]($s.RawPtr + ($rva - $s.VA))
        }
      }
      return $null
    }

    if ($importRva -eq 0) { return @() }
    $importOffset = RvaToOffset $importRva
    if ($null -eq $importOffset) { return @() }

    $fs.Seek($importOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $dlls = [System.Collections.Generic.List[string]]::new()
    while ($true) {
      $origFirstThunk = $br.ReadUInt32()
      $timeDateStamp = $br.ReadUInt32()
      $forwarderChain = $br.ReadUInt32()
      $nameRva = $br.ReadUInt32()
      $firstThunk = $br.ReadUInt32()

      if ($origFirstThunk -eq 0 -and $timeDateStamp -eq 0 -and $forwarderChain -eq 0 -and $nameRva -eq 0 -and $firstThunk -eq 0) {
        break
      }

      $nameOffset = RvaToOffset $nameRva
      if ($null -eq $nameOffset) { continue }

      $pos = $fs.Position
      $fs.Seek($nameOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
      $bytes = New-Object System.Collections.Generic.List[byte]
      while ($true) {
        $b = $br.ReadByte()
        if ($b -eq 0) { break }
        $bytes.Add($b)
      }
      $dllName = [System.Text.Encoding]::ASCII.GetString($bytes.ToArray())
      if ($dllName) { $dlls.Add($dllName) }
      $fs.Seek($pos, [System.IO.SeekOrigin]::Begin) | Out-Null
    }

    return $dlls.ToArray() | Sort-Object -Unique
  } finally {
    $br.Close()
    $fs.Close()
  }
}

function Get-VcpkgExePath {
  $cmd = Get-Command vcpkg -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  if ($env:VCPKG_INSTALLATION_ROOT) {
    $fromEnv = Join-Path $env:VCPKG_INSTALLATION_ROOT 'vcpkg.exe'
    if (Test-Path -LiteralPath $fromEnv) { return $fromEnv }
  }

  $default = 'C:\vcpkg\vcpkg.exe'
  if (Test-Path -LiteralPath $default) { return $default }

  return $null
}

function Resolve-FreetypeDll {
  param(
    [Parameter(Mandatory = $true)][string] $RepoRoot,
    [Parameter(Mandatory = $true)][string] $Platform
  )

  $bundled = Join-Path $RepoRoot 'freetype.dll'
  if (Test-Path -LiteralPath $bundled) {
    $imports = Get-PeImportDllNames -Path $bundled
    $hasDebugCrt = $imports -contains 'ucrtbased.dll' -or ($imports | Where-Object { $_ -match '^[a-zA-Z0-9_]+D\\.dll$' } | Select-Object -First 1)
    if (-not $hasDebugCrt) {
      return [pscustomobject]@{
        Path      = $bundled
        ExtraDlls = @()
      }
    }

    Write-Warning "Bundled freetype.dll depends on debug CRT ($($imports -join ', ')); attempting to fetch a Release freetype.dll via vcpkg."
  }

  $triplet = switch ($Platform) {
    'x64' { 'x64-windows' }
    'Win32' { 'x86-windows' }
    default { throw "Unsupported platform for vcpkg triplet: $Platform" }
  }

  $vcpkgExe = Get-VcpkgExePath
  if (-not $vcpkgExe) {
    throw "vcpkg not found. Install vcpkg (or set VCPKG_INSTALLATION_ROOT) so build.ps1 can fetch a Release freetype.dll."
  }

  & $vcpkgExe install "freetype:$triplet" | Out-Host
  if ($LASTEXITCODE -ne 0) {
    throw "vcpkg install failed (exit=$LASTEXITCODE)."
  }

  $vcpkgRoot = Split-Path -Parent $vcpkgExe
  $binDir = Join-Path $vcpkgRoot "installed\\$triplet\\bin"
  $dllPath = Join-Path $binDir 'freetype.dll'
  Assert-FileExists $dllPath

  $extraSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $queue = [System.Collections.Generic.Queue[string]]::new()
  $queue.Enqueue($dllPath)

  while ($queue.Count -gt 0) {
    $current = $queue.Dequeue()
    foreach ($dep in (Get-PeImportDllNames -Path $current)) {
      if ($dep -match '^(api-ms-win|ext-ms-win)-') { continue }
      $depPath = Join-Path $binDir $dep
      if (-not (Test-Path -LiteralPath $depPath)) { continue }
      if ($extraSet.Add($depPath)) {
        $queue.Enqueue($depPath)
      }
    }
  }

  $extraDlls = $extraSet.ToArray() | Where-Object { $_ -ne $dllPath }

  return [pscustomobject]@{
    Path      = $dllPath
    ExtraDlls = $extraDlls
  }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$distDirResolved = (Resolve-Path -LiteralPath $DistDir -ErrorAction SilentlyContinue)
if (-not $distDirResolved) {
  New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
}
$distDirResolved = (Resolve-Path -LiteralPath $DistDir).Path

if ($Clean) {
  if (Test-Path -LiteralPath $distDirResolved) {
    Remove-Item -LiteralPath $distDirResolved -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $distDirResolved | Out-Null
}

$buildRoot = Join-Path $distDirResolved 'build'
$stagingDir = Join-Path $distDirResolved 'staging'

New-Item -ItemType Directory -Force -Path $buildRoot, $stagingDir | Out-Null
Remove-Item -Path (Join-Path $stagingDir '*') -Recurse -Force -ErrorAction SilentlyContinue

$dfOffsetOut = Join-Path $buildRoot 'DF_kr_offset'
$launcherOut = Join-Path $buildRoot 'dfkr_launcher'
$hookOut = Join-Path $buildRoot 'Dwarf_hook_v2'

Invoke-MsBuild (Join-Path $repoRoot 'DF_kr_offset' 'DF_kr_offset.sln') $dfOffsetOut
Invoke-MsBuild (Join-Path $repoRoot 'dfkr_launcher' 'dfkr_launcher.sln') $launcherOut
Invoke-MsBuild (Join-Path $repoRoot 'Dwarf_hook_v2' 'Dwarf_hook.sln') $hookOut

$dfOffsetExe = Join-Path $dfOffsetOut 'DF_kr_offset.exe'
$launcherExe = Join-Path $launcherOut 'dfkr_launcher.exe'
$hookDll = Join-Path $hookOut 'Dwarf_hook.dll'

Assert-FileExists $dfOffsetExe
Assert-FileExists $launcherExe
Assert-FileExists $hookDll

$dataDir = Join-Path $stagingDir 'data'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

$installBat = Join-Path $repoRoot 'scripts' 'install.bat'
Assert-FileExists $installBat
Copy-Item -LiteralPath $installBat -Destination (Join-Path $stagingDir 'install.bat') -Force

Copy-Item -LiteralPath $dfOffsetExe -Destination $dataDir -Force
Copy-Item -LiteralPath $launcherExe -Destination $dataDir -Force
Copy-Item -LiteralPath $hookDll -Destination $dataDir -Force

foreach ($asset in @('font.ttf', 'translation_data.csv', 'translations.txt')) {
  $assetPath = Join-Path $repoRoot $asset
  Assert-FileExists $assetPath
  Copy-Item -LiteralPath $assetPath -Destination $dataDir -Force
}

$ft = Resolve-FreetypeDll -RepoRoot $repoRoot -Platform $Platform
Copy-Item -LiteralPath $ft.Path -Destination (Join-Path $dataDir 'freetype.dll') -Force
foreach ($depPath in $ft.ExtraDlls) {
  Copy-Item -LiteralPath $depPath -Destination $dataDir -Force
}

$zipPath = Join-Path $distDirResolved $ZipName
if (Test-Path -LiteralPath $zipPath) {
  Remove-Item -LiteralPath $zipPath -Force
}

Push-Location $stagingDir
try {
  Compress-Archive -Path * -DestinationPath $zipPath -Force
} finally {
  Pop-Location
}

Write-Host "Created: $zipPath"
