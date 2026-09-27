<#
.SYNOPSIS
Builds the validation probes with one toolset, statically linked, with maps.

.DESCRIPTION
validation/probe.cpp links a broad slice of the C runtime and the C++ standard
library, and validation/probe_mfc.cpp links MFC and ATL. Each is built with
the static runtime (/MT, and /MTd for the debug variant), and the linker
writes a .map of every function it placed. Applying a signature set to the
executable with its debug information ignored, and comparing each named
address against the map, shows what the set identifies and whether any name
is wrong.
#>
param(
  [Parameter(Mandatory)] [string] $VersionRange,
  [Parameter(Mandatory)] [ValidateSet('x86', 'x64', 'arm', 'arm64')] [string[]] $Arch,
  [Parameter(Mandatory)] [string] $Label,
  [Parameter(Mandatory)] [string] $OutputDirectory,
  [string] $VcvarsVersion = '',
  [switch] $NoMfc
)

$ErrorActionPreference = 'Stop'
$VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$Installation = & $VsWhere -products * -version $VersionRange -latest -property installationPath
if (-not $Installation) {
  throw "no Visual Studio installation in $VersionRange"
}
$VsDevCmd = Join-Path $Installation 'Common7/Tools/VsDevCmd.bat'
$Source = Join-Path $PSScriptRoot '../validation'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

function Import-Environment([string] $Target) {
  $Arguments = @('-no_logo', "-arch=$Target", '-host_arch=x64')
  if ($VcvarsVersion) {
    $Arguments += "-vcvars_ver=$VcvarsVersion"
  }
  if ($Target -eq 'arm') {
    # ARM32 libraries end with Windows SDK 10.0.22621.
    $Kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/Lib'
    $Sdk = Get-ChildItem -Directory $Kits |
      Where-Object { Test-Path (Join-Path $_.FullName 'ucrt/arm/libucrt.lib') } |
      Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    if (-not $Sdk) {
      throw 'no installed Windows SDK has ARM32 libraries'
    }
    $Arguments += "-winsdk=$($Sdk.Name)"
  }
  $Lines = & $env:ComSpec /s /c "`"$VsDevCmd`" $($Arguments -join ' ') && set"
  if ($LASTEXITCODE -ne 0) {
    throw "VsDevCmd.bat failed for $Target"
  }
  foreach ($Line in $Lines) {
    if ($Line -match '^([^=]+)=(.*)$') {
      [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
  }
  $Expected = if ($Target -eq 'x64') { 'x64' } else { $Target }
  if ($env:VSCMD_ARG_TGT_ARCH -ne $Expected) {
    throw "VsDevCmd selected $env:VSCMD_ARG_TGT_ARCH, expected $Expected"
  }
}

function Build([string] $Target, [string] $Name, [string] $File, [string[]] $Flags) {
  $Stem = Join-Path $OutputDirectory "$Label-$Target-$Name"
  $Arguments = @('/nologo', '/std:c++14', '/EHsc', '/W0') + $Flags + @(
    (Join-Path $Source $File), "/Fo$Stem.obj", "/Fe$Stem.exe",
    '/link', "/MAP:$Stem.map", '/INCREMENTAL:NO')
  & cl.exe @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "cl.exe failed for $Label $Target $Name"
  }
  Remove-Item "$Stem.obj"
}

foreach ($Target in $Arch) {
  $Saved = [Environment]::GetEnvironmentVariables('Process')
  Import-Environment $Target
  Write-Host "$Label $Target`: $(Get-Command cl.exe | Select-Object -ExpandProperty Source)"
  Build $Target 'mt-o2' 'probe.cpp' @('/MT', '/O2')
  Build $Target 'mtd-od' 'probe.cpp' @('/MTd', '/Od')
  if (-not $NoMfc) {
    Build $Target 'mfc-mt-o2' 'probe_mfc.cpp' @('/MT', '/O2', '/DUNICODE', '/D_UNICODE')
  }
  # Leave the next architecture a clean environment.
  foreach ($Name in [Environment]::GetEnvironmentVariables('Process').Keys) {
    if (-not $Saved.Contains($Name)) {
      [Environment]::SetEnvironmentVariable($Name, $null, 'Process')
    }
  }
  foreach ($Entry in $Saved.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($Entry.Key, $Entry.Value, 'Process')
  }
}
Get-ChildItem $OutputDirectory | Format-Table Name, Length
