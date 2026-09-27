<#
.SYNOPSIS
Adds Visual Studio installer components to a hosted runner's installation.

.DESCRIPTION
Older MSVC toolsets (v141, v142 ATL/MFC, v140), pinned servicing builds, and
older Windows SDKs are not on the GitHub-hosted images, but the images'
Visual Studio installers can still add them. This modifies the newest
installation inside -VersionRange and then asks vswhere whether every
requested component is really present, because the installer can exit 0
having skipped one.
#>
param(
  [Parameter(Mandatory)] [string] $VersionRange,
  [Parameter(Mandatory)] [string[]] $Component
)

$ErrorActionPreference = 'Stop'
$Installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer'
$VsWhere = Join-Path $Installer 'vswhere.exe'
$Component = @($Component | Where-Object { $_ })
if ($Component.Count -eq 0) {
  throw 'no components were requested'
}

$InstallPath = & $VsWhere -products * -version $VersionRange -latest -property installationPath
if (-not $InstallPath) {
  throw "no Visual Studio installation in $VersionRange"
}

$Arguments = @('modify', '--installPath', "`"$InstallPath`"")
foreach ($Id in $Component) {
  $Arguments += @('--add', $Id)
}
$Arguments += @('--quiet', '--norestart', '--nocache')
Write-Host "vs_installer.exe $($Arguments -join ' ')"

# -Wait covers the installer's child processes, not only the bootstrapper.
$Process = Start-Process -FilePath (Join-Path $Installer 'vs_installer.exe') `
  -ArgumentList $Arguments -Wait -PassThru
Write-Host "vs_installer.exe exited with $($Process.ExitCode)"
if ($Process.ExitCode -notin 0, 3010) {
  throw "vs_installer.exe failed with exit code $($Process.ExitCode)"
}

$Missing = @()
foreach ($Id in $Component) {
  $Found = & $VsWhere -products * -version $VersionRange -latest -requires $Id -property installationPath
  if (-not $Found) {
    $Missing += $Id
  }
}
if ($Missing.Count -ne 0) {
  throw "still not installed after modify: $($Missing -join ', ')"
}
Write-Host "installed: $($Component -join ', ')"
