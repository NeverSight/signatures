<# Compile feature probes with the real x64 MSVC/ATL headers and retain evidence. #>
param(
  [Parameter(Mandatory)] [string] $OutputDirectory,
  [string] $VersionRange = '[17.0,18.0)',
  [string] $VcvarsVersion = '14.44'
)
$ErrorActionPreference = 'Stop'
$VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$Records = (& $VsWhere -products * -version $VersionRange -latest -format json -utf8 | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0 -or -not $Records) { throw 'No matching Visual Studio installation' }
$Installation = $Records[0].installationPath
$VsDevCmd = Join-Path $Installation 'Common7/Tools/VsDevCmd.bat'
$Lines = & $env:ComSpec /s /c "`"$VsDevCmd`" -no_logo -arch=x64 -host_arch=x64 -vcvars_ver=$VcvarsVersion && set"
if ($LASTEXITCODE -ne 0) { throw 'VsDevCmd failed' }
foreach ($Line in $Lines) {
  if ($Line -match '^([^=]+)=(.*)$') {
    [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
  }
}
if ($env:VSCMD_ARG_TGT_ARCH -ne 'x64') { throw 'Expected x64 target' }
if (-not (Test-Path (Join-Path $env:VCToolsInstallDir 'atlmfc/include/atlstr.h'))) {
  throw 'The selected toolset has no ATL headers'
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$Records | ConvertTo-Json -Depth 12 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'installation.json')
$LlvmBin = Join-Path $env:ProgramFiles 'LLVM/bin'
& python (Join-Path $PSScriptRoot 'build_library_feature_probes.py') `
  --kind msvc --compiler (Get-Command cl.exe).Source --llvm-bin $LlvmBin --output $OutputDirectory
if ($LASTEXITCODE -ne 0) { throw 'Feature probe collection failed; evidence is retained' }
