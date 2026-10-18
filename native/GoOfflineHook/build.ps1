# Builds GoOfflineHook.dll (x64) using the Visual Studio build tools.
# Output: ..\..\src\GoOffline\native\GoOfflineHook.dll (and x86 variant if the toolchain is present).

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path $here '..\..\src\GoOffline\native'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "VS C++ build tools not found." }
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvarsall.bat'

function BuildArch($arch, $outName) {
  $cmd = "`"$vcvars`" $arch && cl /nologo /LD /O2 /MT /EHsc /DUNICODE /D_UNICODE `"$here\GoOfflineHook.cpp`" /Fe:`"$outDir\$outName`" /link ws2_32.lib psapi.lib /OUT:`"$outDir\$outName`""
  Write-Host "Building $outName..." -ForegroundColor Cyan
  cmd /c $cmd
  if ($LASTEXITCODE -ne 0) { throw "Build failed for $arch" }
  # Clean intermediates
  Remove-Item -Force -ErrorAction SilentlyContinue "$outDir\*.obj","$outDir\*.exp","$outDir\*.lib"
}

Push-Location $outDir
try {
  BuildArch 'x64' 'GoOfflineHook64.dll'
  try { BuildArch 'x86' 'GoOfflineHook32.dll' } catch { Write-Warning "x86 build skipped: $_" }
} finally {
  Pop-Location
}
Write-Host "Done. Output in $outDir" -ForegroundColor Green
