# Builds the release binaries and the Windows installer (dist\NetScope-Setup-<version>.exe).
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 [-Offline] [-SkipBuild] [-TargetDir target]
#
# Needs Inno Setup 6.1+ (https://jrsoftware.org/isdl.php). ISCC.exe is looked up in PATH,
# the ISCC environment variable, and the usual install folders.
param(
    [switch]$Offline,
    [switch]$SkipBuild,
    [string]$TargetDir = "target"
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

$version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $version) { throw "cannot read the version from Cargo.toml" }

if (-not $SkipBuild) {
    $args = @("build", "--release", "--target-dir", $TargetDir)
    if ($Offline) { $args += "--offline" }
    Write-Host "cargo $($args -join ' ')"
    & cargo @args
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}
$binDir = Join-Path $root "$TargetDir\release"
foreach ($f in "netscope.exe", "netscope-app.exe") {
    if (-not (Test-Path (Join-Path $binDir $f))) { throw "missing $binDir\$f" }
}

function Find-Iscc {
    if ($env:ISCC -and (Test-Path $env:ISCC)) { return $env:ISCC }
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\InnoSetup6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    throw "Inno Setup not found: install it from https://jrsoftware.org/isdl.php or set `$env:ISCC to ISCC.exe"
}
$iscc = Find-Iscc
New-Item -ItemType Directory -Force (Join-Path $root "dist") | Out-Null
Write-Host "ISCC: $iscc"
& $iscc "/DAppVersion=$version" "/DBinDir=$binDir" "/Qp" (Join-Path $root "installer\netscope.iss")
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
$out = Join-Path $root "dist\NetScope-Setup-$version.exe"
"{0}  ({1:N1} MB)" -f $out, ((Get-Item $out).Length / 1MB)
