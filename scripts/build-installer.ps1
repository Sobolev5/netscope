# Builds the release binaries and the Windows installer (dist\NetScope-Setup-<version>.exe).
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 [-Offline] [-SkipBuild] [-TargetDir target]
#                                                                        [-Full | -BundleWebView2 -BundleGeoIP]
#
# -Full embeds everything an offline machine needs (dist\NetScope-Setup-<version>-full.exe,
# ~300 MB): the Microsoft Edge WebView2 runtime (Evergreen standalone installer, redistributable)
# and the DB-IP Lite geolocation databases (CC BY 4.0). Both are downloaded once into
# installer\redist\ and reused. Npcap cannot be embedded (license) and is downloaded at install.
#
# Needs Inno Setup 6.1+ (https://jrsoftware.org/isdl.php). ISCC.exe is looked up in PATH,
# the ISCC environment variable, and the usual install folders.
param(
    [switch]$Offline,
    [switch]$SkipBuild,
    [string]$TargetDir = "target",
    [switch]$Full,
    [switch]$BundleWebView2,
    [switch]$BundleGeoIP
)
if ($Full) { $BundleWebView2 = $true; $BundleGeoIP = $true }
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
$redist = Join-Path $root "installer\redist"
$defines = @("/DAppVersion=$version", "/DBinDir=$binDir")
$suffix = ""
if ($BundleWebView2) {
    $wv = Join-Path $redist "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
    if (-not (Test-Path $wv) -or (Get-Item $wv).Length -lt 50MB) {
        New-Item -ItemType Directory -Force $redist | Out-Null
        Write-Host "downloading the WebView2 Evergreen standalone installer (x64)..."
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest "https://go.microsoft.com/fwlink/?linkid=2124701" -OutFile $wv -UseBasicParsing
        if ((Get-Item $wv).Length -lt 50MB) { throw "WebView2 download looks wrong: $wv" }
    }
    $defines += "/DWebView2Local=$wv"; $suffix = "-full"
}
if ($BundleGeoIP) {
    $geo = Join-Path $redist "geoip"
    if (-not (Test-Path (Join-Path $geo "dbip-city-lite.mmdb")) -or -not (Test-Path (Join-Path $geo "dbip-asn-lite.mmdb"))) {
        Write-Host "downloading the DB-IP Lite databases..."
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "scripts\fetch-geoip.ps1") -Dir $geo
        if ($LASTEXITCODE -ne 0) { throw "GeoIP download failed" }
    }
    $defines += "/DGeoIPDir=$geo"; $suffix = "-full"
}
if ($suffix) { $defines += "/DSuffix=$suffix" }
Write-Host "ISCC: $iscc"
& $iscc @defines "/Qp" (Join-Path $root "installer\netscope.iss")
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }
$out = Join-Path $root "dist\NetScope-Setup-$version$suffix.exe"
"{0}  ({1:N1} MB)" -f $out, ((Get-Item $out).Length / 1MB)
