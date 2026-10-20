# Downloads the free DB-IP Lite databases (CC BY 4.0, https://db-ip.com) used for
# offline geolocation: city (country/region/city/coordinates) and ASN (provider).
# Usage: powershell -ExecutionPolicy Bypass -File scripts\fetch-geoip.ps1 [-Dir geoip]
param([string]$Dir = (Join-Path $PSScriptRoot "..\geoip"))

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force $Dir | Out-Null

function Fetch($kind) {
    $out = Join-Path $Dir "dbip-$kind-lite.mmdb"
    # DB-IP publishes a new file each month; fall back to the previous month early in the month.
    foreach ($back in 0, 1, 2) {
        $month = (Get-Date).AddMonths(-$back).ToString("yyyy-MM")
        $url = "https://download.db-ip.com/free/dbip-$kind-lite-$month.mmdb.gz"
        $gz = "$out.gz"
        try {
            Invoke-WebRequest $url -OutFile $gz -UseBasicParsing
        } catch {
            Write-Host "  $month not available, trying an older release"
            continue
        }
        $in = [IO.File]::OpenRead($gz)
        $zip = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
        $dst = [IO.File]::Create($out)
        $zip.CopyTo($dst)
        $dst.Close(); $zip.Close(); $in.Close()
        Remove-Item $gz
        "{0}: {1:N0} MB ({2})" -f (Split-Path $out -Leaf), ((Get-Item $out).Length / 1MB), $month
        return
    }
    throw "could not download dbip-$kind-lite"
}

Fetch "city"
Fetch "asn"
Write-Host "GeoIP databases saved to $((Resolve-Path $Dir).Path)"
