#!/bin/sh
# Downloads the free DB-IP Lite databases (CC BY 4.0, https://db-ip.com) used for
# offline geolocation: city (country/region/city/coordinates) and ASN (provider).
# Usage: scripts/fetch-geoip.sh [dir]   (default: ./geoip next to the scripts folder)
set -eu
dir="${1:-$(dirname "$0")/../geoip}"
mkdir -p "$dir"

fetch() {
    kind="$1"
    for back in 0 1 2; do
        month=$(date -d "-$back month" +%Y-%m 2>/dev/null || date -v-"$back"m +%Y-%m)
        url="https://download.db-ip.com/free/dbip-$kind-lite-$month.mmdb.gz"
        if curl -fsSL "$url" | gunzip > "$dir/dbip-$kind-lite.mmdb.tmp"; then
            mv "$dir/dbip-$kind-lite.mmdb.tmp" "$dir/dbip-$kind-lite.mmdb"
            echo "dbip-$kind-lite.mmdb ($month)"
            return 0
        fi
        echo "  $month not available, trying an older release"
    done
    rm -f "$dir/dbip-$kind-lite.mmdb.tmp"
    echo "could not download dbip-$kind-lite" >&2
    return 1
}

fetch city
fetch asn
echo "GeoIP databases saved to $dir"
