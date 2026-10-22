# End-to-end check of the NetScope installer on this machine: installs silently for the
# current user, runs the installed program (live capture: needs Npcap), pokes it through the
# API, netscope: links and its window, uninstalls and checks what is left. The user's own
# %LOCALAPPDATA%\NetScope and the netscope:/toast registry keys are set aside first and
# restored at the end. Prints PASS/FAIL lines; screenshots and logs go to -Work.
#
#   powershell -ExecutionPolicy Bypass -File scripts\e2e-installer.ps1 -Setup dist\NetScope-Setup-0.4.0.exe
#
# Keep this file UTF-8 with BOM: Windows PowerShell 5.1 reads it as ANSI otherwise.
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [string]$Work = (Join-Path $env:TEMP "netscope-e2e"),
    # Expected version; by default taken from the installer's file name.
    [string]$Version = ""
)
$ErrorActionPreference = "Stop"
$Setup = (Resolve-Path $Setup).Path
if (-not $Version) {
    if ((Split-Path $Setup -Leaf) -match "NetScope-Setup-(\d+\.\d+\.\d+)") { $Version = $Matches[1] } else { throw "pass -Version" }
}
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
Add-Type -Namespace "" -Name U -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr h); [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr h, int c);'

$results = New-Object System.Collections.Generic.List[string]
function Check([string]$name, [bool]$ok, [string]$detail = "") {
    $results.Add(("{0} {1}{2}" -f ($(if ($ok) { "PASS" } else { "FAIL" })), $name, $(if ($detail) { " — $detail" } else { "" })))
}
function WaitFor([scriptblock]$cond, [int]$seconds) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) { try { if (& $cond) { return $true } } catch {} ; Start-Sleep -Milliseconds 500 }
    return $false
}
function Json([string]$url) { Invoke-RestMethod -Uri $url -TimeoutSec 10 -UseBasicParsing }
function Shot([string]$file) {
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, "NetScopeMain")
    $w = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $c)
    if (-not $w) { return $false }
    $h = [IntPtr]$w.Current.NativeWindowHandle
    [void][U]::ShowWindow($h, 9); [void][U]::SetForegroundWindow($h); Start-Sleep -Seconds 2
    $r = $w.Current.BoundingRectangle
    $bmp = New-Object System.Drawing.Bitmap ([int]$r.Width), ([int]$r.Height)
    [System.Drawing.Graphics]::FromImage($bmp).CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, $bmp.Size)
    $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
    return $true
}
function Log { $f = Join-Path $data "netscope.log"; if (Test-Path $f) { Get-Content $f -Raw -Encoding UTF8 } else { "" } }

$data = Join-Path $env:LOCALAPPDATA "NetScope"
$backup = Join-Path $env:LOCALAPPDATA "NetScope.e2e-backup"
$app = Join-Path $env:LOCALAPPDATA "Programs\NetScope"
$keys = @("HKCU\Software\Classes\netscope", "HKCU\Software\Classes\AppUserModelId\NetScope.Desktop")
New-Item -ItemType Directory -Force $Work | Out-Null

# ---------- set the user's state aside ----------
Get-Process netscope-app, netscope -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $backup) { throw "$backup exists: a previous run did not restore it" }
if (Test-Path $data) { Rename-Item $data $backup }
# reg.exe reports success on stderr, which PowerShell 5.1 turns into an error under "Stop".
$i = 0; foreach ($k in $keys) { cmd.exe /c "reg export `"$k`" `"$(Join-Path $Work "key$i.reg")`" /y >nul 2>nul"; $i++ }

try {
    # ---------- install ----------
    $log = Join-Path $Work "install.log"
    $p = Start-Process $Setup -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/LANG=ru", '/TASKS="desktopicon,egress"', "/LOG=`"$log`"" -PassThru -Wait
    Check "silent install exits with 0" ($p.ExitCode -eq 0) "exit $($p.ExitCode)"
    foreach ($f in "netscope-app.exe", "netscope.exe", "WebView2Loader.dll", "netscope.ico", "LICENSE", "README.md", "scripts\fetch-geoip.ps1", "unins000.exe") {
        Check "installed $f" (Test-Path (Join-Path $app $f))
    }
    $ver = (& (Join-Path $app "netscope.exe") --version) -join ""
    Check "installed version" ($ver -eq "netscope $Version") $ver
    $ini = Get-Content (Join-Path $data "netscope.ini") -Raw -ErrorAction SilentlyContinue
    Check "settings file written by the installer" ($ini -match "egress_check=1" -and $ini -match "show_window=1" -and $ini -match "notifications=medium") ($ini -replace "`r?`n", " | ")
    $menu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\NetScope"
    Check "Start menu shortcuts" ((Test-Path "$menu\NetScope.lnk") -and (Test-Path "$menu\NetScope (console).lnk")) ((Get-ChildItem $menu -ErrorAction SilentlyContinue).Name -join ", ")
    $desktop = [Environment]::GetFolderPath("Desktop")
    Check "desktop shortcut (task chosen)" (Test-Path "$desktop\NetScope.lnk")
    $cmd = (Get-ItemProperty "HKCU:\Software\Classes\netscope\shell\open\command" -ErrorAction SilentlyContinue)."(default)"
    Check "netscope: protocol points to the installed program" ($cmd -eq "`"$app\netscope-app.exe`" `"%1`"") $cmd
    $aumid = Get-ItemProperty "HKCU:\Software\Classes\AppUserModelId\NetScope.Desktop" -ErrorAction SilentlyContinue
    Check "toast application id registered" ($aumid.DisplayName -eq "NetScope") $aumid.IconUri
    $run = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).NetScope
    Check "autostart not enabled (task not chosen)" (-not $run)
    $un = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{7D5B2C1E-5A7F-4E1B-9C3A-NETSCOPE0001}_is1" -ErrorAction SilentlyContinue
    Check "listed in Apps & features" ($un.DisplayName -eq "NetScope" -and $un.DisplayVersion -eq $Version) "$($un.DisplayName) $($un.DisplayVersion)"
    $ilog = Get-Content $log -Raw -Encoding Default
    Check "install log has no errors" (-not ($ilog -match "(?m)^.*(Error|Exception).*$")) ([regex]::Match($ilog, "(?m)^.*(Error|Exception).*$").Value)

    # ---------- run the installed program ----------
    Start-Process (Join-Path $app "netscope-app.exe")
    $up = WaitFor { Test-Path (Join-Path $data "dashboard.url") } 30
    $base = if ($up) { (Get-Content (Join-Path $data "dashboard.url") -Raw).Trim() } else { "" }
    Check "dashboard started" $up $base
    $h = $null; [void](WaitFor { $script:h = Json "$base/api/health"; $h.status -eq "ok" } 20)
    Check "health: ok, version $Version, capturing" ($h.status -eq "ok" -and $h.version -eq $Version -and $h.capture.state -eq "running") (($h | ConvertTo-Json -Compress))
    $win = WaitFor { $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, "NetScopeMain"); $null -ne [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children, $c) } 20
    Check "program window opened (WebView2)" $win
    # Some traffic of our own so the tables are not empty.
    foreach ($u in "https://example.org", "https://www.wikipedia.org", "https://github.com", "https://www.cloudflare.com") { try { Invoke-WebRequest $u -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {} }
    Start-Sleep -Seconds 6
    $s = Json "$base/api/stats"
    Check "traffic seen" ($s.hosts.Count -gt 0 -and $s.connection_count -gt 0) "hosts $($s.hosts.Count), connections $($s.connection_count)"
    Check "hosts carry their programs" (@($s.hosts | Where-Object { $_.processes.Count -gt 0 }).Count -gt 0) ((@($s.hosts | ForEach-Object { $_.processes }) | Select-Object -Unique) -join ", ")
    $dns = Json "$base/api/dns"
    Check "DNS journal with filter counts" ($dns.facets.qtype.Count -gt 0) (($dns.facets.qtype | ForEach-Object { "$($_[0])=$($_[1])" }) -join " ")
    $f = [uri]::EscapeDataString('{"rcode":["NOERROR"]}')
    $ok = Json "$base/api/dns?f=$f"
    Check "DNS field filter" (@($ok.entries | Where-Object { $_.rcode -ne "NOERROR" }).Count -eq 0 -and $ok.total -le $dns.total) "$($ok.total) of $($dns.total)"
    try { Invoke-WebRequest "$base/api/dns?f=%7B%22nope%22:[]%7D" -UseBasicParsing | Out-Null; $bad = 200 } catch { $bad = [int]$_.Exception.Response.StatusCode }
    Check "bad filter is a 400" ($bad -eq 400) "$bad"
    $q = [uri]::EscapeDataString("not lan and idle < 5m")
    $c = Json "$base/api/connections?q=$q"
    Check "connection filter with lan/idle" ($c.total -ge 0 -and @($c.connections | Where-Object { $_.lan }).Count -eq 0) "$($c.total) match"
    $st = Json "$base/api/settings"
    Check "settings page data" ($st.values.egress_check -eq $true -and $st.can_restart -eq $true) "egress_check=$($st.values.egress_check)"
    Check "journal answers" ((Json "$base/api/journal?kind=connections").total -ge 0)
    Check "screenshot: overview" (Shot (Join-Path $Work "1-overview.png"))

    # ---------- netscope: links and the single instance ----------
    Start-Process "netscope://open/map"
    Start-Sleep -Seconds 4
    Check "netscope://open/map reaches the running program" ((Log) -match "action: Open\(Some\(`"#/map`"\)\)")
    Check "screenshot: map via link" (Shot (Join-Path $Work "2-map.png"))
    Start-Process "netscope://mute/security"
    Start-Sleep -Seconds 4
    $muted = (Json "$base/api/settings").values.notify_categories
    Check "a link without the key cannot mute notifications" ((Log) -match "action not accepted" -and ($muted -contains "security")) ($muted -join ",")
    Start-Process (Join-Path $app "netscope-app.exe")
    Start-Sleep -Seconds 4
    $n = @(Get-Process netscope-app -ErrorAction SilentlyContinue).Count
    Check "second start keeps one instance" ($n -eq 1) "$n processes"
    Start-Process "netscope://open/hosts"
    Start-Sleep -Seconds 4
    Check "screenshot: hosts" (Shot (Join-Path $Work "3-hosts.png"))
    $errs = [regex]::Matches((Log), "(?m)^.*\b(ERROR|panicked)\b.*$") | ForEach-Object { $_.Value }
    Check "program log has no errors" ($errs.Count -eq 0) ($errs -join " / ")
    Copy-Item (Join-Path $data "netscope.log") (Join-Path $Work "netscope.log") -ErrorAction SilentlyContinue

    # ---------- uninstall ----------
    $p = Start-Process (Join-Path $app "unins000.exe") -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -PassThru -Wait
    Check "silent uninstall exits with 0" ($p.ExitCode -eq 0) "exit $($p.ExitCode)"
    # The uninstaller copies itself to %TEMP% and finishes there.
    [void](WaitFor { -not (Test-Path (Join-Path $app "netscope-app.exe")) } 30)
    [void](WaitFor { -not (Test-Path $app) } 15)
    Check "program stopped" (@(Get-Process netscope-app, netscope -ErrorAction SilentlyContinue).Count -eq 0)
    Check "program folder removed" (-not (Test-Path $app)) ((Get-ChildItem $app -Recurse -ErrorAction SilentlyContinue).FullName -join ", ")
    Check "shortcuts removed" (-not (Test-Path $menu) -and -not (Test-Path "$desktop\NetScope.lnk"))
    Check "protocol and app id removed" (-not (Test-Path "HKCU:\Software\Classes\netscope") -and -not (Test-Path "HKCU:\Software\Classes\AppUserModelId\NetScope.Desktop"))
    Check "removed from Apps & features" (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{7D5B2C1E-5A7F-4E1B-9C3A-NETSCOPE0001}_is1"))
    $left = (Get-ChildItem $data -ErrorAction SilentlyContinue).Name
    Check "kept: settings, state, journal; removed: logs, icons, WebView2 cache" (-not (($left -contains "netscope.log") -or ($left -contains "icons") -or ($left -contains "WebView2") -or ($left -contains "dashboard.url") -or ($left -contains "netscope.ico"))) ($left -join ", ")
}
catch {
    $results.Add("FAIL script error: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)")
}
finally {
    [System.IO.File]::WriteAllLines((Join-Path $Work "results.txt"), $results, (New-Object System.Text.UTF8Encoding($false)))
    $ErrorActionPreference = "Continue"
    # ---------- put the user's state back ----------
    Get-Process netscope-app, netscope -ErrorAction SilentlyContinue | Stop-Process -Force
    if (Test-Path (Join-Path $app "unins000.exe")) { Start-Process (Join-Path $app "unins000.exe") -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES" -Wait; Start-Sleep -Seconds 5 }
    if (Test-Path $backup) {
        if (Test-Path $data) { Remove-Item $data -Recurse -Force }
        Rename-Item $backup $data
    }
    $i = 0; foreach ($k in $keys) { $f = Join-Path $Work "key$i.reg"; if (Test-Path $f) { cmd.exe /c "reg import `"$f`" >nul 2>nul" }; $i++ }
    $restored = (Test-Path $data) -and -not (Test-Path $backup) -and (Test-Path "HKCU:\Software\Classes\netscope") -and (Test-Path "HKCU:\Software\Classes\AppUserModelId\NetScope.Desktop")
    Add-Content -Path (Join-Path $Work "results.txt") -Value ("restore: " + $(if ($restored) { "OK" } else { "INCOMPLETE" })) -Encoding UTF8
    $results
}
