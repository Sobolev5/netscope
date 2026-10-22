//! NetScope as a desktop program for Windows: its own window (the dashboard inside a
//! WebView2 control), an icon in the notification area, Windows notifications (toasts) for
//! alerts, no console. The analysis itself is `netscope::app::run_with`; this is the shell
//! around it.
//!
//! Notifications: a poller reads `/api/alerts`, keeps the ones the settings ask for (level,
//! categories, quiet hour) and hands them to the UI thread, which shows toasts (`toast.rs`)
//! with a category icon (`icons.rs`); a burst becomes one summary toast. Clicking a toast
//! starts `netscope://…` through the registered URL protocol, which a second instance
//! forwards to the running one (WM_COPYDATA). The tray menu switches all of this.
//!
//! Closing the window keeps NetScope running in the tray; "Quit" in the tray menu ends it.
//! Without the WebView2 runtime the dashboard opens in the default browser instead.
//!
//! Settings come from `%LOCALAPPDATA%\NetScope\netscope.ini` (written by the installer, the
//! dashboard's Settings page or by hand; see `netscope::settings`); command-line arguments,
//! when given, replace the capture settings. The Settings page can also ask for a restart:
//! the analyzer stops and starts again with the file, the window stays and is pointed at
//! the new dashboard. Logs go to `%LOCALAPPDATA%\NetScope\netscope.log`.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod icons;
#[cfg(windows)]
mod toast;
#[cfg(windows)]
mod webview;

#[cfg(not(windows))]
fn main() {
    eprintln!("netscope-app is the Windows desktop shell; on this platform run `netscope`");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    win::main();
}

#[cfg(windows)]
mod win {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
    use std::panic::AssertUnwindSafe;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, Instant};

    use clap::Parser;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
    use windows_sys::Win32::Graphics::Gdi::COLOR_WINDOW;
    use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
    use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE,
        REG_SZ,
    };
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow, GetSystemMetricsForDpi, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE,
        NIM_MODIFY, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CheckMenuRadioItem, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW,
        FindWindowW, GetClientRect, GetCursorPos, GetMenuItemCount, GetMessageW, GetSystemMetrics, IsIconic, LoadCursorW, LoadIconW,
        MessageBoxW, PostMessageW, PostQuitMessage, RegisterClassW, SendMessageTimeoutW, SetForegroundWindow, SetMenuDefaultItem, SetMenuItemInfoW,
        SetWindowPos, ShowWindow, TrackPopupMenu, TranslateMessage, CW_USEDEFAULT, SMTO_ABORTIFHUNG, SMTO_BLOCK, HMENU, IDC_ARROW, IDI_APPLICATION, IDYES, MB_ICONERROR,
        MB_ICONINFORMATION, MB_OK, MB_YESNO, MENUITEMINFOW, MF_BYCOMMAND, MF_CHECKED, MF_POPUP, MF_SEPARATOR, MF_STRING, MIIM_BITMAP, MINMAXINFO,
        MSG, SM_CXSCREEN, SM_CXSMICON, SM_CYSCREEN, SWP_NOACTIVATE, SWP_NOZORDER, SW_HIDE, SW_RESTORE, SW_SHOW, SW_SHOWNORMAL, TPM_BOTTOMALIGN,
        TPM_LEFTALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_COMMAND, WM_COPYDATA, WM_DESTROY, WM_DPICHANGED, WM_GETMINMAXINFO,
        WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_MOVE, WM_RBUTTONUP, WM_SETFOCUS, WM_SIZE, WNDCLASSW, WS_OVERLAPPEDWINDOW, WS_POPUP,
    };

    use netscope::analytics::text::{alert_text, category_label, kind_label};
    use netscope::analytics::{Alert, Category, Severity};
    use netscope::app;
    use netscope::capture::engine::unix_now;
    use netscope::cli::Args;
    use netscope::settings::{self, Settings, SettingsHost};

    use super::icons::{self, color, glyph};
    use super::toast;
    use super::webview::{self, WebView};

    const WM_TRAY: u32 = WM_APP + 1;
    const WM_READY: u32 = WM_APP + 2;
    const WM_FAILED: u32 = WM_APP + 3;
    const WM_SHOW_ME: u32 = WM_APP + 4;
    const WM_ALERT: u32 = WM_APP + 5;
    /// Sent to the main window to end the program (used by the test harness).
    const WM_QUIT_APP: u32 = WM_APP + 6;
    const ID_OPEN: usize = 1;
    const ID_BROWSER: usize = 2;
    const ID_AUTOSTART: usize = 4;
    const ID_GEOIP: usize = 5;
    const ID_LOG: usize = 6;
    const ID_QUIT: usize = 7;
    /// Notification level (radio items of the Notifications submenu).
    const ID_NOTIFY_MEDIUM: usize = 20;
    const ID_NOTIFY_HIGH: usize = 21;
    const ID_NOTIFY_OFF: usize = 22;
    /// Category check items: `ID_CAT_BASE + index in Category::ALL`.
    const ID_CAT_BASE: usize = 30;
    const ID_SNOOZE: usize = 40;
    const MAIN_CLASS: &str = "NetScopeMain";
    const TRAY_CLASS: &str = "NetScopeTray";
    /// `WM_COPYDATA.dwData` of a `netscope://` action forwarded by a second instance.
    const COPYDATA_ACTION: usize = 0x4E53_4341;
    /// "Quiet for an hour" from the tray menu or a toast button.
    const SNOOZE_SECS: i64 = 3600;
    /// Toasts shown one by one per poll; the rest of a burst become one summary toast.
    const BURST_LIMIT: usize = 3;
    /// Toasts per minute before everything is summarized.
    const RATE_LIMIT: usize = 6;
    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE: &str = "NetScope";
    const POWERSHELL: &str = r"WindowsPowerShell\v1.0\powershell.exe";
    const ALERT_POLL: Duration = Duration::from_secs(5);

    /// Shared between the analyzer thread, the alert poller and the window procedures.
    struct Shared {
        addr: Mutex<Option<SocketAddr>>,
        error: Mutex<Option<String>>,
        stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        tray_hwnd: Mutex<usize>,
        main_hwnd: Mutex<usize>,
        /// "Quit" was chosen: closing the window now really closes it.
        quitting: Mutex<bool>,
        hidden_hint_shown: Mutex<bool>,
        russian: bool,
        dir: PathBuf,
        geoip_present: bool,
        /// `show_window=0`: start silently in the tray (e.g. with Windows autostart).
        quiet_start: bool,
        /// The settings page asked for a restart: the analyzer thread starts over with the
        /// settings file when `run_with` returns, instead of ending the program.
        restart: AtomicBool,
        /// Real command-line arguments were given: the settings file is not what runs.
        from_cli: bool,
        /// The dashboard has been up once; later WM_READY messages are restarts.
        ready_once: AtomicBool,
        /// A restart happened: the alert poller forgets which alert ids it has seen.
        poller_reset: AtomicBool,
        /// A `netscope://` action given on the command line, run once the dashboard is up.
        pending_action: Mutex<Option<String>>,
    }
    static SHARED: OnceLock<Shared> = OnceLock::new();

    impl Shared {
        fn ini(&self) -> PathBuf {
            self.dir.join(settings::FILE_NAME)
        }
    }

    thread_local! {
        /// The browser control lives on the UI thread only.
        static WEBVIEW: RefCell<Option<WebView>> = const { RefCell::new(None) };
        /// The origin the control was created for (it only lets that origin through).
        static VIEW_ORIGIN: RefCell<String> = const { RefCell::new(String::new()) };
    }

    /// What the settings page may ask the desktop program to do.
    struct AppHost;

    impl SettingsHost for AppHost {
        fn autostart(&self) -> Option<bool> {
            Some(autostart_enabled())
        }
        fn set_autostart(&self, on: bool) -> Result<(), String> {
            set_autostart(on)
        }
        fn can_restart(&self) -> bool {
            true
        }
        /// Stops the analyzer like "Quit" does, with the restart flag set; the analyzer thread
        /// then reads the settings file again and starts over.
        fn request_restart(&self) -> Result<(), String> {
            if *lock(&shared().quitting) {
                return Err("NetScope is quitting".into());
            }
            let Some(tx) = lock(&shared().stop).take() else { return Err("a restart is already in progress".into()) };
            shared().restart.store(true, Ordering::SeqCst);
            let _ = tx.send(());
            Ok(())
        }
        fn started_from_cli(&self) -> bool {
            shared().from_cli
        }
        fn settings_path(&self) -> PathBuf {
            shared().ini()
        }
        fn log_path(&self) -> Option<PathBuf> {
            Some(shared().dir.join("netscope.log"))
        }
    }

    fn shared() -> &'static Shared {
        SHARED.get().expect("initialised in main")
    }

    /// Locks without ever panicking: the values in `Shared` are plain data that stay
    /// consistent even if another thread panicked while holding the lock.
    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Menu and message texts in the user's Windows language (Russian or English).
    fn text(key: &str) -> String {
        let ru = shared().russian;
        let s = match (key, ru) {
            ("open", true) => "Открыть NetScope",
            ("open", false) => "Open NetScope",
            ("browser", true) => "Открыть в браузере",
            ("browser", false) => "Open in the browser",
            ("notify", true) => "Уведомления",
            ("notify", false) => "Notifications",
            ("level_medium", true) => "Важные и средние",
            ("level_medium", false) => "High and medium",
            ("level_high", true) => "Только важные",
            ("level_high", false) => "High only",
            ("level_off", true) => "Выключены",
            ("level_off", false) => "Off",
            ("snooze", true) => "Не беспокоить час",
            ("snooze", false) => "Quiet for an hour",
            ("snoozed", true) => "Тихий режим до {t} — отменить",
            ("snoozed", false) => "Quiet until {t} — cancel",
            ("toast_open", true) => "Открыть",
            ("toast_open", false) => "Open",
            ("toast_mute", true) => "Не уведомлять: {c}",
            ("toast_mute", false) => "Mute: {c}",
            ("more_title", true) => "Ещё предупреждения",
            ("more_title", false) => "More alerts",
            ("more_body", true) => "Ещё {n} за последнюю минуту. Откройте NetScope, чтобы посмотреть.",
            ("more_body", false) => "{n} more in the last minute. Open NetScope to see them.",
            ("autostart", true) => "Запускать при входе в Windows",
            ("autostart", false) => "Start when I sign in",
            ("geoip", true) => "Скачать геоданные (страны и города)…",
            ("geoip", false) => "Download geolocation data…",
            ("log", true) => "Открыть журнал",
            ("log", false) => "Open log file",
            ("quit", true) => "Выход",
            ("quit", false) => "Quit",
            ("ready_title", true) => "NetScope запущен",
            ("ready_title", false) => "NetScope is running",
            ("ready", true) => "Панель: {url}\nЩёлкните значок, чтобы открыть её.",
            ("ready", false) => "Dashboard: {url}\nClick the icon to open it.",
            ("restarted_title", true) => "NetScope перезапущен",
            ("restarted_title", false) => "NetScope restarted",
            ("restarted", true) => "Новые настройки применены. Панель: {url}",
            ("restarted", false) => "The new settings are in effect. Dashboard: {url}",
            ("hidden_title", true) => "NetScope продолжает работать",
            ("hidden_title", false) => "NetScope keeps running",
            ("hidden", true) => "Окно закрыто, захват продолжается. Значок в трее: открыть снова или выйти.",
            ("hidden", false) => "The window is closed, capture goes on. Use the tray icon to reopen or quit.",
            ("starting", true) => "NetScope: запуск…",
            ("starting", false) => "NetScope: starting…",
            ("failed_title", true) => "NetScope не смог запуститься",
            ("failed_title", false) => "NetScope could not start",
            ("npcap_q", true) => "\n\nДля захвата трафика нужен драйвер Npcap. Открыть страницу загрузки npcap.com?",
            ("npcap_q", false) => "\n\nCapturing traffic needs the Npcap driver. Open the npcap.com download page?",
            ("no_webview", true) => "Среда WebView2 недоступна ({e}) — панель открыта в браузере.",
            ("no_webview", false) => "WebView2 is not available ({e}) — the dashboard opened in the browser.",
            ("geoip_started", true) => "Загрузка началась в отдельном окне. Когда она закончится, перезапустите NetScope.",
            ("geoip_started", false) => "The download runs in its own window. Restart NetScope when it has finished.",
            ("geoip_fail", true) => "Не удалось запустить загрузку: {e}",
            ("geoip_fail", false) => "Could not start the download: {e}",
            ("log_hint", true) => "Подробности в журнале: {log}",
            ("log_hint", false) => "Details are in the log: {log}",
            _ => key,
        };
        s.to_string()
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn fill(buf: &mut [u16], s: &str) {
        let w: Vec<u16> = s.encode_utf16().take(buf.len() - 1).collect();
        buf[..w.len()].copy_from_slice(&w);
        buf[w.len()] = 0;
    }

    // ----- settings (netscope.ini; the parsing lives in netscope::settings) -----

    /// Command-line arguments: the real ones (`real` includes the program name) when given,
    /// otherwise built from the settings file.
    fn args(real: &[String], ini: &Path) -> Result<Args, String> {
        if real.len() > 1 {
            return Args::try_parse_from(real).map_err(|e| e.to_string());
        }
        Args::try_parse_from(Settings::load(ini).to_args("netscope-app")).map_err(|e| format!("{}: {e}", ini.display()))
    }

    /// The notification settings, read from the file every time so a change on the Settings
    /// page or in the tray menu applies without a restart.
    fn notify_settings() -> Settings {
        Settings::load(&shared().ini())
    }

    fn save_setting(key: &str, value: &str) {
        if let Err(e) = settings::write_setting(&shared().ini(), key, value) {
            tracing::warn!("cannot save {key}: {e}");
        }
    }

    /// `HH:MM` of a unix time in local time (for "quiet until …").
    fn clock(ts: i64) -> String {
        // SAFETY: plain conversions of a timestamp; both structures are written by the calls.
        unsafe {
            use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
            use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
            // 100 ns intervals since 1601-01-01; out of range (the settings clamp it, but the
            // file can be edited by hand) shows nothing rather than overflowing.
            let Some(ft) = u64::try_from(ts).ok().and_then(|t| t.checked_add(11_644_473_600)).and_then(|t| t.checked_mul(10_000_000)) else {
                return String::new();
            };
            let ft = FILETIME { dwLowDateTime: ft as u32, dwHighDateTime: (ft >> 32) as u32 };
            let mut utc: SYSTEMTIME = std::mem::zeroed();
            let mut local: SYSTEMTIME = std::mem::zeroed();
            if FileTimeToSystemTime(&ft, &mut utc) == 0 || SystemTimeToTzSpecificLocalTime(null(), &utc, &mut local) == 0 {
                return String::new();
            }
            format!("{:02}:{:02}", local.wHour, local.wMinute)
        }
    }

    /// Log to a file: there is no console. The previous run is kept as `.1`.
    fn init_logging(dir: &Path, verbose: u8) {
        let log = dir.join("netscope.log");
        let _ = fs::rename(&log, dir.join("netscope.log.1"));
        let Ok(file) = File::create(&log) else { return };
        let level = match verbose {
            0 => "netscope=info",
            1 => "netscope=debug",
            _ => "netscope=trace",
        };
        let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_target(false).with_writer(Mutex::new(file)).try_init();
    }

    fn open_url(url: &str) {
        // SAFETY: all strings are NUL-terminated UTF-16 buffers that outlive the call.
        unsafe { ShellExecuteW(null_mut(), wide("open").as_ptr(), wide(url).as_ptr(), null(), null(), SW_SHOWNORMAL) };
    }

    fn message(title: &str, body: &str, flags: u32) -> i32 {
        let hwnd = *lock(&shared().main_hwnd) as HWND;
        // SAFETY: valid NUL-terminated buffers; a null owner window is allowed.
        unsafe { MessageBoxW(hwnd, wide(body).as_ptr(), wide(title).as_ptr(), flags) }
    }

    fn dashboard_url() -> String {
        lock(&shared().addr).map(app::dashboard_url).unwrap_or_else(|| "http://127.0.0.1:8888".into())
    }

    /// Where this process reaches the dashboard: a wildcard bind (`0.0.0.0`, `::`) is not
    /// connectable itself, the loopback address of the same family is.
    fn local_addr(addr: SocketAddr) -> SocketAddr {
        match addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port()),
            IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::new(Ipv6Addr::LOCALHOST.into(), addr.port()),
            _ => addr,
        }
    }

    // ----- autostart (HKCU\...\Run) -----

    fn with_run_key<T>(access: u32, f: impl FnOnce(HKEY) -> T) -> Option<T> {
        let mut key: HKEY = null_mut();
        // SAFETY: the subkey string is NUL-terminated; `key` receives a handle we close below.
        unsafe {
            if RegOpenKeyExW(HKEY_CURRENT_USER, wide(RUN_KEY).as_ptr(), 0, access, &mut key) != ERROR_SUCCESS {
                return None;
            }
            let r = f(key);
            RegCloseKey(key);
            Some(r)
        }
    }

    fn autostart_enabled() -> bool {
        with_run_key(KEY_QUERY_VALUE, |key| {
            let mut size = 0u32;
            // SAFETY: querying only the size; no data buffer is written.
            unsafe { RegQueryValueExW(key, wide(RUN_VALUE).as_ptr(), null_mut(), null_mut(), null_mut(), &mut size) == ERROR_SUCCESS }
        })
        .unwrap_or(false)
    }

    fn set_autostart(on: bool) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| format!("cannot find the program path: {e}"))?;
        let cmd = wide(&format!("\"{}\"", exe.display()));
        let status = with_run_key(KEY_SET_VALUE, |key| {
            // SAFETY: `cmd` is a NUL-terminated UTF-16 string and the byte length matches it.
            unsafe {
                if on {
                    RegSetValueExW(key, wide(RUN_VALUE).as_ptr(), 0, REG_SZ, cmd.as_ptr().cast::<u8>(), (cmd.len() * 2) as u32)
                } else {
                    RegDeleteValueW(key, wide(RUN_VALUE).as_ptr())
                }
            }
        });
        match status {
            Some(ERROR_SUCCESS) => Ok(()),
            Some(ERROR_FILE_NOT_FOUND) if !on => Ok(()),
            Some(code) => Err(format!("registry error {code}")),
            None => Err("cannot open the Run key in the registry".into()),
        }
    }

    // ----- geolocation data -----

    fn geoip_dir(dir: &Path) -> PathBuf {
        dir.join("geoip")
    }

    fn geoip_present(dir: &Path) -> bool {
        netscope::geo::candidate_dirs(None).iter().chain([geoip_dir(dir)].iter()).any(|d| d.join("dbip-city-lite.mmdb").exists())
    }

    /// Runs the bundled download script in its own console window.
    fn download_geoip() {
        let script = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("scripts").join("fetch-geoip.ps1")));
        let Some(script) = script.filter(|s| s.exists()) else {
            message(&text("failed_title"), &text("geoip_fail").replace("{e}", "fetch-geoip.ps1 not found next to the program"), MB_OK | MB_ICONERROR);
            return;
        };
        let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into())).join("System32").join(POWERSHELL);
        let r = std::process::Command::new(powershell)
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-File"])
            .arg(script)
            .arg("-Dir")
            .arg(geoip_dir(&shared().dir))
            .spawn();
        match r {
            Ok(_) => message("NetScope", &text("geoip_started"), MB_OK | MB_ICONINFORMATION),
            Err(e) => message(&text("failed_title"), &text("geoip_fail").replace("{e}", &e.to_string()), MB_OK | MB_ICONERROR),
        };
    }

    // ----- tray icon -----

    fn app_icon() -> *mut std::ffi::c_void {
        // SAFETY: resource 1 is the icon embedded by build.rs; a missing resource falls back
        // to the stock application icon.
        unsafe {
            let icon = LoadIconW(GetModuleHandleW(null()), std::ptr::without_provenance(1)); // MAKEINTRESOURCE(1)
            if icon.is_null() {
                LoadIconW(null_mut(), IDI_APPLICATION)
            } else {
                icon
            }
        }
    }

    fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
        // SAFETY: an all-zero NOTIFYICONDATAW is a valid starting point; fields are set below.
        let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        d.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        d.hWnd = hwnd;
        d.uID = 1;
        d
    }

    fn add_icon(hwnd: HWND) {
        let mut d = icon_data(hwnd);
        d.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        d.uCallbackMessage = WM_TRAY;
        d.hIcon = app_icon();
        fill(&mut d.szTip, &text("starting"));
        // SAFETY: `d` is fully initialised for the flags given.
        unsafe { Shell_NotifyIconW(NIM_ADD, &d) };
    }

    /// A notification from the tray icon (Windows shows these as toasts in the Action Center).
    fn balloon(title: &str, body: &str, level: u32) {
        let hwnd = *lock(&shared().tray_hwnd) as HWND;
        let mut d = icon_data(hwnd);
        d.uFlags = NIF_INFO | NIF_TIP;
        d.dwInfoFlags = level;
        fill(&mut d.szInfoTitle, title);
        fill(&mut d.szInfo, body);
        fill(&mut d.szTip, &format!("NetScope — {}", dashboard_url()));
        // SAFETY: `d` is fully initialised for the flags given.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
    }

    fn remove_icon(hwnd: HWND) {
        let d = icon_data(hwnd);
        // SAFETY: identifies the icon by window and id only.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &d) };
    }

    // ----- notifications (toasts, balloons as the fallback) -----

    fn icon_dir() -> PathBuf {
        shared().dir.join("icons")
    }

    /// The category badge (white glyph on a coloured circle) for toasts; `None` when it
    /// cannot be drawn (the toast then shows the application icon).
    fn badge(category: Option<Category>) -> Option<PathBuf> {
        let (name, g, c) = match category {
            Some(Category::Security) => ("security", glyph::SHIELD, color::SECURITY),
            Some(Category::Novelty) => ("novelty", glyph::EYE, color::NOVELTY),
            Some(Category::Network) => ("network", glyph::NETWORK, color::NETWORK),
            Some(Category::Routes) => ("routes", glyph::MAP_PIN, color::ROUTES),
            None => ("info", glyph::INFO, color::INFO),
        };
        match icons::badge_png(&icon_dir(), name, g, c, 96) {
            Ok(p) => Some(p),
            Err(e) => {
                warn_once(&format!("notification icons unavailable: {e}"));
                None
            }
        }
    }

    /// Logs a message once per process (the same failure would repeat with every toast).
    fn warn_once(msg: &str) {
        static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let mut seen = lock(&SEEN);
        if !seen.iter().any(|m| m == msg) {
            tracing::warn!("{msg}");
            seen.push(msg.to_string());
        }
    }

    /// An informational notification (started, restarted, hidden): a toast, else a balloon.
    fn notify(title: &str, body: &str, level: u32) {
        let image = badge(None);
        let t = toast::Toast {
            title,
            body,
            attribution: "",
            image: image.as_deref(),
            launch: "netscope://open",
            actions: &[],
            tag: "info",
            group: "netscope",
            sound: false,
        };
        if let Err(e) = toast::show(&t) {
            warn_once(&format!("toast notifications unavailable, using tray balloons: {e}"));
            balloon(title, body, level);
        }
    }

    /// Shows the alerts the poller found: up to `BURST_LIMIT` toasts per batch and
    /// `RATE_LIMIT` per minute, the rest as one "N more" toast. That toast is replaced in
    /// place, so its count keeps adding up while the bursts go on (until a minute passes
    /// without one), and it makes a sound when a high-severity alert is folded into it.
    fn notify_alerts(alerts: Vec<Alert>) {
        thread_local! {
            static SHOWN: RefCell<VecDeque<Instant>> = const { RefCell::new(VecDeque::new()) };
            /// Alerts in the current "N more" toast and when it was last updated.
            static SUMMARY: RefCell<(usize, Option<Instant>)> = const { RefCell::new((0, None)) };
        }
        let ru = shared().russian;
        let now = Instant::now();
        SHOWN.with(|s| s.borrow_mut().retain(|t| now.duration_since(*t) < Duration::from_secs(60)));
        let mut shown = 0usize;
        let mut extra = 0usize;
        let mut extra_high = false;
        for a in &alerts {
            if shown >= BURST_LIMIT || SHOWN.with(|s| s.borrow().len()) >= RATE_LIMIT {
                extra += 1;
                extra_high |= a.severity == Severity::High;
                continue;
            }
            show_alert(a, ru);
            shown += 1;
            SHOWN.with(|s| s.borrow_mut().push_back(now));
        }
        if extra > 0 {
            let total = SUMMARY.with(|s| {
                let mut s = s.borrow_mut();
                let (count, at) = *s;
                let count = if at.is_some_and(|t| now.duration_since(t) < Duration::from_secs(60)) { count } else { 0 };
                *s = (count + extra, Some(now));
                count + extra
            });
            let title = text("more_title");
            let body = text("more_body").replace("{n}", &total.to_string());
            let image = badge(None);
            let t = toast::Toast {
                title: &title,
                body: &body,
                attribution: "NetScope",
                image: image.as_deref(),
                launch: "netscope://open/alerts",
                actions: &[],
                tag: "summary",
                group: "netscope",
                sound: extra_high,
            };
            if toast::show(&t).is_err() {
                balloon(&title, &body, NIIF_INFO);
            }
        }
    }

    fn show_alert(a: &Alert, ru: bool) {
        let title = kind_label(a.kind, ru).to_string();
        let body = alert_text(a, ru);
        let category = category_label(a.category, ru);
        let attribution = format!("NetScope · {category}");
        let image = badge(Some(a.category));
        let actions = [
            (text("toast_open"), "netscope://open/alerts".to_string()),
            (text("toast_mute").replace("{c}", category), format!("netscope://mute/{}?k={}", a.category.name(), action_key())),
        ];
        let actions: Vec<(&str, String)> = actions.iter().map(|(l, u)| (l.as_str(), u.clone())).collect();
        let tag = a.id.to_string();
        let t = toast::Toast {
            title: &title,
            body: &body,
            attribution: &attribution,
            image: image.as_deref(),
            launch: "netscope://open/alerts",
            actions: &actions,
            tag: &tag,
            group: a.category.name(),
            sound: a.severity == Severity::High,
        };
        if let Err(e) = toast::show(&t) {
            warn_once(&format!("toast notifications unavailable, using tray balloons: {e}"));
            balloon(&title, &body, if a.severity == Severity::High { NIIF_ERROR } else { NIIF_WARNING });
        }
    }

    // ----- netscope:// actions (toast clicks, second instance) -----

    /// What a `netscope://…` URL asks for.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Action {
        /// Bring the window up, optionally at a dashboard route (`#/alerts`).
        Open(Option<String>),
        /// Quiet hour on (`Some(seconds)`) or off (`None`).
        Snooze(Option<i64>),
        /// Stop notifying about a category.
        Mute(Category),
    }

    /// A random key of this process, put into the toast buttons that change settings. Any web
    /// page can start a `netscope://` URL, so only `open` is accepted without it: a page must
    /// not be able to mute the security notifications. Buttons of toasts from an earlier run
    /// carry an old key and only open the window.
    fn action_key() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| {
            use std::hash::{BuildHasher, Hasher};
            // `RandomState` keys come from the OS random source: unguessable for a web page,
            // which is all this guards against (local programs can edit the settings anyway).
            let part = |salt: u64| {
                let mut h = std::collections::hash_map::RandomState::new().build_hasher();
                h.write_u64(salt);
                h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
                h.write_u32(std::process::id());
                h.finish()
            };
            format!("{:016x}{:016x}", part(1), part(2))
        })
    }

    /// Parses a `netscope://…` URL; actions other than `open` need `?k=<key>` (`action_key`).
    fn parse_action(url: &str, key: &str) -> Option<Action> {
        let rest = url.strip_prefix(&format!("{}://", toast::SCHEME))?;
        let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
        let keyed = !key.is_empty() && query.split('&').any(|kv| kv.strip_prefix("k=") == Some(key));
        let rest = rest.trim_end_matches('/');
        let mut parts = rest.splitn(2, '/');
        match (parts.next()?, parts.next()) {
            ("open", None) => Some(Action::Open(None)),
            ("open", Some(route)) if route.chars().all(|c| c.is_ascii_alphanumeric() || "/-_".contains(c)) => Some(Action::Open(Some(format!("#/{route}")))),
            _ if !keyed => None,
            ("snooze", Some(min)) => Some(Action::Snooze(Some(min.parse::<i64>().ok().filter(|m| (1..=24 * 60).contains(m))? * 60))),
            ("snooze", None) => Some(Action::Snooze(Some(SNOOZE_SECS))),
            ("unsnooze", None) => Some(Action::Snooze(None)),
            ("mute", Some(c)) => Category::parse(c).map(Action::Mute),
            _ => None,
        }
    }

    /// Runs a `netscope://` URL from a toast or a second instance. One that is not accepted
    /// (unknown, or a settings change without this run's key) only brings the window up.
    fn run_action(url: &str) {
        match parse_action(url, action_key()) {
            Some(action) => perform(action),
            None => {
                tracing::warn!("action not accepted, opening the window instead: {}", url.split('?').next().unwrap_or(url));
                show_main();
            }
        }
    }

    fn perform(action: Action) {
        tracing::info!("action: {action:?}");
        match action {
            Action::Open(route) => {
                show_main();
                if let Some(route) = route {
                    let url = dashboard_url();
                    let navigated = WEBVIEW.with(|w| match w.borrow().as_ref() {
                        Some(v) => {
                            v.navigate(&format!("{url}/?app=1{route}"));
                            true
                        }
                        None => false,
                    });
                    if !navigated && (*lock(&shared().main_hwnd) as HWND).is_null() {
                        open_url(&format!("{url}/{route}"));
                    }
                }
            }
            Action::Snooze(Some(secs)) => save_setting("notify_snooze_until", &(unix_now() + secs).to_string()),
            Action::Snooze(None) => save_setting("notify_snooze_until", "0"),
            Action::Mute(c) => {
                let cats: Vec<&str> = notify_settings().notify_categories.iter().filter(|x| **x != c).map(|x| x.name()).collect();
                save_setting("notify_categories", &cats.join(","));
            }
        }
    }

    /// Hands a `netscope://` URL to the running instance's tray window; `false` when there
    /// is none (or it is elevated and this process is not).
    fn forward_action(url: &str) -> bool {
        let mut data = url.as_bytes().to_vec();
        let cds = COPYDATASTRUCT { dwData: COPYDATA_ACTION, cbData: data.len() as u32, lpData: data.as_mut_ptr().cast() };
        // SAFETY: the structure and its buffer outlive the synchronous SendMessageTimeoutW call.
        unsafe {
            let other = FindWindowW(wide(TRAY_CLASS).as_ptr(), null());
            let mut result = 0usize;
            !other.is_null()
                && SendMessageTimeoutW(other, WM_COPYDATA, 0, &cds as *const COPYDATASTRUCT as LPARAM, SMTO_ABORTIFHUNG | SMTO_BLOCK, 5000, &mut result) != 0
                && result != 0
        }
    }

    /// Puts a glyph next to a menu item (by command id, or by position for submenus).
    fn set_menu_icon(menu: HMENU, item: u32, by_position: bool, g: char, px: i32) {
        match icons::menu_bitmap(g, px) {
            Ok(h) => {
                // SAFETY: an all-zero MENUITEMINFOW with the size and the one field set is valid.
                unsafe {
                    let mut mi: MENUITEMINFOW = std::mem::zeroed();
                    mi.cbSize = std::mem::size_of::<MENUITEMINFOW>() as u32;
                    mi.fMask = MIIM_BITMAP;
                    mi.hbmpItem = h;
                    SetMenuItemInfoW(menu, item, i32::from(by_position), &mi);
                }
            }
            Err(e) => warn_once(&format!("menu icons unavailable: {e}")),
        }
    }

    fn show_menu(hwnd: HWND) {
        let checked = |on: bool| if on { MF_CHECKED } else { 0 };
        let s = notify_settings();
        let now = unix_now();
        let ru = shared().russian;
        let snoozed = s.notify_snooze_until > now;
        // SAFETY: standard popup-menu sequence; every handle is checked and destroyed.
        unsafe {
            let px = GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem()).max(16);
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            let item = |menu: HMENU, flags: u32, id: usize, label: &str, g: Option<char>| {
                AppendMenuW(menu, MF_STRING | flags, id, wide(label).as_ptr());
                if let Some(g) = g {
                    set_menu_icon(menu, id as u32, false, g, px);
                }
            };
            item(menu, 0, ID_OPEN, &text("open"), Some(glyph::OPEN_WINDOW));
            SetMenuDefaultItem(menu, ID_OPEN as u32, 0);
            item(menu, 0, ID_BROWSER, &text("browser"), Some(glyph::GLOBE));
            AppendMenuW(menu, MF_SEPARATOR, 0, null());

            // Notifications: level, categories, quiet hour.
            let sub = CreatePopupMenu();
            if !sub.is_null() {
                item(sub, 0, ID_NOTIFY_MEDIUM, &text("level_medium"), None);
                item(sub, 0, ID_NOTIFY_HIGH, &text("level_high"), None);
                item(sub, 0, ID_NOTIFY_OFF, &text("level_off"), None);
                let level = match s.notifications.as_str() {
                    "off" => ID_NOTIFY_OFF,
                    "high" => ID_NOTIFY_HIGH,
                    _ => ID_NOTIFY_MEDIUM,
                };
                CheckMenuRadioItem(sub, ID_NOTIFY_MEDIUM as u32, ID_NOTIFY_OFF as u32, level as u32, MF_BYCOMMAND);
                AppendMenuW(sub, MF_SEPARATOR, 0, null());
                for (i, c) in Category::ALL.iter().enumerate() {
                    let g = match c {
                        Category::Security => glyph::SHIELD,
                        Category::Novelty => glyph::EYE,
                        Category::Network => glyph::NETWORK,
                        Category::Routes => glyph::MAP_PIN,
                    };
                    item(sub, checked(s.notify_categories.contains(c)), ID_CAT_BASE + i, category_label(*c, ru), Some(g));
                }
                AppendMenuW(sub, MF_SEPARATOR, 0, null());
                let snooze_label = if snoozed { text("snoozed").replace("{t}", &clock(s.notify_snooze_until)) } else { text("snooze") };
                item(sub, checked(snoozed), ID_SNOOZE, &snooze_label, Some(glyph::QUIET));
                AppendMenuW(menu, MF_POPUP | MF_STRING, sub as usize, wide(&text("notify")).as_ptr());
                let bell = if s.notifications == "off" || snoozed { glyph::BELL_OFF } else { glyph::BELL };
                // A submenu has no command id: its icon is set by position (the item just added).
                set_menu_icon(menu, GetMenuItemCount(menu).max(1) as u32 - 1, true, bell, px);
            }

            item(menu, checked(autostart_enabled()), ID_AUTOSTART, &text("autostart"), Some(glyph::STARTUP));
            if !shared().geoip_present {
                item(menu, 0, ID_GEOIP, &text("geoip"), Some(glyph::DOWNLOAD));
            }
            item(menu, 0, ID_LOG, &text("log"), Some(glyph::DOCUMENT));
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            item(menu, 0, ID_QUIT, &text("quit"), Some(glyph::POWER));
            let mut pt = std::mem::zeroed();
            GetCursorPos(&mut pt);
            // Without this the menu does not close when the user clicks elsewhere.
            SetForegroundWindow(hwnd);
            let cmd = TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, null());
            // Destroying the menu destroys its submenus too.
            DestroyMenu(menu);
            PostMessageW(hwnd, 0, 0, 0);
            if cmd > 0 {
                command(cmd as usize);
            }
        }
    }

    fn command(id: usize) {
        match id {
            ID_OPEN => show_main(),
            ID_BROWSER => open_url(&dashboard_url()),
            ID_NOTIFY_MEDIUM => save_setting("notifications", "medium"),
            ID_NOTIFY_HIGH => save_setting("notifications", "high"),
            ID_NOTIFY_OFF => save_setting("notifications", "off"),
            ID_SNOOZE => {
                let s = notify_settings();
                perform(Action::Snooze((s.notify_snooze_until <= unix_now()).then_some(SNOOZE_SECS)));
            }
            id if (ID_CAT_BASE..ID_CAT_BASE + Category::ALL.len()).contains(&id) => {
                let c = Category::ALL[id - ID_CAT_BASE];
                let mut cats = notify_settings().notify_categories;
                if cats.contains(&c) {
                    cats.retain(|x| *x != c);
                } else {
                    cats.push(c);
                    cats.sort_by_key(|x| Category::ALL.iter().position(|y| y == x));
                }
                let names: Vec<&str> = cats.iter().map(|x| x.name()).collect();
                save_setting("notify_categories", &names.join(","));
            }
            ID_AUTOSTART => {
                if let Err(e) = set_autostart(!autostart_enabled()) {
                    tracing::warn!("autostart: {e}");
                }
            }
            ID_GEOIP => download_geoip(),
            ID_LOG => open_url(&shared().dir.join("netscope.log").display().to_string()),
            ID_QUIT => quit(),
            _ => {}
        }
    }

    fn quit() {
        *lock(&shared().quitting) = true;
        if let Some(tx) = lock(&shared().stop).take() {
            let _ = tx.send(());
        }
        WEBVIEW.with(|w| w.borrow_mut().take());
        let main = *lock(&shared().main_hwnd) as HWND;
        let tray = *lock(&shared().tray_hwnd) as HWND;
        remove_icon(tray);
        // SAFETY: destroying our own windows and ending this thread's message loop.
        unsafe {
            if !main.is_null() {
                DestroyWindow(main);
            }
            PostQuitMessage(0);
        }
    }

    // ----- main window with the dashboard -----

    /// Brings the program window up; without one (no WebView2) the browser is used.
    fn show_main() {
        let hwnd = *lock(&shared().main_hwnd) as HWND;
        if hwnd.is_null() {
            open_url(&dashboard_url());
            return;
        }
        // SAFETY: our own window handle.
        unsafe {
            ShowWindow(hwnd, if IsIconic(hwnd) != 0 { SW_RESTORE } else { SW_SHOW });
            SetForegroundWindow(hwnd);
        }
        WEBVIEW.with(|w| {
            if let Some(v) = w.borrow().as_ref() {
                v.set_visible(true);
                v.focus();
            }
        });
    }

    fn create_main_window() -> HWND {
        // SAFETY: standard window-class registration; the strings live for the whole process.
        unsafe {
            let module = GetModuleHandleW(null());
            let class = wide(MAIN_CLASS);
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(main_wndproc);
            wc.hInstance = module;
            wc.hIcon = app_icon();
            wc.hCursor = LoadCursorW(null_mut(), IDC_ARROW);
            wc.hbrBackground = (COLOR_WINDOW + 1) as usize as _;
            wc.lpszClassName = class.as_ptr();
            RegisterClassW(&wc);
            // A comfortable default: most of the screen on laptops, 1320×860 logical pixels
            // on big monitors (the process is DPI aware, so metrics are physical pixels).
            let scale = GetDpiForSystem().max(96) as f32 / 96.0;
            let (sw, sh) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
            let w = (sw * 9 / 10).min((1320.0 * scale) as i32).max(640);
            let h = (sh * 9 / 10).min((860.0 * scale) as i32).max(480);
            let (x, y) = if sw > 0 && sh > 0 { ((sw - w) / 2, (sh - h) / 2) } else { (CW_USEDEFAULT, CW_USEDEFAULT) };
            CreateWindowExW(0, class.as_ptr(), wide("NetScope").as_ptr(), WS_OVERLAPPEDWINDOW, x, y, w, h, null_mut(), null_mut(), module, null())
        }
    }

    fn client_size(hwnd: HWND) -> (i32, i32) {
        let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        // SAFETY: our own window handle; `r` is written by the call.
        unsafe { GetClientRect(hwnd, &mut r) };
        (r.right - r.left, r.bottom - r.top)
    }

    unsafe extern "system" fn main_wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        match msg {
            WM_SIZE => {
                let (w, h) = ((lparam & 0xffff) as i32, ((lparam >> 16) & 0xffff) as i32);
                WEBVIEW.with(|v| {
                    if let Some(v) = v.borrow().as_ref() {
                        v.resize(w, h);
                    }
                });
                0
            }
            WM_MOVE => {
                WEBVIEW.with(|v| {
                    if let Some(v) = v.borrow().as_ref() {
                        v.parent_moved();
                    }
                });
                0
            }
            WM_SETFOCUS => {
                WEBVIEW.with(|v| {
                    if let Some(v) = v.borrow().as_ref() {
                        v.focus();
                    }
                });
                0
            }
            WM_GETMINMAXINFO => {
                let info = lparam as *mut MINMAXINFO;
                if !info.is_null() {
                    // The DPI of the monitor the window is on (0 for an invalid window).
                    let dpi = match GetDpiForWindow(hwnd) {
                        0 => GetDpiForSystem(),
                        d => d,
                    };
                    let scale = dpi.max(96) as f32 / 96.0;
                    (*info).ptMinTrackSize.x = (720.0 * scale) as i32;
                    (*info).ptMinTrackSize.y = (480.0 * scale) as i32;
                }
                0
            }
            WM_DPICHANGED => {
                // Windows suggests the new size and position for the new monitor DPI.
                let r = lparam as *const RECT;
                if !r.is_null() {
                    let r = &*r;
                    SetWindowPos(hwnd, null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
                }
                0
            }
            WM_CLOSE => {
                if *lock(&shared().quitting) {
                    DestroyWindow(hwnd);
                } else {
                    // Closing the window keeps the capture running in the tray.
                    ShowWindow(hwnd, SW_HIDE);
                    WEBVIEW.with(|v| {
                        if let Some(v) = v.borrow().as_ref() {
                            v.set_visible(false);
                        }
                    });
                    let mut shown = lock(&shared().hidden_hint_shown);
                    if !*shown {
                        *shown = true;
                        notify(&text("hidden_title"), &text("hidden"), NIIF_INFO);
                    }
                }
                0
            }
            WM_SHOW_ME => {
                show_main();
                0
            }
            WM_QUIT_APP => {
                quit();
                0
            }
            WM_DESTROY => {
                *lock(&shared().main_hwnd) = 0;
                WEBVIEW.with(|w| w.borrow_mut().take());
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    fn quiet() -> bool {
        shared().quiet_start || std::env::var_os("NETSCOPE_NO_BROWSER").is_some()
    }

    /// Starts a WebView2 control showing the dashboard at `url` inside `hwnd`; `show` brings
    /// the window up once the control is ready. A failure reported later destroys the window
    /// and falls back to the browser.
    fn attach_webview(hwnd: HWND, url: &str, show: bool) -> Result<(), String> {
        let hwnd_n = hwnd as usize;
        let origin = url.to_string();
        let done = Box::new(move |r: Result<WebView, String>| {
            // WebView2 reports asynchronously: by now "Quit" may have destroyed the window.
            // Then there is nothing to host the view in; dropping it closes the browser.
            if *lock(&shared().quitting) || *lock(&shared().main_hwnd) != hwnd_n {
                tracing::debug!("WebView2 finished after the window was closed; ignored");
                return;
            }
            match r {
                Ok(view) => {
                    tracing::info!("dashboard window ready");
                    let (w, h) = client_size(hwnd_n as HWND);
                    view.resize(w, h);
                    WEBVIEW.with(|slot| *slot.borrow_mut() = Some(view));
                    VIEW_ORIGIN.with(|o| *o.borrow_mut() = origin);
                    if show {
                        show_main();
                    }
                }
                Err(e) => {
                    tracing::warn!("{e}; using the default browser");
                    // SAFETY: our own window.
                    unsafe { DestroyWindow(hwnd_n as HWND) };
                    *lock(&shared().main_hwnd) = 0;
                    if show {
                        open_url(&dashboard_url());
                    }
                }
            }
        });
        // `?app=1` tells the page it is inside the program window (no browser-notification button:
        // alerts arrive as Windows notifications from this process instead).
        let page = format!("{url}/?app=1");
        webview::create(hwnd, &shared().dir.join("WebView2"), url.to_string(), page, open_url, done)
    }

    /// The dashboard is up again after a restart from the Settings page: point the existing
    /// window at it. The control only lets its own origin through, so a new port means a
    /// new control; without a window the browser is opened when the address changed.
    fn on_restarted() {
        let url = dashboard_url();
        let url_file = shared().dir.join("dashboard.url");
        let old = fs::read_to_string(&url_file).unwrap_or_default();
        let _ = fs::write(&url_file, &url);
        shared().poller_reset.store(true, Ordering::SeqCst);
        notify(&text("restarted_title"), &text("restarted").replace("{url}", &url), NIIF_INFO);
        let hwnd = *lock(&shared().main_hwnd) as HWND;
        if hwnd.is_null() {
            if old.trim() != url && !quiet() {
                open_url(&url);
            }
            return;
        }
        let same_origin = VIEW_ORIGIN.with(|o| *o.borrow() == url);
        let navigated = WEBVIEW.with(|w| match w.borrow().as_ref() {
            Some(v) if same_origin => {
                v.navigate(&format!("{url}/?app=1"));
                true
            }
            _ => false,
        });
        if navigated {
            return;
        }
        tracing::info!("dashboard moved to {url}; recreating the browser control");
        WEBVIEW.with(|w| w.borrow_mut().take());
        if let Err(e) = attach_webview(hwnd, &url, false) {
            tracing::warn!("{e}; using the default browser");
            // SAFETY: our own window.
            unsafe { DestroyWindow(hwnd) };
            *lock(&shared().main_hwnd) = 0;
            open_url(&url);
        }
    }

    /// The dashboard is up: host it in a window, or fall back to the browser.
    fn on_ready() {
        let url = dashboard_url();
        let _ = fs::write(shared().dir.join("dashboard.url"), &url);
        notify(&text("ready_title"), &text("ready").replace("{url}", &url), NIIF_INFO);
        let quiet = quiet();
        match webview::runtime_version() {
            Ok(v) => tracing::info!("WebView2 runtime {v}"),
            Err(e) => {
                tracing::warn!("{e}; using the default browser");
                notify("NetScope", &text("no_webview").replace("{e}", &e), NIIF_WARNING);
                if !quiet {
                    open_url(&url);
                }
                return;
            }
        }
        let hwnd = create_main_window();
        if hwnd.is_null() {
            tracing::error!("cannot create the main window; using the default browser");
            if !quiet {
                open_url(&url);
            }
            return;
        }
        *lock(&shared().main_hwnd) = hwnd as usize;
        if let Err(e) = attach_webview(hwnd, &url, !quiet) {
            tracing::warn!("{e}; using the default browser");
            // SAFETY: our own window.
            unsafe { DestroyWindow(hwnd) };
            *lock(&shared().main_hwnd) = 0;
            if !quiet {
                open_url(&url);
            }
        }
    }

    // ----- alert notifications -----

    /// One line GET against the local dashboard; returns the body on 200.
    fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes()).ok()?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).ok()?;
        let text = String::from_utf8_lossy(&raw);
        let (head, body) = text.split_once("\r\n\r\n")?;
        head.starts_with("HTTP/1.1 200").then(|| body.to_string())
    }

    /// The alerts of an `/api/alerts` body, newest first; entries that do not parse (a
    /// kind this build does not know) are skipped.
    fn parse_alerts(body: &str) -> Vec<Alert> {
        let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        v["alerts"].as_array().map(|a| a.iter().filter_map(|x| serde_json::from_value::<Alert>(x.clone()).ok()).collect()).unwrap_or_default()
    }

    /// Whether the notification level lets an alert of `severity` through.
    fn wanted(level: &str, severity: Severity) -> bool {
        match level {
            "high" => severity == Severity::High,
            "medium" => severity >= Severity::Medium,
            "all" | "low" => true,
            _ => false,
        }
    }

    /// Polls the alert list and posts the new alerts the settings ask for (level, category,
    /// quiet hour) to the tray window, oldest first. The settings come from the file each
    /// time; after a restart the dashboard (and its alert ids) start over, so the poller does too.
    fn spawn_alert_poller() {
        std::thread::Builder::new()
            .name("alert-notify".into())
            .spawn(move || {
                let mut seen: Option<u64> = None;
                loop {
                    std::thread::sleep(ALERT_POLL);
                    if *lock(&shared().quitting) {
                        return;
                    }
                    if shared().poller_reset.swap(false, Ordering::SeqCst) {
                        seen = None;
                    }
                    let Some(addr) = *lock(&shared().addr) else { continue };
                    let Some(body) = http_get(local_addr(addr), "/api/alerts") else { continue };
                    let alerts = parse_alerts(&body);
                    let newest = alerts.iter().map(|a| a.id).max();
                    let Some(last) = seen else {
                        // Alerts from before the poller started are already on the dashboard.
                        seen = Some(newest.unwrap_or(0));
                        continue;
                    };
                    let s = notify_settings();
                    let now = unix_now();
                    let fresh: Vec<Alert> =
                        alerts.into_iter().rev().filter(|a| a.id > last && wanted(&s.notifications, a.severity) && s.notifies(a.category, now)).collect();
                    if !fresh.is_empty() {
                        let hwnd = *lock(&shared().tray_hwnd) as HWND;
                        let raw = Box::into_raw(Box::new(fresh));
                        // SAFETY: the window procedure reclaims the box (WM_ALERT); when the
                        // message cannot be posted (window gone, queue full) it is ours again.
                        unsafe {
                            if PostMessageW(hwnd, WM_ALERT, 0, raw as LPARAM) == 0 {
                                drop(Box::from_raw(raw));
                            }
                        }
                    }
                    if let Some(n) = newest {
                        seen = Some(n.max(last));
                    }
                }
            })
            .expect("spawning the alert poller");
    }

    // ----- the hidden tray window -----

    unsafe extern "system" fn tray_wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        match msg {
            WM_TRAY => {
                match lparam as u32 {
                    WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_main(),
                    WM_RBUTTONUP => show_menu(hwnd),
                    _ => {}
                }
                0
            }
            WM_COMMAND => {
                command(wparam & 0xffff);
                0
            }
            WM_READY => {
                if shared().ready_once.swap(true, Ordering::SeqCst) {
                    on_restarted();
                } else {
                    on_ready();
                    spawn_alert_poller();
                    if let Some(url) = lock(&shared().pending_action).take() {
                        run_action(&url);
                    }
                }
                0
            }
            WM_ALERT => {
                // SAFETY: posted by `spawn_alert_poller` with a leaked Box of this type.
                let alerts = *Box::from_raw(lparam as *mut Vec<Alert>);
                notify_alerts(alerts);
                0
            }
            WM_COPYDATA => {
                // A second instance forwards a `netscope://` action (toast click, protocol start).
                let cds = lparam as *const COPYDATASTRUCT;
                if cds.is_null() || (*cds).dwData != COPYDATA_ACTION || (*cds).lpData.is_null() || (*cds).cbData > 4096 {
                    return 0;
                }
                // SAFETY: the sender's buffer stays valid for the duration of the synchronous message.
                let bytes = std::slice::from_raw_parts((*cds).lpData as *const u8, (*cds).cbData as usize);
                let url = String::from_utf8_lossy(bytes).into_owned();
                run_action(&url);
                1
            }
            WM_FAILED => {
                let err = lock(&shared().error).clone().unwrap_or_default();
                let log = shared().dir.join("netscope.log").display().to_string();
                let body = format!("{err}\n\n{}", text("log_hint").replace("{log}", &log));
                if err.contains("Npcap") || err.contains("wpcap") {
                    if message(&text("failed_title"), &format!("{body}{}", text("npcap_q")), MB_YESNO | MB_ICONERROR) == IDYES {
                        open_url("https://npcap.com/#download");
                    }
                } else {
                    message(&text("failed_title"), &body, MB_OK | MB_ICONERROR);
                }
                quit();
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    pub fn main() {
        let dir = app::data_dir();
        let _ = fs::create_dir_all(&dir);
        // A `netscope://…` argument (toast click, URL protocol) is an action, not a setting.
        let all_args: Vec<String> = std::env::args().collect();
        let action = all_args.iter().skip(1).find(|a| a.starts_with(&format!("{}:", toast::SCHEME))).cloned();
        let real: Vec<String> = all_args.into_iter().filter(|a| !a.starts_with(&format!("{}:", toast::SCHEME))).collect();
        // SAFETY: a named mutex only; the handle is intentionally leaked for the process lifetime.
        let already_running = unsafe {
            let h = CreateMutexW(null(), 1, wide("Local\\NetScope.app").as_ptr());
            // A null handle (e.g. ERROR_ACCESS_DENIED: an elevated instance owns the mutex)
            // also means another NetScope is running.
            h.is_null() || GetLastError() == ERROR_ALREADY_EXISTS
        };
        if already_running {
            if let Some(url) = &action {
                if forward_action(url) {
                    return;
                }
                // The running instance cannot be reached (elevated?): a plain open is still useful.
                if !matches!(parse_action(url, ""), Some(Action::Open(_))) {
                    return;
                }
            }
            // Second launch: bring the running instance's window up (or its dashboard). The
            // post fails when the other instance is elevated and this one is not (UIPI).
            // SAFETY: plain window lookup and message post.
            let shown = unsafe {
                let other = FindWindowW(wide(MAIN_CLASS).as_ptr(), null());
                !other.is_null() && PostMessageW(other, WM_SHOW_ME, 0, 0) != 0
            };
            if !shown {
                let url = fs::read_to_string(dir.join("dashboard.url")).unwrap_or_else(|_| "http://127.0.0.1:8888".into());
                open_url(url.trim());
            }
            return;
        }
        // Toasts need an application id with a name and an icon, and clicks need the URL
        // protocol; both are (re)registered for this user on every start.
        let icon = dir.join("netscope.ico");
        let ico = include_bytes!("../../../assets/netscope.ico");
        if fs::metadata(&icon).map_or(true, |m| m.len() != ico.len() as u64) {
            let _ = fs::write(&icon, ico);
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Err(e) = toast::register(&exe, &icon) {
                tracing::warn!("notification registration: {e}");
            }
        }
        // SAFETY: process-wide one-time initialisation before any window or COM call.
        unsafe {
            SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32);
        }
        // SAFETY: plain query of the UI language.
        let russian = unsafe { GetUserDefaultUILanguage() } & 0x3ff == 0x19;
        let ini = dir.join(settings::FILE_NAME);
        let quiet_start = !Settings::load(&ini).show_window;
        let _ = SHARED.set(Shared {
            addr: Mutex::new(None),
            error: Mutex::new(None),
            stop: Mutex::new(None),
            tray_hwnd: Mutex::new(0),
            main_hwnd: Mutex::new(0),
            quitting: Mutex::new(false),
            hidden_hint_shown: Mutex::new(false),
            russian,
            geoip_present: geoip_present(&dir),
            dir: dir.clone(),
            quiet_start,
            restart: AtomicBool::new(false),
            from_cli: real.len() > 1,
            ready_once: AtomicBool::new(false),
            poller_reset: AtomicBool::new(false),
            pending_action: Mutex::new(action),
        });
        let args = match args(&real, &ini) {
            Ok(a) => a,
            Err(e) => {
                message(&text("failed_title"), &e, MB_OK | MB_ICONERROR);
                return;
            }
        };
        init_logging(&dir, args.verbose);
        tracing::info!("netscope-app {} starting; settings in {}", env!("CARGO_PKG_VERSION"), dir.display());

        // The tray icon's owner: a hidden top-level window (never shown). A message-only
        // window would not do — SetForegroundWindow/TrackPopupMenu need a real one for the
        // tray menu to open and close properly.
        // SAFETY: standard window-class registration; the class name and procedure live for
        // the whole process.
        let tray = unsafe {
            let module = GetModuleHandleW(null());
            let class = wide(TRAY_CLASS);
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(tray_wndproc);
            wc.hInstance = module;
            wc.lpszClassName = class.as_ptr();
            RegisterClassW(&wc);
            CreateWindowExW(0, class.as_ptr(), wide("NetScope").as_ptr(), WS_POPUP, 0, 0, 0, 0, null_mut(), null_mut(), module, null())
        };
        if tray.is_null() {
            message(&text("failed_title"), "CreateWindowExW failed", MB_OK | MB_ICONERROR);
            return;
        }
        *lock(&shared().tray_hwnd) = tray as usize;
        add_icon(tray);

        // The analyzer runs on its own thread and reports back through window messages. It
        // starts over when the settings page asked for a restart (`AppHost::request_restart`).
        let tray_n = tray as usize;
        let host: Arc<dyn SettingsHost> = Arc::new(AppHost);
        std::thread::Builder::new()
            .name("netscope".into())
            .spawn(move || {
                let fail = |e: String| {
                    tracing::error!("{e}");
                    *lock(&shared().error) = Some(e);
                    // SAFETY: posting to a window of this process; the handle stays valid
                    // until the message loop below returns.
                    unsafe { PostMessageW(tray_n as HWND, WM_FAILED, 0, 0) };
                };
                let mut first = Some(args);
                loop {
                    if *lock(&shared().quitting) {
                        return;
                    }
                    // The flag is cleared before the sender exists: a request cannot slip in between.
                    shared().restart.store(false, Ordering::SeqCst);
                    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
                    *lock(&shared().stop) = Some(stop_tx);
                    let run_args = match first.take().map_or_else(|| self::args(&real, &shared().ini()), Ok) {
                        Ok(a) => a,
                        Err(e) => return fail(e),
                    };
                    let shutdown = async move {
                        let _ = stop_rx.await;
                    };
                    let on_ready = move |addr: SocketAddr| {
                        *lock(&shared().addr) = Some(addr);
                        // SAFETY: as above.
                        unsafe { PostMessageW(tray_n as HWND, WM_READY, 0, 0) };
                    };
                    // A panic must reach the UI like an error does; otherwise the tray icon
                    // would say "starting…" forever.
                    let error = match std::panic::catch_unwind(AssertUnwindSafe(|| app::run_with_host(run_args, shutdown, on_ready, Some(host.clone())))) {
                        Ok(Ok(())) => None,
                        Ok(Err(e)) => Some(format!("{e:#}")),
                        Err(panic) => Some(
                            panic
                                .downcast_ref::<&str>()
                                .map(|s| s.to_string())
                                .or_else(|| panic.downcast_ref::<String>().cloned())
                                .unwrap_or_else(|| "internal error (panic)".to_string()),
                        ),
                    };
                    if let Some(e) = error {
                        return fail(e);
                    }
                    if !shared().restart.load(Ordering::SeqCst) || *lock(&shared().quitting) {
                        return;
                    }
                    tracing::info!("restarting with new settings");
                }
            })
            .expect("spawning the analyzer thread");

        // SAFETY: the classic message loop; `msg` is written by GetMessageW before use.
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        let _ = fs::remove_file(dir.join("dashboard.url"));
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn with_ini(text: &str, f: impl FnOnce(&Path)) {
            // Tests run in parallel: a counter keeps two inputs of the same length apart.
            static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("netscope-app-{}-{}-{n}", std::process::id(), text.len()));
            fs::create_dir_all(&dir).unwrap();
            let ini = dir.join(settings::FILE_NAME);
            fs::write(&ini, text).unwrap();
            f(&ini);
            fs::remove_dir_all(&dir).ok();
        }

        fn argv(list: &[&str]) -> Vec<String> {
            list.iter().map(|s| s.to_string()).collect()
        }

        /// The file configures the program; real command-line arguments replace it entirely.
        #[test]
        fn settings_become_arguments_unless_real_ones_are_given() {
            with_ini("# comment\nport = 9000\ninterface=\"Wi-Fi\"\negress_check=0\nshow_window=0\nbogus=1\n", |ini| {
                let a = args(&argv(&["netscope-app"]), ini).unwrap();
                assert_eq!((a.port, a.interface.as_deref(), a.no_egress_check), (Some(9000), Some("Wi-Fi"), true));
                let a = args(&argv(&["netscope-app", "--demo"]), ini).unwrap();
                assert_eq!((a.port, a.interface.as_deref(), a.no_egress_check, a.demo), (None, None, false, true), "the file is ignored");
                let e = args(&argv(&["netscope-app", "--port", "70000"]), ini).unwrap_err();
                assert!(e.contains("70000"), "{e}");
                assert!(args(&argv(&["netscope-app", "--bogus"]), ini).is_err());
            });
        }

        #[test]
        fn missing_or_broken_settings() {
            with_ini("", |ini| assert_eq!(args(&argv(&["netscope-app"]), ini).unwrap().port, None));
            with_ini("port=notanumber\n", |ini| assert_eq!(args(&argv(&["netscope-app"]), ini).unwrap().port, None, "an unusable value is ignored"));
            let missing = std::env::temp_dir().join("netscope-app-definitely-missing").join(settings::FILE_NAME);
            let a = args(&argv(&["netscope-app"]), &missing).unwrap();
            assert_eq!((a.port, a.host.as_str(), a.verbose), (None, "127.0.0.1", 0));
        }

        #[test]
        fn wildcard_binds_are_reached_through_loopback() {
            let p = |s: &str| s.parse::<SocketAddr>().unwrap();
            assert_eq!(local_addr(p("0.0.0.0:8888")), p("127.0.0.1:8888"));
            assert_eq!(local_addr(p("[::]:8888")), p("[::1]:8888"));
            assert_eq!(local_addr(p("127.0.0.1:8888")), p("127.0.0.1:8888"));
            assert_eq!(local_addr(p("[::1]:1")), p("[::1]:1"));
            assert_eq!(local_addr(p("192.168.1.5:80")), p("192.168.1.5:80"));
        }

        const ALERT: &str = r#"{"id":7,"ts":1,"severity":"high","kind":"volume_spike","category":"security","host":"1.2.3.4","name":null,"message":"spike","details":{"rate":"5000000","baseline":"10"}}"#;

        #[test]
        fn alerts_with_missing_fields_are_skipped() {
            let body = format!(
                r#"{{"alerts":[
                {ALERT},
                {{"id":1,"ts":1,"severity":"high","kind":"not_a_kind","category":"security","host":null,"name":null,"message":"m","details":{{}}}},
                {{"ts":1,"severity":"high","kind":"new_process","category":"novelty","host":null,"name":null,"message":"no id","details":{{}}}},
                {{"id":2,"ts":1,"severity":"loud","kind":"new_process","category":"novelty","host":null,"name":null,"message":"bad severity","details":{{}}}},
                {{"id":5,"ts":1,"severity":"low","kind":"new_process","category":"novelty","host":null,"name":null,"message":"ok","details":{{"process":"x.exe"}}}},
                null, 7, "x", []
            ]}}"#
            );
            let a = parse_alerts(&body);
            assert_eq!(a.iter().map(|x| x.id).collect::<Vec<_>>(), vec![7, 5]);
            assert_eq!((a[0].kind, a[0].category, a[1].details["process"].as_str()), (netscope::analytics::AlertKind::VolumeSpike, Category::Security, "x.exe"));
            for empty in [r#"{"alerts":null}"#, r#"{"alerts":{}}"#, r#"{"alerts":"x"}"#, "[]", "", "null", r#"{"counts":{}}"#, "{\"alerts\":[]}", "garbage"] {
                assert!(parse_alerts(empty).is_empty(), "{empty}");
            }
        }

        #[test]
        fn levels_filter_by_severity() {
            assert!(wanted("all", Severity::Low) && wanted("low", Severity::Medium) && wanted("low", Severity::High));
            assert!(wanted("medium", Severity::High) && wanted("medium", Severity::Medium) && !wanted("medium", Severity::Low));
            assert!(wanted("high", Severity::High) && !wanted("high", Severity::Medium));
            assert!(!wanted("off", Severity::High) && !wanted("ALL", Severity::High) && !wanted("", Severity::High), "levels are compared verbatim");
        }

        #[test]
        fn alert_toast_texts_come_from_the_shared_templates() {
            let a = parse_alerts(&format!(r#"{{"alerts":[{ALERT}]}}"#)).remove(0);
            assert_eq!(kind_label(a.kind, true), "Всплеск трафика");
            assert!(alert_text(&a, false).starts_with("Traffic spike to unknown host 1.2.3.4: 4.8 MB/s"));
            assert_eq!(category_label(a.category, false), "Security");
        }

        #[test]
        fn actions_are_parsed_strictly() {
            const K: &str = "0123456789abcdef0123456789abcdef";
            let p = |u: &str| parse_action(u, K);
            assert_eq!(p("netscope://open"), Some(Action::Open(None)));
            assert_eq!(p("netscope://open/"), Some(Action::Open(None)));
            assert_eq!(p("netscope://open/alerts"), Some(Action::Open(Some("#/alerts".into()))));
            assert_eq!(p("netscope://open/conn/42"), Some(Action::Open(Some("#/conn/42".into()))));
            assert_eq!(p("netscope://open/alerts?x=1"), Some(Action::Open(Some("#/alerts".into()))), "a query does not end up in the route");
            assert_eq!(p("netscope://open/<script>"), None, "only route characters");
            assert_eq!(p("netscope://open/a?b/c"), Some(Action::Open(Some("#/a".into()))));
            assert_eq!(p(&format!("netscope://snooze?k={K}")), Some(Action::Snooze(Some(SNOOZE_SECS))));
            assert_eq!(p(&format!("netscope://snooze/15?k={K}")), Some(Action::Snooze(Some(900))));
            assert_eq!(p(&format!("netscope://snooze/0?k={K}")), None);
            assert_eq!(p(&format!("netscope://snooze/100000?k={K}")), None);
            assert_eq!(p(&format!("netscope://snooze/-5?k={K}")), None);
            assert_eq!(p(&format!("netscope://unsnooze?k={K}")), Some(Action::Snooze(None)));
            assert_eq!(p(&format!("netscope://mute/novelty?k={K}")), Some(Action::Mute(Category::Novelty)));
            assert_eq!(p(&format!("netscope://mute/novelty?x=1&k={K}")), Some(Action::Mute(Category::Novelty)), "the key may be any parameter");
            assert_eq!(p(&format!("netscope://mute/everything?k={K}")), None);
            assert_eq!(p("http://open"), None);
            assert_eq!(p(&format!("netscope://quit?k={K}")), None);
        }

        #[test]
        fn settings_changes_need_this_runs_key() {
            const K: &str = "0123456789abcdef0123456789abcdef";
            // What a web page could start: no key, a wrong key, an empty key, a key prefix.
            for url in [
                "netscope://mute/security".to_string(),
                "netscope://mute/security?k=".to_string(),
                "netscope://mute/security?k=deadbeef".to_string(),
                format!("netscope://mute/security?k={}", &K[..31]),
                format!("netscope://mute/security?k={K}x"),
                format!("netscope://mute/security?kk={K}"),
                format!("netscope://mute/security/?k={K}/"),
                "netscope://snooze/1440".to_string(),
                "netscope://snooze".to_string(),
                "netscope://unsnooze".to_string(),
            ] {
                assert_eq!(parse_action(&url, K), None, "{url}");
            }
            // Without a key of our own (a second instance that could not reach the running
            // one) nothing but `open` is accepted, whatever the URL carries.
            assert_eq!(parse_action("netscope://mute/security?k=", ""), None);
            assert_eq!(parse_action("netscope://open/alerts", ""), Some(Action::Open(Some("#/alerts".into()))));
            // The key of this process: random, stable, URL-safe.
            let k = action_key();
            assert_eq!(k.len(), 32);
            assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(k, action_key());
            assert_eq!(parse_action(&format!("netscope://mute/routes?k={k}"), action_key()), Some(Action::Mute(Category::Routes)));
        }

        #[test]
        fn clock_survives_any_timestamp() {
            for ts in [i64::MIN, -1, i64::MAX, 1_844_674_407_370, settings::MAX_SNOOZE_UNTIL + 1_000_000_000_000] {
                let _ = clock(ts); // must not panic (debug builds check overflow)
            }
            assert_eq!(clock(-1), "");
            assert_eq!(clock(i64::MAX), "");
            for ts in [0, 1_760_000_000, settings::MAX_SNOOZE_UNTIL] {
                let c = clock(ts);
                assert!(c.len() == 5 && c.as_bytes()[2] == b':', "{ts} -> {c:?}");
            }
        }
    }
}
