//! NetScope as a desktop program for Windows: its own window (the dashboard inside a
//! WebView2 control), an icon in the notification area, system notifications for alerts,
//! no console. The analysis itself is `netscope::app::run_with`; this is the shell around it.
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
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
    use std::panic::AssertUnwindSafe;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
    use std::time::Duration;

    use clap::Parser;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
    use windows_sys::Win32::Graphics::Gdi::COLOR_WINDOW;
    use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE,
        REG_SZ,
    };
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_WARNING, NIM_ADD, NIM_DELETE,
        NIM_MODIFY, NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow, DispatchMessageW, FindWindowW, GetClientRect,
        GetCursorPos, GetMessageW, GetSystemMetrics, IsIconic, LoadCursorW, LoadIconW, MessageBoxW, PostMessageW, PostQuitMessage, RegisterClassW,
        SetForegroundWindow, SetMenuDefaultItem, SetWindowPos, ShowWindow, TrackPopupMenu, TranslateMessage, CW_USEDEFAULT, IDC_ARROW,
        IDI_APPLICATION, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MB_YESNO, MF_CHECKED, MF_SEPARATOR, MF_STRING, MINMAXINFO, MSG,
        SM_CXSCREEN, SM_CYSCREEN, SWP_NOACTIVATE, SWP_NOZORDER, SW_HIDE, SW_RESTORE, SW_SHOW, SW_SHOWNORMAL, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
        TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_DPICHANGED, WM_GETMINMAXINFO, WM_LBUTTONDBLCLK, WM_LBUTTONUP,
        WM_MOVE, WM_RBUTTONUP, WM_SETFOCUS, WM_SIZE, WNDCLASSW, WS_OVERLAPPEDWINDOW, WS_POPUP,
    };

    use netscope::app;
    use netscope::cli::Args;
    use netscope::settings::{self, Settings, SettingsHost};

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
    const ID_NOTIFY: usize = 3;
    const ID_AUTOSTART: usize = 4;
    const ID_GEOIP: usize = 5;
    const ID_LOG: usize = 6;
    const ID_QUIT: usize = 7;
    const MAIN_CLASS: &str = "NetScopeMain";
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
            ("notify", true) => "Уведомления о предупреждениях",
            ("notify", false) => "Alert notifications",
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
            ("kind_sensitive_http", true) => "Пароли/токены по HTTP",
            ("kind_sensitive_http", false) => "Credentials over HTTP",
            ("kind_suspicious_dns", true) => "Подозрительный DNS",
            ("kind_suspicious_dns", false) => "Suspicious DNS",
            ("kind_volume_spike", true) => "Всплеск трафика",
            ("kind_volume_spike", false) => "Traffic spike",
            ("kind_cleartext_protocol", true) => "Незашифрованный протокол",
            ("kind_cleartext_protocol", false) => "Cleartext protocol",
            ("kind_new_process", true) => "Новая программа в сети",
            ("kind_new_process", false) => "New program online",
            ("kind_new_destination", true) => "Новое направление",
            ("kind_new_destination", false) => "New destination",
            ("kind_new_country", true) => "Новая страна",
            ("kind_new_country", false) => "New country",
            ("kind_new_listener", true) => "Новый открытый порт",
            ("kind_new_listener", false) => "New open port",
            ("kind_unsigned_process", true) => "Неподписанная программа",
            ("kind_unsigned_process", false) => "Unsigned program",
            ("kind_route_change", true) => "Смена маршрута",
            ("kind_route_change", false) => "Route change",
            ("kind_latency_increase", true) => "Рост задержки",
            ("kind_latency_increase", false) => "Latency increase",
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

    /// The notification level (`medium`, `high`, `off`), read from the file every time so a
    /// change on the Settings page applies without a restart.
    fn notify_level() -> String {
        Settings::load(&shared().ini()).notifications
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

    fn show_menu(hwnd: HWND) {
        let checked = |on: bool| if on { MF_CHECKED } else { 0 };
        // SAFETY: standard popup-menu sequence; every handle is checked and destroyed.
        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            AppendMenuW(menu, MF_STRING, ID_OPEN, wide(&text("open")).as_ptr());
            SetMenuDefaultItem(menu, ID_OPEN as u32, 0);
            AppendMenuW(menu, MF_STRING, ID_BROWSER, wide(&text("browser")).as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING | checked(notify_level() != "off"), ID_NOTIFY, wide(&text("notify")).as_ptr());
            AppendMenuW(menu, MF_STRING | checked(autostart_enabled()), ID_AUTOSTART, wide(&text("autostart")).as_ptr());
            if !shared().geoip_present {
                AppendMenuW(menu, MF_STRING, ID_GEOIP, wide(&text("geoip")).as_ptr());
            }
            AppendMenuW(menu, MF_STRING, ID_LOG, wide(&text("log")).as_ptr());
            AppendMenuW(menu, MF_SEPARATOR, 0, null());
            AppendMenuW(menu, MF_STRING, ID_QUIT, wide(&text("quit")).as_ptr());
            let mut pt = std::mem::zeroed();
            GetCursorPos(&mut pt);
            // Without this the menu does not close when the user clicks elsewhere.
            SetForegroundWindow(hwnd);
            let cmd = TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, pt.x, pt.y, 0, hwnd, null());
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
            ID_NOTIFY => {
                let level = if notify_level() == "off" { "medium" } else { "off" };
                if let Err(e) = settings::write_setting(&shared().ini(), "notifications", level) {
                    tracing::warn!("cannot save the notification level: {e}");
                }
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
                        balloon(&text("hidden_title"), &text("hidden"), NIIF_INFO);
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
        balloon(&text("restarted_title"), &text("restarted").replace("{url}", &url), NIIF_INFO);
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
        balloon(&text("ready_title"), &text("ready").replace("{url}", &url), NIIF_INFO);
        let quiet = quiet();
        match webview::runtime_version() {
            Ok(v) => tracing::info!("WebView2 runtime {v}"),
            Err(e) => {
                tracing::warn!("{e}; using the default browser");
                balloon("NetScope", &text("no_webview").replace("{e}", &e), NIIF_WARNING);
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

    /// `(id, severity, kind, message)` of every alert in an `/api/alerts` body, newest first.
    fn parse_alerts(body: &str) -> Vec<(u64, String, String, String)> {
        let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
        v["alerts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        Some((
                            x["id"].as_u64()?,
                            x["severity"].as_str()?.to_string(),
                            x["kind"].as_str()?.to_string(),
                            x["message"].as_str().unwrap_or("").to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn wanted(level: &str, severity: &str) -> bool {
        match level {
            "high" => severity == "high",
            "medium" => severity == "high" || severity == "medium",
            "all" | "low" => true,
            _ => false,
        }
    }

    /// Polls the alert list and posts new high/medium alerts to the tray window. The level
    /// comes from the settings file each time; after a restart the dashboard (and its alert
    /// ids) start over, so the poller does too.
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
                    let newest = alerts.iter().map(|a| a.0).max();
                    let Some(last) = seen else {
                        // Alerts from before the poller started are already on the dashboard.
                        seen = Some(newest.unwrap_or(0));
                        continue;
                    };
                    let level = notify_level();
                    for (id, severity, kind, message) in alerts.iter().rev() {
                        if *id > last && wanted(&level, severity) {
                            let payload = Box::new((text(&format!("kind_{kind}")), message.clone(), severity == "high"));
                            let hwnd = *lock(&shared().tray_hwnd) as HWND;
                            let raw = Box::into_raw(payload);
                            // SAFETY: the window procedure reclaims the box (WM_ALERT); when the
                            // message cannot be posted (window gone, queue full) it is ours again.
                            unsafe {
                                if PostMessageW(hwnd, WM_ALERT, 0, raw as LPARAM) == 0 {
                                    drop(Box::from_raw(raw));
                                }
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
                }
                0
            }
            WM_ALERT => {
                // SAFETY: posted by `spawn_alert_poller` with a leaked Box of this type.
                let (title, body, high) = *Box::from_raw(lparam as *mut (String, String, bool));
                balloon(&title, &body, if high { NIIF_ERROR } else { NIIF_WARNING });
                0
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
        // SAFETY: a named mutex only; the handle is intentionally leaked for the process lifetime.
        let already_running = unsafe {
            let h = CreateMutexW(null(), 1, wide("Local\\NetScope.app").as_ptr());
            // A null handle (e.g. ERROR_ACCESS_DENIED: an elevated instance owns the mutex)
            // also means another NetScope is running.
            h.is_null() || GetLastError() == ERROR_ALREADY_EXISTS
        };
        if already_running {
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
        // SAFETY: process-wide one-time initialisation before any window or COM call.
        unsafe {
            SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32);
        }
        // SAFETY: plain query of the UI language.
        let russian = unsafe { GetUserDefaultUILanguage() } & 0x3ff == 0x19;
        let ini = dir.join(settings::FILE_NAME);
        let real: Vec<String> = std::env::args().collect();
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
            let class = wide("NetScopeTray");
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

        #[test]
        fn alerts_with_missing_fields_are_skipped() {
            let body = r#"{"alerts":[
                {"id":1,"severity":"high","kind":"k"},
                {"severity":"high","kind":"k","message":"no id"},
                {"id":2,"kind":"k","message":"no severity"},
                {"id":3,"severity":"low","message":"no kind"},
                {"id":"4","severity":"low","kind":"k","message":"string id"},
                {"id":5,"severity":"low","kind":"k","message":null},
                null, 7, "x", []
            ]}"#;
            let a = parse_alerts(body);
            assert_eq!(a.iter().map(|x| x.0).collect::<Vec<_>>(), vec![1, 5]);
            assert_eq!((a[0].3.as_str(), a[1].3.as_str()), ("", ""), "a missing or null message is empty");
            for empty in [r#"{"alerts":null}"#, r#"{"alerts":{}}"#, r#"{"alerts":"x"}"#, "[]", "", "null", r#"{"counts":{}}"#, "{\"alerts\":[]}"] {
                assert!(parse_alerts(empty).is_empty(), "{empty}");
            }
            assert!(wanted("all", "low") && wanted("low", "medium") && wanted("low", "high"));
            assert!(!wanted("ALL", "high") && !wanted("", "high") && !wanted("medium", "") && !wanted("high", "HIGH"), "levels and severities are compared verbatim");
        }

        #[test]
        fn alerts_are_parsed_and_filtered() {
            let body = r#"{"counts":{},"alerts":[{"id":7,"severity":"high","kind":"volume_spike","message":"spike"},{"id":6,"severity":"low","kind":"cleartext_protocol","message":"telnet"},{"id":5,"severity":"medium","kind":"new_country"}]}"#;
            let a = parse_alerts(body);
            assert_eq!(a.len(), 3);
            assert_eq!((a[0].0, a[0].1.as_str(), a[2].3.as_str()), (7, "high", ""));
            assert!(wanted("medium", "high") && wanted("medium", "medium") && !wanted("medium", "low"));
            assert!(wanted("high", "high") && !wanted("high", "medium") && !wanted("off", "high"));
            assert!(parse_alerts("garbage").is_empty());
        }
    }
}
