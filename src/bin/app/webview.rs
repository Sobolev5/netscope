//! A minimal WebView2 host without the SDK crates: `WebView2Loader.dll` (redistributable,
//! shipped next to the program) is loaded at runtime and the handful of COM interfaces used
//! are declared by hand, with the vtable layouts and IIDs taken from `WebView2.h`.
//!
//! Everything here runs on the UI thread that owns the window: WebView2 is apartment
//! threaded and delivers its callbacks through that thread's message loop.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};
use windows_sys::Win32::Foundation::{HWND, RECT, S_OK};
use windows_sys::Win32::System::Com::CoTaskMemFree;

const E_NOINTERFACE: HRESULT = 0x8000_4002_u32 as i32;
const E_POINTER: HRESULT = 0x8000_4003_u32 as i32;

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> GUID {
    GUID { data1: a, data2: b, data3: c, data4: d }
}
const IID_IUNKNOWN: GUID = guid(0, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
const IID_ENV_COMPLETED: GUID = guid(0x4e8a3389, 0xc9d8, 0x4bd2, [0xb6, 0xb5, 0x12, 0x4f, 0xee, 0x6c, 0xc1, 0x4d]);
const IID_CONTROLLER_COMPLETED: GUID = guid(0x6c4819f3, 0xc9b7, 0x4260, [0x81, 0x27, 0xc9, 0xf5, 0xbd, 0xe7, 0xf6, 0x8c]);
const IID_NEW_WINDOW_REQUESTED: GUID = guid(0xd4c185fe, 0xc81c, 0x4989, [0x97, 0xaf, 0x2d, 0x3f, 0xa7, 0xab, 0x56, 0x51]);
const IID_NAVIGATION_STARTING: GUID = guid(0x9adbe429, 0xf36d, 0x432b, [0x9d, 0xdc, 0xf8, 0x88, 0x1f, 0xbd, 0x76, 0xe3]);

type Unused = *const c_void;
type Method = unsafe extern "system" fn(*mut c_void) -> HRESULT;
type MethodBool = unsafe extern "system" fn(*mut c_void, i32) -> HRESULT;
type MethodStr = unsafe extern "system" fn(*mut c_void, PCWSTR) -> HRESULT;
type MethodOutStr = unsafe extern "system" fn(*mut c_void, *mut PWSTR) -> HRESULT;
type MethodOutPtr = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT;
type MethodAddHandler = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut i64) -> HRESULT;

/// Any COM interface: a pointer to a vtable whose first three slots are IUnknown's.
#[repr(C)]
struct Com<V> {
    vtbl: *const V,
}

#[repr(C)]
struct IUnknownVtbl {
    query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

#[repr(C)]
struct EnvironmentVtbl {
    base: IUnknownVtbl,
    create_controller: unsafe extern "system" fn(*mut c_void, HWND, *mut c_void) -> HRESULT,
    _create_web_resource_response: Unused,
    _get_browser_version_string: Unused,
    _add_new_browser_version_available: Unused,
    _remove_new_browser_version_available: Unused,
}

#[repr(C)]
struct ControllerVtbl {
    base: IUnknownVtbl,
    _get_is_visible: Unused,
    put_is_visible: MethodBool,
    _get_bounds: Unused,
    put_bounds: unsafe extern "system" fn(*mut c_void, RECT) -> HRESULT,
    _get_zoom_factor: Unused,
    _put_zoom_factor: Unused,
    _add_zoom_factor_changed: Unused,
    _remove_zoom_factor_changed: Unused,
    _set_bounds_and_zoom_factor: Unused,
    move_focus: unsafe extern "system" fn(*mut c_void, i32) -> HRESULT,
    _add_move_focus_requested: Unused,
    _remove_move_focus_requested: Unused,
    _add_got_focus: Unused,
    _remove_got_focus: Unused,
    _add_lost_focus: Unused,
    _remove_lost_focus: Unused,
    _add_accelerator_key_pressed: Unused,
    _remove_accelerator_key_pressed: Unused,
    _get_parent_window: Unused,
    _put_parent_window: Unused,
    notify_parent_window_position_changed: Method,
    close: Method,
    get_core_web_view2: MethodOutPtr,
}

#[repr(C)]
struct CoreVtbl {
    base: IUnknownVtbl,
    get_settings: MethodOutPtr,
    _get_source: Unused,
    navigate: MethodStr,
    _navigate_to_string: Unused,
    add_navigation_starting: MethodAddHandler,
    _remove_navigation_starting: Unused,
    _add_content_loading: Unused,
    _remove_content_loading: Unused,
    _add_source_changed: Unused,
    _remove_source_changed: Unused,
    _add_history_changed: Unused,
    _remove_history_changed: Unused,
    _add_navigation_completed: Unused,
    _remove_navigation_completed: Unused,
    _add_frame_navigation_starting: Unused,
    _remove_frame_navigation_starting: Unused,
    _add_frame_navigation_completed: Unused,
    _remove_frame_navigation_completed: Unused,
    _add_script_dialog_opening: Unused,
    _remove_script_dialog_opening: Unused,
    _add_permission_requested: Unused,
    _remove_permission_requested: Unused,
    _add_process_failed: Unused,
    _remove_process_failed: Unused,
    _add_script_to_execute_on_document_created: Unused,
    _remove_script_to_execute_on_document_created: Unused,
    _execute_script: Unused,
    _capture_preview: Unused,
    _reload: Unused,
    _post_web_message_as_json: Unused,
    _post_web_message_as_string: Unused,
    _add_web_message_received: Unused,
    _remove_web_message_received: Unused,
    _call_dev_tools_protocol_method: Unused,
    _get_browser_process_id: Unused,
    _get_can_go_back: Unused,
    _get_can_go_forward: Unused,
    _go_back: Unused,
    _go_forward: Unused,
    _get_dev_tools_protocol_event_receiver: Unused,
    _stop: Unused,
    add_new_window_requested: MethodAddHandler,
    _remove_new_window_requested: Unused,
    _add_document_title_changed: Unused,
    _remove_document_title_changed: Unused,
    _get_document_title: Unused,
    _add_host_object_to_script: Unused,
    _remove_host_object_from_script: Unused,
    _open_dev_tools_window: Unused,
    _add_contains_full_screen_element_changed: Unused,
    _remove_contains_full_screen_element_changed: Unused,
    _get_contains_full_screen_element: Unused,
    _add_web_resource_requested: Unused,
    _remove_web_resource_requested: Unused,
    _add_web_resource_requested_filter: Unused,
    _remove_web_resource_requested_filter: Unused,
    _add_window_close_requested: Unused,
    _remove_window_close_requested: Unused,
}

#[repr(C)]
struct SettingsVtbl {
    base: IUnknownVtbl,
    _get_is_script_enabled: Unused,
    _put_is_script_enabled: Unused,
    _get_is_web_message_enabled: Unused,
    _put_is_web_message_enabled: Unused,
    _get_are_default_script_dialogs_enabled: Unused,
    _put_are_default_script_dialogs_enabled: Unused,
    _get_is_status_bar_enabled: Unused,
    put_is_status_bar_enabled: MethodBool,
    _get_are_dev_tools_enabled: Unused,
    _put_are_dev_tools_enabled: Unused,
    _get_are_default_context_menus_enabled: Unused,
    _put_are_default_context_menus_enabled: Unused,
    _get_are_host_objects_allowed: Unused,
    _put_are_host_objects_allowed: Unused,
    _get_is_zoom_control_enabled: Unused,
    _put_is_zoom_control_enabled: Unused,
    _get_is_built_in_error_page_enabled: Unused,
    _put_is_built_in_error_page_enabled: Unused,
}

#[repr(C)]
struct NewWindowArgsVtbl {
    base: IUnknownVtbl,
    get_uri: MethodOutStr,
    _put_new_window: Unused,
    _get_new_window: Unused,
    put_handled: MethodBool,
}

#[repr(C)]
struct NavigationStartingArgsVtbl {
    base: IUnknownVtbl,
    get_uri: MethodOutStr,
    _get_is_user_initiated: Unused,
    _get_is_redirected: Unused,
    _get_request_headers: Unused,
    _get_cancel: Unused,
    put_cancel: MethodBool,
}

// ----- our own COM objects: completion and event handlers -----

enum Callback {
    Completed(Box<dyn FnMut(HRESULT, *mut c_void)>),
    Event(Box<dyn FnMut(*mut c_void, *mut c_void)>),
}

/// A reference-counted handler object WebView2 can call back into.
#[repr(C)]
struct Handler {
    vtbl: *const HandlerVtbl,
    refs: AtomicU32,
    iid: GUID,
    callback: Callback,
}

#[repr(C)]
struct HandlerVtbl {
    base: IUnknownVtbl,
    invoke: *const c_void,
}
// SAFETY: the vtables are immutable function-pointer tables.
unsafe impl Sync for HandlerVtbl {}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe extern "system" fn handler_query_interface(this: *mut c_void, riid: *const GUID, out: *mut *mut c_void) -> HRESULT {
    if out.is_null() {
        return E_POINTER;
    }
    let h = this as *mut Handler;
    if same_guid(&*riid, &IID_IUNKNOWN) || same_guid(&*riid, &(*h).iid) {
        (*h).refs.fetch_add(1, Ordering::Relaxed);
        *out = this;
        S_OK
    } else {
        *out = null_mut();
        E_NOINTERFACE
    }
}

unsafe extern "system" fn handler_add_ref(this: *mut c_void) -> u32 {
    (*(this as *mut Handler)).refs.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn handler_release(this: *mut c_void) -> u32 {
    let left = (*(this as *mut Handler)).refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        drop(Box::from_raw(this as *mut Handler));
    }
    left
}

unsafe extern "system" fn handler_invoke_completed(this: *mut c_void, code: HRESULT, result: *mut c_void) -> HRESULT {
    if let Callback::Completed(f) = &mut (*(this as *mut Handler)).callback {
        f(code, result);
    }
    S_OK
}

unsafe extern "system" fn handler_invoke_event(this: *mut c_void, sender: *mut c_void, args: *mut c_void) -> HRESULT {
    if let Callback::Event(f) = &mut (*(this as *mut Handler)).callback {
        f(sender, args);
    }
    S_OK
}

static COMPLETED_VTBL: HandlerVtbl = HandlerVtbl {
    base: IUnknownVtbl { query_interface: handler_query_interface, add_ref: handler_add_ref, release: handler_release },
    invoke: handler_invoke_completed as *const c_void,
};
static EVENT_VTBL: HandlerVtbl = HandlerVtbl {
    base: IUnknownVtbl { query_interface: handler_query_interface, add_ref: handler_add_ref, release: handler_release },
    invoke: handler_invoke_event as *const c_void,
};

/// A new handler with one reference, owned by the caller until handed to WebView2.
fn new_handler(iid: GUID, callback: Callback) -> *mut c_void {
    let vtbl = match callback {
        Callback::Completed(_) => &COMPLETED_VTBL,
        Callback::Event(_) => &EVENT_VTBL,
    };
    Box::into_raw(Box::new(Handler { vtbl, refs: AtomicU32::new(1), iid, callback })) as *mut c_void
}

unsafe fn release(p: *mut c_void) {
    if !p.is_null() {
        ((*(*(p as *mut Com<IUnknownVtbl>)).vtbl).release)(p);
    }
}

/// Copies and frees a string WebView2 allocated with CoTaskMemAlloc.
unsafe fn take_string(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
    CoTaskMemFree(p as *const c_void);
    s
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ----- the loader -----

struct Loader {
    _lib: libloading::Library,
    create_environment: unsafe extern "system" fn(PCWSTR, PCWSTR, *mut c_void, *mut c_void) -> HRESULT,
    available_version: unsafe extern "system" fn(PCWSTR, *mut PWSTR) -> HRESULT,
}

static LOADER: OnceLock<Result<Loader, String>> = OnceLock::new();

/// `WebView2Loader.dll` next to the program only (build.rs copies it there), so that no
/// other directory on the way up can plant a DLL. Debug builds also accept the copy in the
/// source tree (`assets/webview2`) for `cargo run` from an unusual target directory.
fn loader_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        out.push(dir.join("WebView2Loader.dll"));
    }
    if cfg!(debug_assertions) {
        out.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("assets").join("webview2").join("WebView2Loader.dll"));
    }
    out
}

/// `uri` is on `origin` itself: exactly `origin`, or `origin` followed by a path, query or
/// fragment. A bare prefix test would also accept `http://127.0.0.1:8888.evil.example/`.
fn same_origin(uri: &str, origin: &str) -> bool {
    match uri.strip_prefix(origin) {
        Some(rest) => rest.is_empty() || rest.starts_with(['/', '?', '#']),
        None => false,
    }
}

fn loader() -> Result<&'static Loader, String> {
    LOADER
        .get_or_init(|| {
            let path = loader_candidates().into_iter().find(|p| p.exists()).ok_or("WebView2Loader.dll not found next to the program")?;
            // SAFETY: loading Microsoft's loader library; its DllMain has no preconditions.
            let lib = unsafe { libloading::Library::new(&path) }.map_err(|e| format!("{}: {e}", path.display()))?;
            // SAFETY: the symbol types match the declarations in WebView2.h.
            unsafe {
                let create_environment = *lib.get(b"CreateCoreWebView2EnvironmentWithOptions\0").map_err(|e| e.to_string())?;
                let available_version = *lib.get(b"GetAvailableCoreWebView2BrowserVersionString\0").map_err(|e| e.to_string())?;
                Ok(Loader { _lib: lib, create_environment, available_version })
            }
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Version of the installed WebView2 runtime (Evergreen or Edge), if any.
pub fn runtime_version() -> Result<String, String> {
    let l = loader()?;
    let mut v: PWSTR = null_mut();
    // SAFETY: `v` receives a CoTaskMem string that `take_string` frees.
    let hr = unsafe { (l.available_version)(null(), &mut v) };
    if hr != S_OK || v.is_null() {
        return Err(format!("WebView2 runtime not installed (0x{hr:08x})"));
    }
    Ok(unsafe { take_string(v) })
}

// ----- the hosted view -----

/// A WebView2 control filling a window. Only usable on the thread that created it.
pub struct WebView {
    controller: *mut Com<ControllerVtbl>,
    core: *mut Com<CoreVtbl>,
}

impl WebView {
    pub fn resize(&self, width: i32, height: i32) {
        // SAFETY: live controller pointer owned by this struct.
        unsafe { ((*(*self.controller).vtbl).put_bounds)(self.controller as *mut c_void, RECT { left: 0, top: 0, right: width, bottom: height }) };
    }

    pub fn set_visible(&self, visible: bool) {
        // SAFETY: as above.
        unsafe { ((*(*self.controller).vtbl).put_is_visible)(self.controller as *mut c_void, visible as i32) };
    }

    pub fn focus(&self) {
        // SAFETY: as above; 0 = COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC.
        unsafe { ((*(*self.controller).vtbl).move_focus)(self.controller as *mut c_void, 0) };
    }

    pub fn parent_moved(&self) {
        // SAFETY: as above.
        unsafe { ((*(*self.controller).vtbl).notify_parent_window_position_changed)(self.controller as *mut c_void) };
    }

    pub fn navigate(&self, url: &str) {
        // SAFETY: NUL-terminated UTF-16 outlives the call.
        unsafe { ((*(*self.core).vtbl).navigate)(self.core as *mut c_void, wide(url).as_ptr()) };
    }
}

impl Drop for WebView {
    fn drop(&mut self) {
        // SAFETY: closing releases the browser; the references are ours.
        unsafe {
            ((*(*self.controller).vtbl).close)(self.controller as *mut c_void);
            release(self.core as *mut c_void);
            release(self.controller as *mut c_void);
        }
    }
}

/// Starts creating a WebView2 in `hwnd` showing `url`; `done` runs on this thread when the
/// control is ready (or failed). Navigations away from `origin` and new windows go to
/// `open_external` instead — the dashboard stays the only thing inside the program window.
pub fn create(
    hwnd: HWND,
    user_data: &Path,
    origin: String,
    url: String,
    open_external: fn(&str),
    done: Box<dyn FnOnce(Result<WebView, String>)>,
) -> Result<(), String> {
    let l = loader()?;
    let hwnd_n = hwnd as usize;
    let mut done = Some(done);
    let finish = move |r: Result<WebView, String>| {
        if let Some(d) = done.take() {
            d(r);
        }
    };
    let finish = std::rc::Rc::new(std::cell::RefCell::new(finish));
    let finish_env = finish.clone();
    let env_handler = new_handler(
        IID_ENV_COMPLETED,
        Callback::Completed(Box::new(move |code, env| {
            if code != S_OK || env.is_null() {
                (finish_env.borrow_mut())(Err(format!("WebView2 environment failed: 0x{code:08x}")));
                return;
            }
            let env = env as *mut Com<EnvironmentVtbl>;
            let finish_ctl = finish_env.clone();
            let (origin, url) = (origin.clone(), url.clone());
            let ctl_handler = new_handler(
                IID_CONTROLLER_COMPLETED,
                Callback::Completed(Box::new(move |code, ctl| {
                    if code != S_OK || ctl.is_null() {
                        (finish_ctl.borrow_mut())(Err(format!("WebView2 controller failed: 0x{code:08x}")));
                        return;
                    }
                    // SAFETY: `ctl` is a live ICoreWebView2Controller for the duration of the callback;
                    // we take our own reference before returning.
                    let r = unsafe { setup(ctl as *mut Com<ControllerVtbl>, &origin, &url, open_external) };
                    (finish_ctl.borrow_mut())(r);
                })),
            );
            // SAFETY: valid environment pointer from the callback; the handler is ours.
            let hr = unsafe { ((*(*env).vtbl).create_controller)(env as *mut c_void, hwnd_n as HWND, ctl_handler) };
            unsafe { release(ctl_handler) };
            if hr != S_OK {
                (finish_env.borrow_mut())(Err(format!("CreateCoreWebView2Controller failed: 0x{hr:08x}")));
            }
        })),
    );
    let user_data = wide(&user_data.display().to_string());
    // SAFETY: strings are NUL-terminated and outlive the call; the handler is ours.
    let hr = unsafe { (l.create_environment)(null(), user_data.as_ptr(), null_mut(), env_handler) };
    unsafe { release(env_handler) };
    if hr != S_OK {
        return Err(format!("CreateCoreWebView2EnvironmentWithOptions failed: 0x{hr:08x}"));
    }
    Ok(())
}

/// Takes ownership of a freshly created controller: settings, event handlers, first page.
unsafe fn setup(controller: *mut Com<ControllerVtbl>, origin: &str, url: &str, open_external: fn(&str)) -> Result<WebView, String> {
    ((*(*controller).vtbl).base.add_ref)(controller as *mut c_void);
    let mut core: *mut c_void = null_mut();
    let hr = ((*(*controller).vtbl).get_core_web_view2)(controller as *mut c_void, &mut core);
    if hr != S_OK || core.is_null() {
        release(controller as *mut c_void);
        return Err(format!("get_CoreWebView2 failed: 0x{hr:08x}"));
    }
    let core = core as *mut Com<CoreVtbl>;
    let view = WebView { controller, core };

    let mut settings: *mut c_void = null_mut();
    if ((*(*core).vtbl).get_settings)(core as *mut c_void, &mut settings) == S_OK && !settings.is_null() {
        let s = settings as *mut Com<SettingsVtbl>;
        ((*(*s).vtbl).put_is_status_bar_enabled)(settings, 0);
        release(settings);
    }

    // target=_blank links (and window.open) go to the default browser.
    let open = open_external;
    let new_window = new_handler(
        IID_NEW_WINDOW_REQUESTED,
        Callback::Event(Box::new(move |_sender, args| {
            let a = args as *mut Com<NewWindowArgsVtbl>;
            let mut uri: PWSTR = null_mut();
            if ((*(*a).vtbl).get_uri)(args, &mut uri) == S_OK {
                open(&take_string(uri));
            }
            ((*(*a).vtbl).put_handled)(args, 1);
        })),
    );
    let mut token = 0i64;
    ((*(*core).vtbl).add_new_window_requested)(core as *mut c_void, new_window, &mut token);
    release(new_window);

    // Plain links to other sites as well: the window shows only the dashboard.
    let origin = origin.to_string();
    let navigating = new_handler(
        IID_NAVIGATION_STARTING,
        Callback::Event(Box::new(move |_sender, args| {
            let a = args as *mut Com<NavigationStartingArgsVtbl>;
            let mut uri: PWSTR = null_mut();
            if ((*(*a).vtbl).get_uri)(args, &mut uri) != S_OK {
                return;
            }
            let uri = take_string(uri);
            if !same_origin(&uri, &origin) && !uri.starts_with("about:") {
                ((*(*a).vtbl).put_cancel)(args, 1);
                open(&uri);
            }
        })),
    );
    ((*(*core).vtbl).add_navigation_starting)(core as *mut c_void, navigating, &mut token);
    release(navigating);

    view.navigate(url);
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_dashboard_origin_stays_inside_the_window() {
        let o = "http://127.0.0.1:8888";
        for ok in ["http://127.0.0.1:8888", "http://127.0.0.1:8888/", "http://127.0.0.1:8888/?app=1", "http://127.0.0.1:8888?x=1", "http://127.0.0.1:8888#top"] {
            assert!(same_origin(ok, o), "{ok}");
        }
        for bad in ["http://127.0.0.1:88880/", "http://127.0.0.1:8888.evil.example/", "https://127.0.0.1:8888/", "http://127.0.0.1:8889/", "http://localhost:8888/", "", "about:blank"] {
            assert!(!same_origin(bad, o), "{bad}");
        }
    }

    #[test]
    fn the_loader_is_only_looked_for_next_to_the_program() {
        let c = loader_candidates();
        let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
        assert_eq!(c[0], exe_dir.join("WebView2Loader.dll"));
        assert_eq!(c.len(), if cfg!(debug_assertions) { 2 } else { 1 });
        assert!(c.iter().all(|p| p.file_name().is_some_and(|n| n == "WebView2Loader.dll")));
    }
}
