//! Windows toast notifications (`Windows.UI.Notifications`) without the WinRT crates: the
//! activation functions come from `combase.dll` at runtime and the five interfaces used are
//! declared by hand, with vtable layouts and IIDs from the Windows SDK headers. Toasts are
//! shown for the application id registered by [`register`]; clicking one (or one of its
//! buttons) starts `netscope://…` through the URL protocol registered there as well.
//!
//! Everything runs on the UI thread (an STA): the notifier is created once and kept.

use std::cell::RefCell;
use std::ffi::c_void;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use libloading::Library;
use windows_sys::core::{GUID, HRESULT, PCWSTR};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, S_OK};
use windows_sys::Win32::System::Registry::{RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ};
use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

/// The application id toasts are shown under (also set on the Start-menu shortcut).
pub const APP_ID: &str = "NetScope.Desktop";
/// The URL scheme toast clicks arrive through: `netscope://open/alerts`, `netscope://snooze/60`…
pub const SCHEME: &str = "netscope";

/// A WinRT string handle (`HString`).
type HString = *mut c_void;
type Unused = *const c_void;

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> GUID {
    GUID { data1: a, data2: b, data3: c, data4: d }
}
const IID_MANAGER_STATICS: GUID = guid(0x50ac103f, 0xd235, 0x4598, [0xbb, 0xef, 0x98, 0xfe, 0x4d, 0x1a, 0x3a, 0xd4]);
const IID_NOTIFIER: GUID = guid(0x75927b93, 0x03f3, 0x41ec, [0x91, 0xd3, 0x6e, 0x5b, 0xac, 0x1b, 0x38, 0xe7]);
const IID_TOAST_FACTORY: GUID = guid(0x04124b20, 0x82c6, 0x4229, [0xb1, 0x09, 0xfd, 0x9e, 0xd4, 0x66, 0x2b, 0x53]);
const IID_TOAST2: GUID = guid(0x9dfb9fd1, 0x143a, 0x490e, [0x90, 0xbf, 0xb9, 0xfb, 0xa7, 0x13, 0x2d, 0xe7]);
const IID_XML_DOCUMENT: GUID = guid(0xf7f3a506, 0x1e87, 0x42d6, [0xbc, 0xfb, 0xb8, 0xc8, 0x09, 0xfa, 0x54, 0x94]);
const IID_XML_DOCUMENT_IO: GUID = guid(0x6cd0e74e, 0xee65, 0x4489, [0x9e, 0xbf, 0xca, 0x43, 0xe8, 0x7b, 0xa6, 0x37]);

#[repr(C)]
struct IUnknownVtbl {
    query_interface: unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

/// IInspectable: IUnknown plus GetIids, GetRuntimeClassName, GetTrustLevel.
#[repr(C)]
struct IInspectableVtbl {
    base: IUnknownVtbl,
    _get_iids: Unused,
    _get_runtime_class_name: Unused,
    _get_trust_level: Unused,
}

#[repr(C)]
struct ManagerStaticsVtbl {
    base: IInspectableVtbl,
    _create_toast_notifier: Unused,
    create_toast_notifier_with_id: unsafe extern "system" fn(*mut c_void, HString, *mut *mut c_void) -> HRESULT,
    _get_template_content: Unused,
}

#[repr(C)]
struct NotifierVtbl {
    base: IInspectableVtbl,
    show: unsafe extern "system" fn(*mut c_void, *mut c_void) -> HRESULT,
    _hide: Unused,
    get_setting: unsafe extern "system" fn(*mut c_void, *mut i32) -> HRESULT,
    _add_to_schedule: Unused,
    _remove_from_schedule: Unused,
    _get_scheduled_toast_notifications: Unused,
}

#[repr(C)]
struct ToastFactoryVtbl {
    base: IInspectableVtbl,
    create_toast_notification: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> HRESULT,
}

#[repr(C)]
struct Toast2Vtbl {
    base: IInspectableVtbl,
    put_tag: unsafe extern "system" fn(*mut c_void, HString) -> HRESULT,
    _get_tag: Unused,
    put_group: unsafe extern "system" fn(*mut c_void, HString) -> HRESULT,
    _get_group: Unused,
    _put_suppress_popup: Unused,
    _get_suppress_popup: Unused,
}

#[repr(C)]
struct XmlIoVtbl {
    base: IInspectableVtbl,
    load_xml: unsafe extern "system" fn(*mut c_void, HString) -> HRESULT,
    _load_xml_with_settings: Unused,
    _save_to_file_async: Unused,
}

/// A COM interface pointer that is released on drop.
struct Com(*mut c_void);

impl Com {
    fn vtbl<V>(&self) -> &V {
        // SAFETY: every COM object starts with a pointer to its vtable; the caller names
        // the layout matching the interface this pointer was obtained for.
        unsafe { &**(self.0 as *const *const V) }
    }

    fn query(&self, iid: &GUID) -> Result<Com, String> {
        let mut out: *mut c_void = null_mut();
        // SAFETY: QueryInterface on a live object; `out` receives an owned reference.
        let hr = unsafe { (self.vtbl::<IUnknownVtbl>().query_interface)(self.0, iid, &mut out) };
        if hr != S_OK || out.is_null() {
            return Err(format!("QueryInterface failed: 0x{hr:08x}"));
        }
        Ok(Com(out))
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: releasing the reference this wrapper owns.
            unsafe { (self.vtbl::<IUnknownVtbl>().release)(self.0) };
        }
    }
}

type GetActivationFactory = unsafe extern "system" fn(HString, *const GUID, *mut *mut c_void) -> HRESULT;
type ActivateInstance = unsafe extern "system" fn(HString, *mut *mut c_void) -> HRESULT;
type CreateString = unsafe extern "system" fn(PCWSTR, u32, *mut HString) -> HRESULT;
type DeleteString = unsafe extern "system" fn(HString) -> HRESULT;

/// The WinRT activation functions of combase.dll.
struct Runtime {
    _lib: Library,
    get_activation_factory: GetActivationFactory,
    activate_instance: ActivateInstance,
    create_string: CreateString,
    delete_string: DeleteString,
}

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

fn runtime() -> Result<&'static Runtime, String> {
    RUNTIME
        .get_or_init(|| {
            // SAFETY: combase.dll is a system library; the symbols are looked up by their
            // documented names and signatures.
            unsafe {
                let lib = Library::new("combase.dll").map_err(|e| format!("combase.dll: {e}"))?;
                let sym = |name: &[u8]| lib.get::<*const c_void>(name).map(|s| *s).map_err(|e| format!("{}: {e}", String::from_utf8_lossy(name)));
                let get_activation_factory = std::mem::transmute::<*const c_void, GetActivationFactory>(sym(b"RoGetActivationFactory\0")?);
                let activate_instance = std::mem::transmute::<*const c_void, ActivateInstance>(sym(b"RoActivateInstance\0")?);
                let create_string = std::mem::transmute::<*const c_void, CreateString>(sym(b"WindowsCreateString\0")?);
                let delete_string = std::mem::transmute::<*const c_void, DeleteString>(sym(b"WindowsDeleteString\0")?);
                Ok(Runtime { _lib: lib, get_activation_factory, activate_instance, create_string, delete_string })
            }
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// An HString that is deleted on drop.
struct HStr(HString);

impl HStr {
    fn new(rt: &Runtime, s: &str) -> Result<Self, String> {
        let w: Vec<u16> = s.encode_utf16().collect();
        let mut h: HString = null_mut();
        // SAFETY: the buffer outlives the call; WindowsCreateString copies it.
        let hr = unsafe { (rt.create_string)(w.as_ptr(), w.len() as u32, &mut h) };
        if hr != S_OK {
            return Err(format!("WindowsCreateString failed: 0x{hr:08x}"));
        }
        Ok(HStr(h))
    }
}

impl Drop for HStr {
    fn drop(&mut self) {
        if let Ok(rt) = runtime() {
            // SAFETY: a string this wrapper created.
            unsafe { (rt.delete_string)(self.0) };
        }
    }
}

fn factory(rt: &Runtime, class: &str, iid: &GUID) -> Result<Com, String> {
    let name = HStr::new(rt, class)?;
    let mut out: *mut c_void = null_mut();
    // SAFETY: documented activation call; `out` receives an owned reference.
    let hr = unsafe { (rt.get_activation_factory)(name.0, iid, &mut out) };
    if hr != S_OK || out.is_null() {
        return Err(format!("activation factory for {class}: 0x{hr:08x}"));
    }
    Ok(Com(out))
}

/// The toast notifier for this application, created once per thread.
struct Toaster {
    notifier: Com,
    factory: Com,
}

thread_local! {
    static TOASTER: RefCell<Option<Result<Toaster, String>>> = const { RefCell::new(None) };
}

fn toaster_init() -> Result<Toaster, String> {
    let rt = runtime()?;
    let statics = factory(rt, "Windows.UI.Notifications.ToastNotificationManager", &IID_MANAGER_STATICS)?;
    let id = HStr::new(rt, APP_ID)?;
    let mut notifier: *mut c_void = null_mut();
    // SAFETY: method of a live factory; `notifier` receives an owned reference.
    let hr = unsafe { (statics.vtbl::<ManagerStaticsVtbl>().create_toast_notifier_with_id)(statics.0, id.0, &mut notifier) };
    if hr != S_OK || notifier.is_null() {
        return Err(format!("CreateToastNotifierWithId failed: 0x{hr:08x}"));
    }
    let notifier = Com(notifier);
    let notifier = notifier.query(&IID_NOTIFIER)?;
    let mut setting = 0i32;
    // SAFETY: a plain getter on the notifier.
    if unsafe { (notifier.vtbl::<NotifierVtbl>().get_setting)(notifier.0, &mut setting) } == S_OK && setting != 0 {
        tracing::warn!("Windows notifications are disabled for NetScope (setting {setting}); toasts will not be shown");
    }
    let factory = factory(rt, "Windows.UI.Notifications.ToastNotification", &IID_TOAST_FACTORY)?;
    Ok(Toaster { notifier, factory })
}

/// What to show.
pub struct Toast<'a> {
    pub title: &'a str,
    pub body: &'a str,
    /// Small grey line under the text ("NetScope · Security").
    pub attribution: &'a str,
    /// PNG shown instead of the application logo (a category icon); `None` keeps the logo.
    pub image: Option<&'a Path>,
    /// `netscope://…` opened when the toast itself is clicked.
    pub launch: &'a str,
    /// Buttons: (label, `netscope://…`).
    pub actions: &'a [(&'a str, String)],
    /// Replaces an earlier toast with the same tag and group.
    pub tag: &'a str,
    pub group: &'a str,
    pub sound: bool,
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// A `file:///` URI for a local path, as toast images want it.
fn file_uri(p: &Path) -> String {
    let s = p.display().to_string().replace('\\', "/");
    let mut out = String::from("file:///");
    for c in s.chars() {
        match c {
            ' ' => out.push_str("%20"),
            '#' => out.push_str("%23"),
            '%' => out.push_str("%25"),
            c => out.push(c),
        }
    }
    out
}

/// The toast's XML (ToastGeneric), ready for `IXmlDocumentIO::LoadXml`.
pub fn xml(t: &Toast) -> String {
    let mut x = format!("<toast activationType=\"protocol\" launch=\"{}\" duration=\"short\">", xml_escape(t.launch));
    x.push_str("<visual><binding template=\"ToastGeneric\">");
    if let Some(img) = t.image {
        x.push_str(&format!("<image placement=\"appLogoOverride\" hint-crop=\"circle\" src=\"{}\"/>", xml_escape(&file_uri(img))));
    }
    x.push_str(&format!("<text hint-maxLines=\"1\">{}</text><text>{}</text>", xml_escape(t.title), xml_escape(t.body)));
    if !t.attribution.is_empty() {
        x.push_str(&format!("<text placement=\"attribution\">{}</text>", xml_escape(t.attribution)));
    }
    x.push_str("</binding></visual>");
    if !t.actions.is_empty() {
        x.push_str("<actions>");
        for (label, url) in t.actions {
            x.push_str(&format!("<action content=\"{}\" arguments=\"{}\" activationType=\"protocol\"/>", xml_escape(label), xml_escape(url)));
        }
        x.push_str("</actions>");
    }
    if !t.sound {
        x.push_str("<audio silent=\"true\"/>");
    }
    x.push_str("</toast>");
    x
}

/// Shows a toast; the error says why it could not be shown (the caller falls back to a
/// tray balloon).
pub fn show(t: &Toast) -> Result<(), String> {
    TOASTER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let toaster = slot.get_or_insert_with(toaster_init);
        let toaster = toaster.as_ref().map_err(Clone::clone)?;
        let rt = runtime()?;
        // The XML document.
        let class = HStr::new(rt, "Windows.Data.Xml.Dom.XmlDocument")?;
        let mut raw: *mut c_void = null_mut();
        // SAFETY: documented activation call; `raw` receives an owned reference.
        let hr = unsafe { (rt.activate_instance)(class.0, &mut raw) };
        if hr != S_OK || raw.is_null() {
            return Err(format!("XmlDocument activation failed: 0x{hr:08x}"));
        }
        let inspectable = Com(raw);
        let doc = inspectable.query(&IID_XML_DOCUMENT)?;
        let io = inspectable.query(&IID_XML_DOCUMENT_IO)?;
        let text = HStr::new(rt, &xml(t))?;
        // SAFETY: method of a live object with a valid HString.
        let hr = unsafe { (io.vtbl::<XmlIoVtbl>().load_xml)(io.0, text.0) };
        if hr != S_OK {
            return Err(format!("LoadXml failed: 0x{hr:08x}"));
        }
        // The notification.
        let mut raw: *mut c_void = null_mut();
        // SAFETY: factory method; `raw` receives an owned reference.
        let hr = unsafe { (toaster.factory.vtbl::<ToastFactoryVtbl>().create_toast_notification)(toaster.factory.0, doc.0, &mut raw) };
        if hr != S_OK || raw.is_null() {
            return Err(format!("CreateToastNotification failed: 0x{hr:08x}"));
        }
        let toast = Com(raw);
        if let Ok(t2) = toast.query(&IID_TOAST2) {
            let tag = HStr::new(rt, t.tag)?;
            let group = HStr::new(rt, t.group)?;
            // SAFETY: setters on a live object with valid HStrings.
            unsafe {
                (t2.vtbl::<Toast2Vtbl>().put_tag)(t2.0, tag.0);
                (t2.vtbl::<Toast2Vtbl>().put_group)(t2.0, group.0);
            }
        }
        // SAFETY: Show on a live notifier with a live notification.
        let hr = unsafe { (toaster.notifier.vtbl::<NotifierVtbl>().show)(toaster.notifier.0, toast.0) };
        if hr != S_OK {
            return Err(format!("Show failed: 0x{hr:08x}"));
        }
        Ok(())
    })
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Writes `value` as a string value under `HKCU\<subkey>` (the default value when `name`
/// is `None`), creating the key.
fn set_string(subkey: &str, name: Option<&str>, value: &str) -> Result<(), String> {
    let mut key: HKEY = null_mut();
    let sub = wide(subkey);
    // SAFETY: NUL-terminated strings; the key handle is closed before returning.
    unsafe {
        let r = RegCreateKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, null(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, null(), &mut key, null_mut());
        if r != ERROR_SUCCESS {
            return Err(format!("cannot create HKCU\\{subkey}: error {r}"));
        }
        let data = wide(value);
        let name_w = name.map(wide);
        let name_ptr = name_w.as_ref().map_or(null(), |n| n.as_ptr());
        let r = RegSetValueExW(key, name_ptr, 0, REG_SZ, data.as_ptr().cast::<u8>(), (data.len() * 2) as u32);
        RegCloseKey(key);
        if r != ERROR_SUCCESS {
            return Err(format!("cannot write HKCU\\{subkey}\\{}: error {r}", name.unwrap_or("(default)")));
        }
    }
    Ok(())
}

/// Registers this process' application id (so Windows shows toasts with NetScope's name and
/// icon) and the `netscope:` URL protocol (so toast clicks reach the program). Both live in
/// HKCU, are idempotent and also written by the installer; `icon` is a `.ico` file.
pub fn register(exe: &Path, icon: &Path) -> Result<(), String> {
    // SAFETY: a NUL-terminated string; must happen before any window of the process exists.
    unsafe { SetCurrentProcessExplicitAppUserModelID(wide(APP_ID).as_ptr()) };
    let app = format!("Software\\Classes\\AppUserModelId\\{APP_ID}");
    set_string(&app, Some("DisplayName"), "NetScope")?;
    set_string(&app, Some("IconUri"), &icon.display().to_string())?;
    let proto = format!("Software\\Classes\\{SCHEME}");
    set_string(&proto, None, "URL:NetScope")?;
    set_string(&proto, Some("URL Protocol"), "")?;
    set_string(&format!("{proto}\\DefaultIcon"), None, &format!("\"{}\",0", exe.display()))?;
    set_string(&format!("{proto}\\shell\\open\\command"), None, &format!("\"{}\" \"%1\"", exe.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_is_escaped_and_complete() {
        let actions = [("Open".to_string(), "netscope://open/alerts".to_string())];
        let actions: Vec<(&str, String)> = actions.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
        let t = Toast {
            title: "A <b> & \"c\"",
            body: "line\nbreak 'q'",
            attribution: "NetScope · Security",
            image: Some(Path::new(r"C:\Users\me\App Data\icons\security.png")),
            launch: "netscope://open/alerts?x=1&y=2",
            actions: &actions,
            tag: "7",
            group: "security",
            sound: false,
        };
        let x = xml(&t);
        assert!(x.starts_with("<toast activationType=\"protocol\" launch=\"netscope://open/alerts?x=1&amp;y=2\""));
        assert!(x.contains("<text hint-maxLines=\"1\">A &lt;b&gt; &amp; &quot;c&quot;</text><text>line break &apos;q&apos;</text>"));
        assert!(x.contains("src=\"file:///C:/Users/me/App%20Data/icons/security.png\""));
        assert!(x.contains("<action content=\"Open\" arguments=\"netscope://open/alerts\" activationType=\"protocol\"/>"));
        assert!(x.contains("<text placement=\"attribution\">NetScope · Security</text>"));
        assert!(x.ends_with("<audio silent=\"true\"/></toast>"));
        let loud = Toast { sound: true, image: None, actions: &[], attribution: "", ..t };
        let x = xml(&loud);
        assert!(!x.contains("<audio") && !x.contains("<image") && !x.contains("<actions>") && !x.contains("attribution"));
    }

    #[test]
    fn interface_layouts_follow_iinspectable() {
        use std::mem::size_of;
        let p = size_of::<usize>();
        assert_eq!(size_of::<IInspectableVtbl>(), 6 * p);
        assert_eq!(size_of::<ManagerStaticsVtbl>(), 9 * p);
        assert_eq!(size_of::<NotifierVtbl>(), 12 * p);
        assert_eq!(size_of::<Toast2Vtbl>(), 12 * p);
        assert_eq!(size_of::<XmlIoVtbl>(), 9 * p);
    }
}
