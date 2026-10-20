//! Raw libpcap / Npcap bindings, resolved at runtime with `libloading`.
//!
//! Loading at runtime (instead of linking) means the binary starts even when
//! libpcap is missing and can tell the user exactly what to install, and the
//! build needs no pcap SDK on any platform.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, c_uint, c_void};

use libloading::Library;

pub const PCAP_ERRBUF_SIZE: usize = 256;

/// `pcap_init` option: strings passed to and returned by libpcap are UTF-8.
pub const PCAP_CHAR_ENC_UTF_8: c_uint = 1;

// `pcap_next_ex` results.
pub const NEXT_OK: c_int = 1;
pub const NEXT_TIMEOUT: c_int = 0;
pub const NEXT_EOF: c_int = -2;

// `pcap_activate` errors (pcap/pcap.h).
pub const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
pub const PCAP_ERROR_PERM_DENIED: c_int = -8;
pub const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;

// `pcap_if.flags`.
pub const PCAP_IF_LOOPBACK: u32 = 0x1;
pub const PCAP_IF_UP: u32 = 0x2;
pub const PCAP_IF_RUNNING: u32 = 0x4;
pub const PCAP_IF_WIRELESS: u32 = 0x8;

/// Opaque capture handle.
#[repr(C)]
pub struct pcap_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct timeval {
    pub tv_sec: c_long,
    #[cfg(target_os = "macos")]
    pub tv_usec: i32,
    #[cfg(not(target_os = "macos"))]
    pub tv_usec: c_long,
}

#[repr(C)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: u32,
    pub len: u32,
}

/// Only the leading address-family bytes are read; layout differs between OSes.
#[repr(C)]
pub struct sockaddr {
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct pcap_addr {
    pub next: *mut pcap_addr,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}

#[repr(C)]
pub struct pcap_if {
    pub next: *mut pcap_if,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut pcap_addr,
    pub flags: u32,
}

#[repr(C)]
pub struct bpf_program {
    pub bf_len: c_uint,
    pub bf_insns: *mut c_void,
}

macro_rules! pcap_api {
    (
        required { $( $name:ident : fn($($arg:ty),*) $(-> $ret:ty)? ;)* }
        optional { $( $opt:ident : fn($($oarg:ty),*) $(-> $oret:ty)? ;)* }
    ) => {
        /// Function table of a loaded libpcap. The `Library` is kept alive alongside
        /// the copied function pointers, so they stay valid for the struct's lifetime.
        /// Optional entries are `None` in older libpcap / Npcap builds.
        pub struct Api {
            _lib: Library,
            $(pub $name: unsafe extern "C" fn($($arg),*) $(-> $ret)?,)*
            $(pub $opt: Option<unsafe extern "C" fn($($oarg),*) $(-> $oret)?>,)*
        }

        impl Api {
            /// # Safety
            /// `lib` must be a libpcap-compatible library exporting these C symbols.
            pub unsafe fn from_library(lib: Library) -> Result<Self, libloading::Error> {
                $(
                    let $name = *lib.get::<unsafe extern "C" fn($($arg),*) $(-> $ret)?>(
                        concat!(stringify!($name), "\0").as_bytes(),
                    )?;
                )*
                $(
                    let $opt = lib.get::<unsafe extern "C" fn($($oarg),*) $(-> $oret)?>(
                        concat!(stringify!($opt), "\0").as_bytes(),
                    ).ok().map(|s| *s);
                )*
                Ok(Self { _lib: lib, $($name,)* $($opt,)* })
            }
        }
    };
}

pcap_api! {
    required {
    pcap_lib_version: fn() -> *const c_char;
    pcap_findalldevs: fn(*mut *mut pcap_if, *mut c_char) -> c_int;
    pcap_freealldevs: fn(*mut pcap_if);
    pcap_create: fn(*const c_char, *mut c_char) -> *mut pcap_t;
    pcap_set_snaplen: fn(*mut pcap_t, c_int) -> c_int;
    pcap_set_promisc: fn(*mut pcap_t, c_int) -> c_int;
    pcap_set_timeout: fn(*mut pcap_t, c_int) -> c_int;
    pcap_set_immediate_mode: fn(*mut pcap_t, c_int) -> c_int;
    pcap_set_buffer_size: fn(*mut pcap_t, c_int) -> c_int;
    pcap_activate: fn(*mut pcap_t) -> c_int;
    pcap_open_offline: fn(*const c_char, *mut c_char) -> *mut pcap_t;
    pcap_next_ex: fn(*mut pcap_t, *mut *mut pcap_pkthdr, *mut *const u8) -> c_int;
    pcap_datalink: fn(*mut pcap_t) -> c_int;
    pcap_compile: fn(*mut pcap_t, *mut bpf_program, *const c_char, c_int, u32) -> c_int;
    pcap_setfilter: fn(*mut pcap_t, *mut bpf_program) -> c_int;
    pcap_freecode: fn(*mut bpf_program);
    pcap_geterr: fn(*mut pcap_t) -> *mut c_char;
    pcap_statustostr: fn(c_int) -> *const c_char;
    pcap_close: fn(*mut pcap_t);
    }
    optional {
    pcap_init: fn(c_uint, *mut c_char) -> c_int;
    }
}

impl Api {
    /// Switches libpcap to UTF-8 strings. Must run before any other pcap call. Without it
    /// Npcap uses the ANSI code page, so Cyrillic adapter descriptions, paths and error
    /// texts come out as mojibake. Older libraries lack `pcap_init`; failure is ignored.
    pub fn init_utf8(&self) {
        if let Some(init) = self.pcap_init {
            let mut err = [0 as c_char; PCAP_ERRBUF_SIZE];
            // SAFETY: a valid error buffer of the documented size.
            unsafe { init(PCAP_CHAR_ENC_UTF_8, err.as_mut_ptr()) };
        }
    }
}

/// Library names tried in order; `NETSCOPE_LIBPCAP` overrides them all.
pub fn candidates() -> Vec<String> {
    if let Ok(p) = std::env::var("NETSCOPE_LIBPCAP") {
        return vec![p];
    }
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        vec![format!(r"{root}\System32\Npcap\wpcap.dll"), "wpcap.dll".into()]
    } else if cfg!(target_os = "macos") {
        vec!["libpcap.A.dylib".into(), "/usr/lib/libpcap.A.dylib".into(), "libpcap.dylib".into()]
    } else {
        vec!["libpcap.so.1".into(), "libpcap.so".into(), "libpcap.so.0.8".into()]
    }
}

/// Opens a shared library. On Windows a full path is loaded with
/// `LOAD_WITH_ALTERED_SEARCH_PATH`, so Npcap's `Packet.dll` next to `wpcap.dll` is found.
pub fn open_library(name: &str) -> Result<Library, libloading::Error> {
    #[cfg(windows)]
    {
        use libloading::os::windows::{Library as WinLibrary, LOAD_WITH_ALTERED_SEARCH_PATH};
        let flags = if std::path::Path::new(name).is_absolute() { LOAD_WITH_ALTERED_SEARCH_PATH } else { 0 };
        // SAFETY: loading Npcap runs its DllMain, which has no preconditions for us.
        unsafe { WinLibrary::load_with_flags(name, flags).map(Library::from) }
    }
    #[cfg(not(windows))]
    {
        // SAFETY: libpcap's initializers have no preconditions.
        unsafe { Library::new(name) }
    }
}
