//! Icons for the tray menu and the notifications, drawn at run time with GDI+ from the
//! system icon font (Segoe Fluent Icons on Windows 11, Segoe MDL2 Assets before): a glyph
//! on a transparent background for menu items, a white glyph in a coloured circle saved as
//! PNG for toast images. Nothing is shipped as image files, and the result matches the
//! system's own look at any DPI.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use windows_sys::core::GUID;
use windows_sys::Win32::Graphics::Gdi::HBITMAP;
use windows_sys::Win32::Graphics::GdiPlus::{
    GdipCreateBitmapFromScan0, GdipCreateFont, GdipCreateFontFamilyFromName, GdipCreateHBITMAPFromBitmap, GdipCreateSolidFill,
    GdipCreateStringFormat, GdipDeleteBrush, GdipDeleteFont, GdipDeleteFontFamily, GdipDeleteGraphics, GdipDeleteStringFormat,
    GdipDisposeImage, GdipDrawString, GdipFillEllipse, GdipGetImageGraphicsContext, GdipGraphicsClear, GdipSaveImageToFile,
    GdipSetSmoothingMode, GdipSetStringFormatAlign, GdipSetStringFormatLineAlign, GdipSetTextRenderingHint, GdiplusStartup,
    FontStyleRegular, GdiplusStartupInput, GpBitmap, GpBrush, GpFont, GpFontFamily, GpGraphics, GpImage, GpSolidFill,
    GpStringFormat, RectF, SmoothingModeAntiAlias, StringAlignmentCenter, TextRenderingHintAntiAlias, UnitPixel,
};

/// 32 bits per pixel, premultiplied alpha (`PixelFormat32bppPARGB`).
const PIXEL_FORMAT_32BPP_PARGB: i32 = 0x000E_200B;
const CLSID_PNG_ENCODER: GUID = GUID { data1: 0x557cf406, data2: 0x1a04, data3: 0x11d3, data4: [0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e] };

/// Glyphs of the Segoe icon fonts (same code points in Fluent and MDL2).
pub mod glyph {
    pub const OPEN_WINDOW: char = '\u{E8A7}';
    pub const GLOBE: char = '\u{E774}';
    pub const BELL: char = '\u{EA8F}';
    pub const BELL_OFF: char = '\u{E7ED}';
    pub const QUIET: char = '\u{E708}';
    pub const SHIELD: char = '\u{EA18}';
    pub const EYE: char = '\u{E7B3}';
    pub const NETWORK: char = '\u{E909}';
    pub const MAP_PIN: char = '\u{E8F0}';
    pub const POWER: char = '\u{E7E8}';
    pub const DOCUMENT: char = '\u{E8A5}';
    pub const DOWNLOAD: char = '\u{E896}';
    pub const STARTUP: char = '\u{E7F4}';
    pub const INFO: char = '\u{E946}';
}

/// Toast image colours (ARGB) per alert category and for plain information.
pub mod color {
    pub const SECURITY: u32 = 0xFFD9_3A2F;
    pub const NOVELTY: u32 = 0xFF7C_4DDB;
    pub const NETWORK: u32 = 0xFF1E_88E5;
    pub const ROUTES: u32 = 0xFF1B_9E6B;
    pub const INFO: u32 = 0xFF4A_5568;
    /// Menu glyphs: dark grey, like the system's own menu icons.
    pub const MENU: u32 = 0xFF2B_2B2B;
}

static GDIPLUS: OnceLock<Result<(), String>> = OnceLock::new();

/// Starts GDI+ once for the process (it stays up until exit).
fn startup() -> Result<(), String> {
    GDIPLUS
        .get_or_init(|| {
            let input = GdiplusStartupInput { GdiplusVersion: 1, DebugEventCallback: 0, SuppressBackgroundThread: 0, SuppressExternalCodecs: 0 };
            let mut token: usize = 0;
            // SAFETY: documented start-up call with a valid input structure.
            let status = unsafe { GdiplusStartup(&mut token, &input, null_mut()) };
            if status == 0 {
                Ok(())
            } else {
                Err(format!("GdiplusStartup failed with status {status}"))
            }
        })
        .clone()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A GDI+ bitmap released on drop.
struct Bitmap(*mut GpBitmap);

impl Drop for Bitmap {
    fn drop(&mut self) {
        // SAFETY: a bitmap this wrapper owns.
        unsafe { GdipDisposeImage(self.0.cast::<GpImage>()) };
    }
}

/// Draws `glyph` centred in a `size`×`size` bitmap: on a circle of colour `circle` when
/// given, else on transparency. `em` is the font size in pixels, `fg` the glyph colour.
fn render(glyph: char, size: i32, em: f32, fg: u32, circle: Option<u32>) -> Result<Bitmap, String> {
    startup()?;
    let check = |status: i32, what: &str| if status == 0 { Ok(()) } else { Err(format!("{what}: GDI+ status {status}")) };
    // SAFETY: every handle is checked right after creation and released below; the
    // strings outlive the calls that use them.
    unsafe {
        let mut bmp: *mut GpBitmap = null_mut();
        check(GdipCreateBitmapFromScan0(size, size, 0, PIXEL_FORMAT_32BPP_PARGB, null(), &mut bmp), "GdipCreateBitmapFromScan0")?;
        let bmp = Bitmap(bmp);
        let mut g: *mut GpGraphics = null_mut();
        check(GdipGetImageGraphicsContext(bmp.0.cast::<GpImage>(), &mut g), "GdipGetImageGraphicsContext")?;
        let result = (|| -> Result<(), String> {
            check(GdipSetSmoothingMode(g, SmoothingModeAntiAlias), "GdipSetSmoothingMode")?;
            check(GdipSetTextRenderingHint(g, TextRenderingHintAntiAlias), "GdipSetTextRenderingHint")?;
            check(GdipGraphicsClear(g, 0), "GdipGraphicsClear")?;
            if let Some(c) = circle {
                let mut brush: *mut GpSolidFill = null_mut();
                check(GdipCreateSolidFill(c, &mut brush), "GdipCreateSolidFill")?;
                let r = GdipFillEllipse(g, brush.cast::<GpBrush>(), 0.0, 0.0, size as f32, size as f32);
                GdipDeleteBrush(brush.cast::<GpBrush>());
                check(r, "GdipFillEllipse")?;
            }
            let mut family: *mut GpFontFamily = null_mut();
            let mut found = false;
            for name in ["Segoe Fluent Icons", "Segoe MDL2 Assets"] {
                if GdipCreateFontFamilyFromName(wide(name).as_ptr(), null_mut(), &mut family) == 0 && !family.is_null() {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err("neither Segoe Fluent Icons nor Segoe MDL2 Assets is installed".into());
            }
            let mut font: *mut GpFont = null_mut();
            let r = GdipCreateFont(family, em, FontStyleRegular, UnitPixel, &mut font);
            GdipDeleteFontFamily(family);
            check(r, "GdipCreateFont")?;
            let mut format: *mut GpStringFormat = null_mut();
            let mut brush: *mut GpSolidFill = null_mut();
            let r = (|| -> Result<(), String> {
                check(GdipCreateStringFormat(0, 0, &mut format), "GdipCreateStringFormat")?;
                check(GdipSetStringFormatAlign(format, StringAlignmentCenter), "GdipSetStringFormatAlign")?;
                check(GdipSetStringFormatLineAlign(format, StringAlignmentCenter), "GdipSetStringFormatLineAlign")?;
                check(GdipCreateSolidFill(fg, &mut brush), "GdipCreateSolidFill")?;
                let text: Vec<u16> = glyph.encode_utf16(&mut [0u16; 2]).to_vec();
                let rect = RectF { X: 0.0, Y: 0.0, Width: size as f32, Height: size as f32 };
                check(GdipDrawString(g, text.as_ptr(), text.len() as i32, font, &rect, format, brush.cast::<GpBrush>()), "GdipDrawString")
            })();
            if !brush.is_null() {
                GdipDeleteBrush(brush.cast::<GpBrush>());
            }
            if !format.is_null() {
                GdipDeleteStringFormat(format);
            }
            GdipDeleteFont(font);
            r
        })();
        GdipDeleteGraphics(g);
        result?;
        Ok(bmp)
    }
}

/// A menu-sized glyph (`size` pixels, e.g. the small-icon metric for the DPI) as a 32-bit
/// bitmap with alpha, the way `MENUITEMINFO.hbmpItem` wants it. Bitmaps are cached for
/// the process lifetime; menus only borrow them.
pub fn menu_bitmap(glyph: char, size: i32) -> Result<HBITMAP, String> {
    thread_local! {
        static CACHE: RefCell<HashMap<(char, i32), usize>> = RefCell::new(HashMap::new());
    }
    if let Some(h) = CACHE.with(|c| c.borrow().get(&(glyph, size)).copied()) {
        return Ok(h as HBITMAP);
    }
    let bmp = render(glyph, size, size as f32 * 0.8, color::MENU, None)?;
    let mut h: HBITMAP = null_mut();
    // SAFETY: converting a live bitmap; the HBITMAP is owned by the cache from here on.
    let status = unsafe { GdipCreateHBITMAPFromBitmap(bmp.0, &mut h, 0) };
    if status != 0 || h.is_null() {
        return Err(format!("GdipCreateHBITMAPFromBitmap: status {status}"));
    }
    CACHE.with(|c| c.borrow_mut().insert((glyph, size), h as usize));
    Ok(h)
}

/// Writes `glyph` in white on a circle of `color` as a PNG of `size` pixels; an existing
/// file of this program version is reused.
pub fn badge_png(dir: &Path, name: &str, glyph: char, color: u32, size: i32) -> Result<PathBuf, String> {
    let path = dir.join(format!("{name}-{}.png", env!("CARGO_PKG_VERSION")));
    if path.exists() {
        return Ok(path);
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let bmp = render(glyph, size, size as f32 * 0.52, 0xFFFF_FFFF, Some(color))?;
    // SAFETY: saving a live bitmap to a NUL-terminated path with the PNG encoder.
    let status = unsafe { GdipSaveImageToFile(bmp.0.cast::<GpImage>(), wide(&path.display().to_string()).as_ptr(), &CLSID_PNG_ENCODER, null()) };
    if status != 0 {
        return Err(format!("GdipSaveImageToFile({}): status {status}", path.display()));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NETSCOPE_ICON_SHEET=<dir>` writes every glyph as a PNG there (to look at them).
    #[test]
    fn glyph_sheet_on_request() {
        let Some(dir) = std::env::var_os("NETSCOPE_ICON_SHEET") else { return };
        let dir = PathBuf::from(dir);
        let all = [
            ("open_window", glyph::OPEN_WINDOW),
            ("globe", glyph::GLOBE),
            ("bell", glyph::BELL),
            ("bell_off", glyph::BELL_OFF),
            ("quiet", glyph::QUIET),
            ("shield", glyph::SHIELD),
            ("eye", glyph::EYE),
            ("network", glyph::NETWORK),
            ("map_pin", glyph::MAP_PIN),
            ("power", glyph::POWER),
            ("document", glyph::DOCUMENT),
            ("download", glyph::DOWNLOAD),
            ("startup", glyph::STARTUP),
            ("info", glyph::INFO),
        ];
        let extra: Vec<(String, char)> = std::env::var("NETSCOPE_ICON_EXTRA")
            .unwrap_or_default()
            .split(',')
            .filter_map(|h| u32::from_str_radix(h.trim(), 16).ok().and_then(char::from_u32).map(|c| (format!("x{}", h.trim()), c)))
            .collect();
        let all = all.into_iter().map(|(n, g)| (n.to_string(), g)).chain(extra);
        for (name, g) in all {
            let name = name.as_str();
            badge_png(&dir, name, g, color::NETWORK, 96).unwrap();
            let menu = render(g, 32, 32.0 * 0.8, color::MENU, None).unwrap();
            let path = dir.join(format!("menu-{name}.png"));
            // SAFETY: saving a live bitmap.
            let status = unsafe { GdipSaveImageToFile(menu.0.cast::<GpImage>(), wide(&path.display().to_string()).as_ptr(), &CLSID_PNG_ENCODER, null()) };
            assert_eq!(status, 0);
        }
    }

    #[test]
    fn badges_and_menu_bitmaps_render() {
        let dir = std::env::temp_dir().join(format!("netscope-icons-{}", std::process::id()));
        let p = badge_png(&dir, "security", glyph::SHIELD, color::SECURITY, 48).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert!(bytes.starts_with(b"\x89PNG"), "{}", p.display());
        assert!(bytes.len() > 200);
        assert_eq!(badge_png(&dir, "security", glyph::SHIELD, color::SECURITY, 48).unwrap(), p, "reused");
        let h = menu_bitmap(glyph::BELL, 16).unwrap();
        assert!(!h.is_null());
        assert_eq!(menu_bitmap(glyph::BELL, 16).unwrap(), h, "cached");
        std::fs::remove_dir_all(&dir).ok();
    }
}
