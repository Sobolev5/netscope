//! The Inno Setup script: its Russian texts must reach the installer intact, and every
//! message must exist in both languages.

use std::collections::BTreeSet;

const ISS: &[u8] = include_bytes!("../installer/netscope.iss");

#[test]
fn script_is_utf8_with_a_byte_order_mark() {
    // Without the BOM Inno Setup reads the file in the ANSI code page ("РЎРѕР·РґР°С‚СЊ").
    assert_eq!(&ISS[..3], b"\xEF\xBB\xBF", "installer/netscope.iss must be saved as UTF-8 with BOM");
    let text = std::str::from_utf8(&ISS[3..]).expect("valid UTF-8");
    assert!(text.contains("ru.TaskDesktop=Создать"), "Russian texts are there as written");
    assert!(!text.contains('\u{FFFD}') && !text.contains("Р°") && !text.contains("РЎ"), "no mojibake in the source");
}

#[test]
fn every_message_exists_in_both_languages() {
    let text = std::str::from_utf8(&ISS[3..]).unwrap();
    let keys = |lang: &str| -> BTreeSet<String> {
        text.lines().filter_map(|l| l.strip_prefix(&format!("{lang}."))).filter_map(|l| l.split_once('=')).map(|(k, _)| k.to_string()).collect()
    };
    let (en, ru) = (keys("en"), keys("ru"));
    assert!(en.len() >= 10, "{en:?}");
    assert_eq!(en, ru, "ru and en custom messages differ");
    // Every {cm:Name} the script uses is defined (here, or among Inno Setup's own messages).
    const BUILT_IN: &[&str] = &["AdditionalIcons", "CreateDesktopIcon", "LaunchProgram", "UninstallProgram", "ProgramOnTheWeb", "AutoStartProgram", "AutoStartProgramGroupDescription"];
    for part in text.split("{cm:").skip(1) {
        let name = part.split(['}', ',']).next().unwrap();
        assert!(en.contains(name) || BUILT_IN.contains(&name), "{{cm:{name}}} is not defined");
    }
}
